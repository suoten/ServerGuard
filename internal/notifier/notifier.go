package notifier

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/smtp"
	"strings"
	"sync"
	"time"

	"github.com/suoten/serverguard/internal/types"
	"github.com/suoten/serverguard/internal/agent/eventbus"
)

// Notifier manages all alert notification channels.
// Supports: email, webhook, WxPusher, DingTalk, Feishu, Slack, Telegram, SMS.
type Notifier struct {
	mu       sync.RWMutex
	channels []Channel
	eventBus *eventbus.EventBus
	silence  SilenceConfig

	// Alert aggregation: merge similar alerts within a time window
	aggMu       sync.Mutex
	aggBuffer   map[string][]types.Alert // key = level+source+title
	aggLastSend map[string]time.Time     // key = level+source+title
	aggWindow   time.Duration            // 5 minutes
	aggCooldown time.Duration            // 10 minutes per same alert source

	// Daily digest
	digestEnabled  bool
	digestHour     int    // 8 = 8:00 AM
	digestLastDate string // YYYY-MM-DD
	// digestProvider 由外部注入，生成每日巡检报告内容（标题, 正文）。
	// 未注入时退回默认占位内容。
	digestProvider func() (string, string)

	// P0 告警升级 + 时区感知延迟推送
	escalationMgr *EscalationManager
	timeZoneDelay *TimeZoneDelay

	// 智能降噪：抖动抑制 + 同源关联归并
	corr *correlator
}

// Channel interface for alert delivery.
type Channel interface {
	Name() string
	Send(ctx context.Context, alert types.Alert) error
	Enabled() bool
}

// SilenceConfig defines silence periods.
type SilenceConfig struct {
	Enabled bool
	Periods []SilencePeriod
}

type SilencePeriod struct {
	StartHour int
	EndHour   int
	Levels    []string
}

// New creates a new Notifier.
func New(bus *eventbus.EventBus) *Notifier {
	n := &Notifier{
		eventBus:       bus,
		aggBuffer:      make(map[string][]types.Alert),
		aggLastSend:    make(map[string]time.Time),
		aggWindow:      5 * time.Minute,
		aggCooldown:    10 * time.Minute,
		digestHour:     8,
		digestLastDate: time.Now().Format("2006-01-02"),
		escalationMgr:  NewEscalationManager(),
		timeZoneDelay:  NewTimeZoneDelay(),
		corr:           newCorrelator(),
	}

	// Subscribe to alert events
	bus.Subscribe(types.EventAlert, n.handleAlert)

	// Start aggregation flusher (checks every 30 seconds)
	go n.aggregationFlusher()

	// Start daily digest checker (checks every 10 minutes)
	go n.dailyDigestChecker()

	// Start P0 escalation checker (checks every 30 seconds)
	go n.escalationChecker()

	// Start time-zone delay flusher (checks every 5 minutes)
	go n.timeZoneDelayFlusher()

	// Start correlator flusher (incident updates every 60 seconds)
	go n.correlatorFlusher()

	return n
}

// AddChannel adds a notification channel.
func (n *Notifier) AddChannel(ch Channel) {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.channels = append(n.channels, ch)
}

// SetSilence sets the silence configuration.
func (n *Notifier) SetSilence(s SilenceConfig) {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.silence = s
}

// handleAlert handles incoming alert events with aggregation.
func (n *Notifier) handleAlert(event types.Event) {
	if event.Type != types.EventAlert {
		return
	}

	// Check silence
	if n.isSilenced(string(event.Level)) {
		return
	}

	alert := types.Alert{
		ID:        event.ID,
		Level:     event.Level,
		Title:     event.Title,
		Message:   event.Message,
		Source:    event.Source,
		Timestamp: event.Timestamp,
	}

	// ── 智能降噪第一层：抖动抑制 ──
	// 同一告警 10 分钟内 ≥3 次 → 自动静默 30 分钟（仅停推送，告警仍落库）
	fp := fmt.Sprintf("%s|%s|%s", event.Level, event.Source, event.Title)
	if muted, notice := n.corr.CheckFlapping(fp, time.Now()); muted {
		if notice {
			n.sendToChannels(flappingNotice(fp))
		}
		return
	}

	// ── 智能降噪第二层：同源关联归并 ──
	// 同一来源 IP 15 分钟内触发 ≥2 类告警 → 合并为一条关联事件推送
	trackResult, merged := n.corr.Track(alert, time.Now())
	switch trackResult {
	case TrackMerge:
		if merged != nil {
			n.sendToChannels(*merged)
		}
		return
	case TrackAbsorb:
		return // 已并入关联事件，等待周期摘要
	}

	// 时区感知延迟：凌晨 0-6 点 P2/P3 告警入延迟队列，8 点统一推送
	if n.timeZoneDelay.ShouldDelay(alert, time.Now()) {
		n.timeZoneDelay.Enqueue(alert)
		return
	}

	// P0 告警升级跟踪
	n.escalationMgr.Track(alert)

	// Aggregate: buffer the alert, flush will send merged notifications
	key := fmt.Sprintf("%s|%s|%s", event.Level, event.Source, event.Title)
	n.aggMu.Lock()
	n.aggBuffer[key] = append(n.aggBuffer[key], alert)

	// If this is the first alert in the window and cooldown has passed, send immediately
	lastSend, exists := n.aggLastSend[key]
	if !exists || time.Since(lastSend) >= n.aggCooldown {
		n.aggLastSend[key] = time.Now()
		n.aggMu.Unlock()

		// Send immediately for first alert
		n.sendToChannels(alert)
		return
	}
	n.aggMu.Unlock()
	// Subsequent alerts within cooldown are buffered, will be sent as aggregated summary
}

// isSilenced checks if the current time falls within a silence period.
func (n *Notifier) isSilenced(level string) bool {
	n.mu.RLock()
	defer n.mu.RUnlock()

	if !n.silence.Enabled {
		return false
	}

	hour := time.Now().Hour()
	for _, period := range n.silence.Periods {
		if hour >= period.StartHour && hour < period.EndHour {
			if len(period.Levels) == 0 {
				return true // silence all
			}
			for _, l := range period.Levels {
				if l == level {
					return true
				}
			}
		}
	}
	return false
}

// sendToChannels sends an alert to all enabled channels.
// Severity routing:
//
//	Critical/Fatal → all enabled channels (urgent)
//	Error          → all channels except email (reduce noise)
//	Warning        → IM channels only (WxPusher, DingTalk, Feishu, Slack, Telegram)
//	Info           → skip notification, only stored in database
func (n *Notifier) sendToChannels(alert types.Alert) {
	// Info level: don't send notifications, just store
	if alert.Level == types.AlertInfo {
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	n.mu.RLock()
	channels := n.channels
	n.mu.RUnlock()

	for _, ch := range channels {
		if !ch.Enabled() {
			continue
		}

		// Severity-based channel routing
		name := ch.Name()
		isEmail := strings.Contains(strings.ToLower(name), "email") || strings.Contains(strings.ToLower(name), "smtp")

		switch alert.Level {
		case types.AlertCritical, types.AlertFatal:
			// Send to ALL channels including email
		case types.AlertError:
			// Send to all except email (reduce inbox noise)
			if isEmail {
				continue
			}
		case types.AlertWarning:
			// Only IM channels
			if isEmail {
				continue
			}
		}

		go func(c Channel) {
			if err := c.Send(ctx, alert); err != nil {
				_ = err
			}
		}(ch)
	}
}

// aggregationFlusher periodically checks for buffered alerts and sends aggregated summaries.
func (n *Notifier) aggregationFlusher() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		n.aggMu.Lock()
		for key, alerts := range n.aggBuffer {
			if len(alerts) <= 1 {
				// Only one alert, already sent immediately
				delete(n.aggBuffer, key)
				continue
			}

			// Check if cooldown has passed since last send
			lastSend, exists := n.aggLastSend[key]
			if exists && time.Since(lastSend) < n.aggCooldown {
				continue // Still in cooldown, keep buffering
			}

			// Send aggregated summary
			first := alerts[0]
			last := alerts[len(alerts)-1]
			summary := types.Alert{
				Level:     first.Level,
				Title:     first.Title,
				Source:    first.Source,
				Timestamp: time.Now(),
				Message: fmt.Sprintf("%s\n\n（5分钟内共发生 %d 次，首次：%s，末次：%s）",
					first.Message, len(alerts),
					first.Timestamp.Format("15:04:05"),
					last.Timestamp.Format("15:04:05")),
			}
			n.aggLastSend[key] = time.Now()
			delete(n.aggBuffer, key)
			n.aggMu.Unlock()

			n.sendToChannels(summary)
			n.aggMu.Lock()
		}
		n.aggMu.Unlock()
	}
}

// dailyDigestChecker checks if it's time to send the daily digest.
func (n *Notifier) dailyDigestChecker() {
	ticker := time.NewTicker(10 * time.Minute)
	defer ticker.Stop()

	for range ticker.C {
		if !n.digestEnabled {
			continue
		}

		now := time.Now()
		today := now.Format("2006-01-02")

		// Already sent today
		if today == n.digestLastDate {
			continue
		}

		// Check if it's past the digest hour
		if now.Hour() >= n.digestHour {
			n.sendDailyDigest()
			n.digestLastDate = today
		}
	}
}

// sendDailyDigest sends a daily summary of all alerts and actions.
func (n *Notifier) sendDailyDigest() {
	title, message := "ServerGuard 每日摘要", "今日系统运行正常，无异常告警。"
	n.mu.RLock()
	provider := n.digestProvider
	n.mu.RUnlock()
	if provider != nil {
		title, message = provider()
	}
	alert := types.Alert{
		Level:     types.AlertInfo,
		Title:     title,
		Source:    "digest",
		Timestamp: time.Now(),
		Message:   message,
	}
	n.sendToChannels(alert)
}

// SetDigestProvider 注入每日巡检报告内容生成器（由装配层调用）。
func (n *Notifier) SetDigestProvider(p func() (string, string)) {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.digestProvider = p
}

// escalationChecker 定期检查 P0 告警是否需要升级（5min 全渠道再推送，30min 通知第二联系人）。
func (n *Notifier) escalationChecker() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		toEscalate := n.escalationMgr.CheckAndEscalate()
		for _, alert := range toEscalate {
			// 升级后强制发送到所有渠道（包括 email）
			escalatedAlert := alert
			escalatedAlert.Title = "[升级] " + alert.Title
			escalatedAlert.Message = fmt.Sprintf("P0 告警已超过阈值未确认，自动升级推送。\n\n原始告警：%s", alert.Message)
			n.sendToChannels(escalatedAlert)
		}
	}
}

// timeZoneDelayFlusher 定期检查延迟队列，8 点后统一推送积压的 P2/P3 告警。
func (n *Notifier) timeZoneDelayFlusher() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	for range ticker.C {
		toFlush := n.timeZoneDelay.Flush(time.Now())
		for _, alert := range toFlush {
			delayedAlert := alert
			delayedAlert.Title = "[延迟推送] " + alert.Title
			delayedAlert.Message = fmt.Sprintf("凌晨静默期积压告警，现统一推送。\n\n原始告警：%s", alert.Message)
			n.sendToChannels(delayedAlert)
		}
	}
}

// correlatorFlusher 定期推送关联事件更新摘要。
func (n *Notifier) correlatorFlusher() {
	ticker := time.NewTicker(60 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		for _, summary := range n.corr.Flush(time.Now()) {
			n.sendToChannels(summary)
		}
	}
}

// MarkAlertConfirmed 标记告警已确认，停止升级跟踪。
func (n *Notifier) MarkAlertConfirmed(alertID string) {
	n.escalationMgr.MarkConfirmed(alertID)
}

// GetEscalationManager 返回升级管理器（供 API 层查询）。
func (n *Notifier) GetEscalationManager() *EscalationManager {
	return n.escalationMgr
}

// GetTimeZoneDelay 返回时区延迟器（供 API 层查询）。
func (n *Notifier) GetTimeZoneDelay() *TimeZoneDelay {
	return n.timeZoneDelay
}

// UpdateChannels replaces all channels (used when settings change).
func (n *Notifier) UpdateChannels(channels []Channel) {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.channels = channels
}

// SetDigest configures the daily digest.
func (n *Notifier) SetDigest(enabled bool, hour int) {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.digestEnabled = enabled
	n.digestHour = hour
}

// SendCustom sends a custom test message to all channels.
// 使用 Warning 级别确保通知能实际发送（Info 级别会被 sendToChannels 跳过）
func (n *Notifier) SendCustom(title, message string) error {
	alert := types.Alert{
		Level:     types.AlertWarning,
		Title:     title,
		Message:   message,
		Source:    "test",
		Timestamp: time.Now(),
	}
	n.mu.RLock()
	channels := n.channels
	n.mu.RUnlock()

	var lastErr error
	sentCount := 0
	for _, ch := range channels {
		if !ch.Enabled() {
			continue
		}
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		if err := ch.Send(ctx, alert); err != nil {
			lastErr = err
		} else {
			sentCount++
		}
		cancel()
	}

	if sentCount == 0 && lastErr != nil {
		return lastErr
	}
	return nil
}

// --- Email Channel ---

type EmailChannel struct {
	name     string
	enabled  bool
	smtpHost string
	smtpPort string
	username string
	password string
	from     string
	to       []string
}

func NewEmailChannel(name, smtpHost, smtpPort, username, password, from string, to []string) *EmailChannel {
	return &EmailChannel{
		name: name, enabled: true,
		smtpHost: smtpHost, smtpPort: smtpPort,
		username: username, password: password,
		from: from, to: to,
	}
}

func (c *EmailChannel) Name() string  { return c.name }
func (c *EmailChannel) Enabled() bool { return c.enabled }

func (c *EmailChannel) Send(ctx context.Context, alert types.Alert) error {
	subject := fmt.Sprintf("[ServerGuard %s] %s", strings.ToUpper(string(alert.Level)), alert.Title)
	body := fmt.Sprintf("告警级别: %s\n来源: %s\n时间: %s\n\n%s",
		alert.Level, alert.Source, alert.Timestamp.Format(time.RFC3339), alert.Message)

	msg := fmt.Sprintf("From: %s\r\nTo: %s\r\nSubject: %s\r\n\r\n%s",
		c.from, strings.Join(c.to, ","), subject, body)

	auth := smtp.PlainAuth("", c.username, c.password, c.smtpHost)
	return smtp.SendMail(c.smtpHost+":"+c.smtpPort, auth, c.from, c.to, []byte(msg))
}

// --- Webhook Channel ---

type WebhookChannel struct {
	name    string
	enabled bool
	url     string
	headers map[string]string
}

func NewWebhookChannel(name, url string, headers map[string]string) *WebhookChannel {
	return &WebhookChannel{name: name, enabled: true, url: url, headers: headers}
}

func (c *WebhookChannel) Name() string  { return c.name }
func (c *WebhookChannel) Enabled() bool { return c.enabled }

func (c *WebhookChannel) Send(ctx context.Context, alert types.Alert) error {
	payload, err := json.Marshal(map[string]interface{}{
		"level":     alert.Level,
		"title":     alert.Title,
		"message":   alert.Message,
		"source":    alert.Source,
		"timestamp": alert.Timestamp,
	})
	if err != nil {
		return err
	}

	req, err := http.NewRequestWithContext(ctx, "POST", c.url, bytes.NewReader(payload))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	for k, v := range c.headers {
		req.Header.Set(k, v)
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	resp.Body.Close()
	return nil
}

// --- DingTalk Channel ---

type DingTalkChannel struct {
	name    string
	enabled bool
	webhook string
	secret  string
}

func NewDingTalkChannel(name, webhook, secret string) *DingTalkChannel {
	return &DingTalkChannel{name: name, enabled: true, webhook: webhook, secret: secret}
}

func (c *DingTalkChannel) Name() string  { return c.name }
func (c *DingTalkChannel) Enabled() bool { return c.enabled }

func (c *DingTalkChannel) Send(ctx context.Context, alert types.Alert) error {
	url := c.webhook
	if c.secret != "" {
		timestamp := time.Now().UnixMilli()
		stringToSign := fmt.Sprintf("%d\n%s", timestamp, c.secret)
		mac := hmac.New(sha256.New, []byte(c.secret))
		mac.Write([]byte(stringToSign))
		sign := base64.StdEncoding.EncodeToString(mac.Sum(nil))
		url = fmt.Sprintf("%s&timestamp=%d&sign=%s", c.webhook, timestamp, sign)
	}

	text := fmt.Sprintf("### ServerGuard 告警\n\n**级别**: %s\n**来源**: %s\n**时间**: %s\n\n%s",
		strings.ToUpper(string(alert.Level)),
		alert.Source,
		alert.Timestamp.Format("2006-01-02 15:04:05"),
		alert.Message)

	payload, _ := json.Marshal(map[string]interface{}{
		"msgtype": "markdown",
		"markdown": map[string]string{
			"title": alert.Title,
			"text":  text,
		},
	})

	req, _ := http.NewRequestWithContext(ctx, "POST", url, bytes.NewReader(payload))
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	resp.Body.Close()
	return nil
}

// --- WeChat (企业微信) Channel ---

type WeChatChannel struct {
	name    string
	enabled bool
	webhook string
}

func NewWeChatChannel(name, webhook string) *WeChatChannel {
	return &WeChatChannel{name: name, enabled: true, webhook: webhook}
}

func (c *WeChatChannel) Name() string  { return c.name }
func (c *WeChatChannel) Enabled() bool { return c.enabled }

func (c *WeChatChannel) Send(ctx context.Context, alert types.Alert) error {
	content := fmt.Sprintf("ServerGuard 告警\n级别: %s\n来源: %s\n时间: %s\n\n%s",
		strings.ToUpper(string(alert.Level)),
		alert.Source,
		alert.Timestamp.Format("2006-01-02 15:04:05"),
		alert.Message)

	payload, _ := json.Marshal(map[string]interface{}{
		"msgtype": "text",
		"text": map[string]string{
			"content": content,
		},
	})

	req, _ := http.NewRequestWithContext(ctx, "POST", c.webhook, bytes.NewReader(payload))
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	resp.Body.Close()
	return nil
}

// --- Feishu (飞书) Channel ---

type FeishuChannel struct {
	name    string
	enabled bool
	webhook string
}

func NewFeishuChannel(name, webhook string) *FeishuChannel {
	return &FeishuChannel{name: name, enabled: true, webhook: webhook}
}

func (c *FeishuChannel) Name() string  { return c.name }
func (c *FeishuChannel) Enabled() bool { return c.enabled }

func (c *FeishuChannel) Send(ctx context.Context, alert types.Alert) error {
	content := fmt.Sprintf("ServerGuard 告警\n**级别**: %s\n**来源**: %s\n**时间**: %s\n\n%s",
		strings.ToUpper(string(alert.Level)),
		alert.Source,
		alert.Timestamp.Format("2006-01-02 15:04:05"),
		alert.Message)

	payload, _ := json.Marshal(map[string]interface{}{
		"msg_type": "text",
		"content": map[string]string{
			"text": content,
		},
	})

	req, _ := http.NewRequestWithContext(ctx, "POST", c.webhook, bytes.NewReader(payload))
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	resp.Body.Close()
	return nil
}

// --- Slack Channel ---

type SlackChannel struct {
	name    string
	enabled bool
	webhook string
}

func NewSlackChannel(name, webhook string) *SlackChannel {
	return &SlackChannel{name: name, enabled: true, webhook: webhook}
}

func (c *SlackChannel) Name() string  { return c.name }
func (c *SlackChannel) Enabled() bool { return c.enabled }

func (c *SlackChannel) Send(ctx context.Context, alert types.Alert) error {
	color := "warning"
	switch alert.Level {
	case types.AlertCritical, types.AlertFatal:
		color = "danger"
	case types.AlertInfo:
		color = "good"
	}

	payload, _ := json.Marshal(map[string]interface{}{
		"attachments": []map[string]interface{}{
			{
				"color": color,
				"title": alert.Title,
				"text":  alert.Message,
				"fields": []map[string]string{
					{"title": "Source", "value": alert.Source, "short": "true"},
					{"title": "Level", "value": string(alert.Level), "short": "true"},
				},
				"ts": alert.Timestamp.Unix(),
			},
		},
	})

	req, _ := http.NewRequestWithContext(ctx, "POST", c.webhook, bytes.NewReader(payload))
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	resp.Body.Close()
	return nil
}

// --- Telegram Channel ---

type TelegramChannel struct {
	name    string
	enabled bool
	token   string
	chatID  string
}

func NewTelegramChannel(name, token, chatID string) *TelegramChannel {
	return &TelegramChannel{name: name, enabled: true, token: token, chatID: chatID}
}

func (c *TelegramChannel) Name() string  { return c.name }
func (c *TelegramChannel) Enabled() bool { return c.enabled }

func (c *TelegramChannel) Send(ctx context.Context, alert types.Alert) error {
	text := fmt.Sprintf("🚨 *ServerGuard Alert*\n*Level*: %s\n*Source*: %s\n*Time*: %s\n\n%s",
		strings.ToUpper(string(alert.Level)),
		alert.Source,
		alert.Timestamp.Format("2006-01-02 15:04:05"),
		alert.Message)

	url := fmt.Sprintf("https://api.telegram.org/bot%s/sendMessage", c.token)
	payload, _ := json.Marshal(map[string]interface{}{
		"chat_id":    c.chatID,
		"text":       text,
		"parse_mode": "Markdown",
	})

	req, _ := http.NewRequestWithContext(ctx, "POST", url, bytes.NewReader(payload))
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	resp.Body.Close()
	return nil
}

// --- WxPusher Channel ---
// WxPusher is a free multi-platform push service.
// Users need appToken and UID from https://wxpusher.zjiecode.com/admin/
// Pushes messages to WxPusher APP / WeChat ClawBot.

type WxPusherChannel struct {
	name     string
	enabled  bool
	appToken string // Get from wxpusher.zjiecode.com admin
	uid      string // User ID, get by scanning app QR code
}

func NewWxPusherChannel(name, appToken, uid string) *WxPusherChannel {
	return &WxPusherChannel{name: name, enabled: true, appToken: appToken, uid: uid}
}

func (c *WxPusherChannel) Name() string  { return c.name }
func (c *WxPusherChannel) Enabled() bool { return c.enabled }

func (c *WxPusherChannel) Send(ctx context.Context, alert types.Alert) error {
	if c.appToken == "" || c.uid == "" {
		return fmt.Errorf("WxPusher appToken 或 UID 未配置")
	}

	// Build a readable message
	levelText := map[types.AlertLevel]string{
		types.AlertInfo:     "ℹ️ 信息",
		types.AlertWarning:  "⚠️ 警告",
		types.AlertError:    "🔴 错误",
		types.AlertCritical: "🔴 严重",
		types.AlertFatal:    "💀 致命",
	}
	levelStr := levelText[alert.Level]
	if levelStr == "" {
		levelStr = string(alert.Level)
	}

	content := fmt.Sprintf("%s\n\n**来源**: %s\n**时间**: %s\n\n%s",
		levelStr,
		alert.Source,
		alert.Timestamp.Format("2006-01-02 15:04:05"),
		alert.Message)

	// summary is shown in notification preview, max 20 chars
	summary := alert.Title
	if len(summary) > 20 {
		runes := []rune(summary)
		if len(runes) > 20 {
			summary = string(runes[:20]) + "..."
		}
	}

	payload, _ := json.Marshal(map[string]interface{}{
		"appToken":    c.appToken,
		"content":     content,
		"summary":     summary,
		"contentType": 3, // 3=markdown
		"uids":        []string{c.uid},
	})

	req, err := http.NewRequestWithContext(ctx, "POST", "https://wxpusher.zjiecode.com/api/send/message", bytes.NewReader(payload))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return fmt.Errorf("WxPusher推送失败: HTTP %d", resp.StatusCode)
	}

	// Check response body for success
	var result struct {
		Code int    `json:"code"`
		Msg  string `json:"msg"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err == nil {
		if result.Code != 1000 {
			return fmt.Errorf("WxPusher推送失败: %s", result.Msg)
		}
	}
	return nil
}
