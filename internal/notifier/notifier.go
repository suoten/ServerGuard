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

// 向宝塔学习：包级共享 HTTP client，替代 http.DefaultClient
// DefaultClient 没有超时、没有连接池限制，在低配服务器上容易泄漏 goroutine
var sharedHTTPClient = &http.Client{
	Timeout: 10 * time.Second,
	Transport: &http.Transport{
		MaxIdleConns:        5,
		MaxIdleConnsPerHost: 2,
		IdleConnTimeout:     60 * time.Second,
	},
}

// AlertHumanizer 可选的告警文案增强接口（由 LLM 增强器实现）
type AlertHumanizer interface {
	IsEnabled() bool
	HumanizeAlert(alert types.Alert) string
}

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

	// historyProvider 历史相似故障查询器（可选注入，告警推送时附经验提示）
	historyProvider HistoryProvider

	// P0 告警升级 + 时区感知延迟推送
	escalationMgr *EscalationManager
	timeZoneDelay *TimeZoneDelay

	// 智能降噪：抖动抑制 + 同源关联归并
	corr *correlator

	// V4.0 — LLM 增强层（可选，默认 nil）
	humanizer AlertHumanizer

	// V4.0 — 双向通知器（可选，默认 nil）
	biNotifier *BidirectionalNotifier

	// stopCh 关闭时 backgroundLoop 退出，避免 goroutine 泄漏
	stopCh    chan struct{}
	stopOnce  sync.Once
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
		stopCh:         make(chan struct{}),
	}

	// Subscribe to alert events
	bus.Subscribe(types.EventAlert, n.handleAlert)

	// 向宝塔学习：5 个独立 goroutine 合并为 1 个
	// 原来每个功能各启一个 goroutine 各一个 ticker，5 个 ticker 每次都唤醒一次调度器
	// 合并后只需 1 个 goroutine、1 个 ticker，按内部计数器分频执行
	go n.backgroundLoop()

	return n
}

// Stop 停止后台循环（幂等）。进程优雅退出或重建 Notifier 时调用。
func (n *Notifier) Stop() {
	n.stopOnce.Do(func() { close(n.stopCh) })
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

// HistoryProvider 根据告警症状返回历史相似故障的处理经验（无命中返回空串）。
// 由 main 注入知识库查询，避免 notifier 直接依赖 knowledge 包。
type HistoryProvider func(title, source string) string

// SetHistoryProvider 注入历史相似故障查询器——告警推送时自动附上
// "这个症状历史上是怎么解决的"，让每条告警自带药方。
func (n *Notifier) SetHistoryProvider(p HistoryProvider) {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.historyProvider = p
}

// historyHint 查询历史经验并格式化为可追加的提示文本。
func (n *Notifier) historyHint(title, source string) string {
	n.mu.RLock()
	p := n.historyProvider
	n.mu.RUnlock()
	if p == nil {
		return ""
	}
	hint := p(title, source)
	if hint == "" {
		return ""
	}
	return "\n\n📚 历史相似故障经验：\n" + hint
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

	// 历史经验注入：知识库里有相似症状的处置记录时，附在告警后一起推送——
	// 让收到告警的人第一眼就知道"上次是怎么解决的"
	if hint := n.historyHint(event.Title, event.Source); hint != "" {
		alert.Message += hint
	}

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

	// V4.0 — LLM 增强层：如果启用，用 LLM 人性化告警文案
	n.mu.RLock()
	humanizer := n.humanizer
	biNotifier := n.biNotifier
	n.mu.RUnlock()

	if humanizer != nil && humanizer.IsEnabled() {
		if enhanced := humanizer.HumanizeAlert(alert); enhanced != "" {
			alert.Message = enhanced
		}
	}

	// V4.0 — 双向通知：如果启用，给告警附加回复编号
	if biNotifier != nil {
		shortID, formattedMsg := biNotifier.FormatAlertWithActionCode(alert)
		if shortID != "" {
			alert.Message = formattedMsg
		}
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

		// 向宝塔学习：低配服务器通知渠道通常只有 1-2 个
		// 不为每个 channel 开 goroutine，串行发送更省资源
		// 只有渠道数 > 2 时才并发
		if len(channels) > 2 {
			go func(c Channel) {
				if err := c.Send(ctx, alert); err != nil {
					_ = err
				}
			}(ch)
		} else {
			// 串行发送，不开 goroutine
			_ = ch.Send(ctx, alert)
		}
	}
}

// backgroundLoop 合并版后台循环：1 个 goroutine、1 个 ticker 管所有周期任务。
// 向宝塔学习：不搞 5 个 goroutine 各一个 ticker，1 个就够
//
// 分频方案（base = 30s）：
//   tick % 1  → aggregation flush + escalation check（每 30s）
//   tick % 2  → correlator flush（每 60s）
//   tick % 10 → timeZoneDelay flush（每 5min）
//   tick % 20 → dailyDigest check（每 10min）
func (n *Notifier) backgroundLoop() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	tick := 0
	for {
		select {
		case <-n.stopCh:
			return
		case <-ticker.C:
		}
		tick++
		now := time.Now()

		// 每 30s：告警聚合 flush
		n.flushAggregation()

		// 每 30s：P0 升级检查
		n.flushEscalation()

		// 每 60s：关联事件 flush
		if tick%2 == 0 {
			n.flushCorrelator()
		}

		// 每 5min：时区延迟 flush
		if tick%10 == 0 {
			n.flushTimeZoneDelay()
		}

		// 每 10min：每日摘要检查
		if tick%20 == 0 {
			n.checkDailyDigest(now)
		}
	}
}

// flushAggregation sends aggregated alert summaries.
func (n *Notifier) flushAggregation() {
	n.aggMu.Lock()
	for key, alerts := range n.aggBuffer {
		if len(alerts) <= 1 {
			delete(n.aggBuffer, key)
			continue
		}
		lastSend, exists := n.aggLastSend[key]
		if exists && time.Since(lastSend) < n.aggCooldown {
			continue
		}
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

// flushEscalation checks and sends P0 escalations.
func (n *Notifier) flushEscalation() {
	for _, alert := range n.escalationMgr.CheckAndEscalate() {
		escalatedAlert := alert
		escalatedAlert.Title = "[升级] " + alert.Title
		escalatedAlert.Message = fmt.Sprintf("P0 告警已超过阈值未确认，自动升级推送。\n\n原始告警：%s", alert.Message)
		n.sendToChannels(escalatedAlert)
	}
}

// flushCorrelator sends correlator flush summaries.
func (n *Notifier) flushCorrelator() {
	for _, summary := range n.corr.Flush(time.Now()) {
		n.sendToChannels(summary)
	}
}

// flushTimeZoneDelay flushes delayed alerts.
func (n *Notifier) flushTimeZoneDelay() {
	for _, alert := range n.timeZoneDelay.Flush(time.Now()) {
		delayedAlert := alert
		delayedAlert.Title = "[延迟推送] " + alert.Title
		delayedAlert.Message = fmt.Sprintf("凌晨静默期积压告警，现统一推送。\n\n原始告警：%s", alert.Message)
		n.sendToChannels(delayedAlert)
	}
}

// checkDailyDigest checks and sends daily digest if due.
func (n *Notifier) checkDailyDigest(now time.Time) {
	if !n.digestEnabled {
		return
	}
	today := now.Format("2006-01-02")
	if today == n.digestLastDate {
		return
	}
	if now.Hour() >= n.digestHour {
		n.sendDailyDigest()
		n.digestLastDate = today
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

// SetHumanizer 注入 LLM 增强器（可选，nil 表示不启用）
func (n *Notifier) SetHumanizer(h AlertHumanizer) {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.humanizer = h
}

// SetBidirectionalNotifier 注入双向通知器（可选，nil 表示不启用）
func (n *Notifier) SetBidirectionalNotifier(b *BidirectionalNotifier) {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.biNotifier = b
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
	if hour < 0 || hour > 23 {
		hour = 8 // 非法值回退默认早 8 点
	}
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

	resp, err := sharedHTTPClient.Do(req)
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
	resp, err := sharedHTTPClient.Do(req)
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
	resp, err := sharedHTTPClient.Do(req)
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
	resp, err := sharedHTTPClient.Do(req)
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
	resp, err := sharedHTTPClient.Do(req)
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
	resp, err := sharedHTTPClient.Do(req)
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

	resp, err := sharedHTTPClient.Do(req)
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
