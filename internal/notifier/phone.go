package notifier

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/suoten/serverguard/internal/types"
)

// PhoneChannel 电话语音通知渠道
// 支持阿里云语音通知、腾讯云语音通知、自定义语音API
// 仅用于 Critical 和 Fatal 级别告警
type PhoneChannel struct {
	name         string
	enabled      bool
	provider     string // aliyun, tencent, custom
	apiKey       string
	apiSecret    string
	phones       []string
	endpoint     string
	templateCode string
	minLevel     types.AlertLevel
	rateLimit    time.Duration
	lastCall     time.Time
}

// NewPhoneChannel 创建电话通知渠道
func NewPhoneChannel(name, provider, apiKey, apiSecret string, phones []string) *PhoneChannel {
	return &PhoneChannel{
		name:      name,
		enabled:   true,
		provider:  provider,
		apiKey:    apiKey,
		apiSecret: apiSecret,
		phones:    phones,
		minLevel:  types.AlertCritical,
		rateLimit: 5 * time.Minute,
	}
}

func (c *PhoneChannel) Name() string      { return c.name }
func (c *PhoneChannel) Enabled() bool     { return c.enabled }
func (c *PhoneChannel) SetEnabled(b bool) { c.enabled = b }

// alertSeverityRank 返回告警级别的数值排序
func alertSeverityRank(level types.AlertLevel) int {
	switch level {
	case types.AlertInfo:
		return 1
	case types.AlertWarning:
		return 2
	case types.AlertError:
		return 3
	case types.AlertCritical:
		return 4
	case types.AlertFatal:
		return 5
	default:
		return 0
	}
}

// shouldCall 判断告警级别是否达到电话通知阈值
func shouldCall(alertLevel, minLevel types.AlertLevel) bool {
	return alertSeverityRank(alertLevel) >= alertSeverityRank(minLevel)
}

// SetMinLevel 设置最低触发告警级别
func (c *PhoneChannel) SetMinLevel(level types.AlertLevel) {
	c.minLevel = level
}

// SetRateLimit 设置速率限制（两次通话最小间隔）
func (c *PhoneChannel) SetRateLimit(d time.Duration) {
	c.rateLimit = d
}

// Send 发送电话通知
func (c *PhoneChannel) Send(ctx context.Context, alert types.Alert) error {
	if len(c.phones) == 0 {
		return fmt.Errorf("电话接收号码未配置")
	}

	if !shouldCall(alert.Level, c.minLevel) {
		return nil
	}

	now := time.Now()
	if now.Sub(c.lastCall) < c.rateLimit {
		return fmt.Errorf("电话通知速率限制: 距上次通话不足 %v", c.rateLimit)
	}
	c.lastCall = now

	content := fmt.Sprintf("告警: %s. %s", alert.Title, alert.Message)
	if len(content) > 200 {
		content = content[:197] + "..."
	}

	var lastErr error
	for _, phone := range c.phones {
		var err error
		switch c.provider {
		case "aliyun":
			err = c.callAliyun(ctx, phone, content)
		case "tencent":
			err = c.callTencent(ctx, phone, content)
		case "custom":
			err = c.callCustom(ctx, phone, content)
		default:
			err = fmt.Errorf("不支持的电话通知提供商: %s", c.provider)
		}
		if err != nil {
			lastErr = err
		}
	}

	return lastErr
}

// callAliyun 通过阿里云语音通知API拨打电话
func (c *PhoneChannel) callAliyun(ctx context.Context, phone, content string) error {
	endpoint := c.endpoint
	if endpoint == "" {
		endpoint = "https://dyvmsapi.aliyuncs.com"
	}

	params := url.Values{
		"PhoneNumbers":     {phone},
		"AccessKeyId":      {c.apiKey},
		"Action":           {"SingleCallByTts"},
		"Format":           {"JSON"},
		"Version":          {"2017-05-25"},
		"Timestamp":        {time.Now().UTC().Format(time.RFC3339)},
		"SignatureMethod":  {"HMAC-SHA1"},
		"SignatureVersion": {"1.0"},
		"SignatureNonce":   {fmt.Sprintf("%d", time.Now().UnixNano())},
	}

	if c.templateCode != "" {
		params.Set("TtsCode", c.templateCode)
	}
	templateParam := fmt.Sprintf(`{"content":"%s"}`, content)
	params.Set("TtsParam", templateParam)

	req, err := http.NewRequestWithContext(ctx, "GET", endpoint+"?"+params.Encode(), nil)
	if err != nil {
		return err
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("阿里云语音通知失败: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("阿里云语音API返回状态码: %d", resp.StatusCode)
	}
	return nil
}

// callTencent 通过腾讯云语音通知API拨打电话
func (c *PhoneChannel) callTencent(ctx context.Context, phone, content string) error {
	endpoint := c.endpoint
	if endpoint == "" {
		endpoint = "https://vms.tencentcloudapi.com"
	}

	payload := fmt.Sprintf(`{
		"CalledNumber": "%s",
		"VoiceSdkAppId": "%s",
		"TemplateId": "%s",
		"TemplateParamSet": ["%s"]
	}`, phone, c.apiKey, c.templateCode, content)

	req, err := http.NewRequestWithContext(ctx, "POST", endpoint, strings.NewReader(payload))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+c.apiSecret)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("腾讯云语音通知失败: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("腾讯云语音API返回状态码: %d", resp.StatusCode)
	}
	return nil
}

// callCustom 通过自定义HTTP接口拨打电话
func (c *PhoneChannel) callCustom(ctx context.Context, phone, content string) error {
	if c.endpoint == "" {
		return fmt.Errorf("自定义电话接口URL未配置")
	}

	params := url.Values{
		"phone":   {phone},
		"content": {content},
		"key":     {c.apiKey},
	}

	req, err := http.NewRequestWithContext(ctx, "POST", c.endpoint, strings.NewReader(params.Encode()))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("自定义电话通知失败: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("自定义电话API返回状态码: %d", resp.StatusCode)
	}
	return nil
}
