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

// SMSChannel 短信通知渠道
// 支持阿里云短信、腾讯云短信、华为云短信
type SMSChannel struct {
	name         string
	enabled      bool
	provider     string // aliyun, tencent, huawei, custom
	apiKey       string
	apiSecret    string
	signName     string
	templateCode string
	phones       []string
	endpoint     string
}

// NewSMSChannel 创建短信通知渠道
func NewSMSChannel(name, provider, apiKey, apiSecret, signName, templateCode string, phones []string) *SMSChannel {
	return &SMSChannel{
		name:         name,
		enabled:      true,
		provider:     provider,
		apiKey:       apiKey,
		apiSecret:    apiSecret,
		signName:     signName,
		templateCode: templateCode,
		phones:       phones,
	}
}

func (c *SMSChannel) Name() string      { return c.name }
func (c *SMSChannel) Enabled() bool     { return c.enabled }
func (c *SMSChannel) SetEnabled(b bool) { c.enabled = b }

// Send 发送短信通知
func (c *SMSChannel) Send(ctx context.Context, alert types.Alert) error {
	if len(c.phones) == 0 {
		return fmt.Errorf("短信接收号码未配置")
	}

	levelText := map[types.AlertLevel]string{
		types.AlertInfo:     "[信息]",
		types.AlertWarning:  "[警告]",
		types.AlertError:    "[错误]",
		types.AlertCritical: "[严重]",
		types.AlertFatal:    "[致命]",
	}
	levelStr := levelText[alert.Level]
	if levelStr == "" {
		levelStr = "[" + string(alert.Level) + "]"
	}

	content := fmt.Sprintf("%s %s: %s", levelStr, alert.Title, alert.Message)
	if len(content) > 500 {
		content = content[:497] + "..."
	}

	var lastErr error
	for _, phone := range c.phones {
		var err error
		switch c.provider {
		case "aliyun":
			err = c.sendAliyun(ctx, phone, content)
		case "tencent":
			err = c.sendTencent(ctx, phone, content)
		case "huawei":
			err = c.sendHuawei(ctx, phone, content)
		case "custom":
			err = c.sendCustom(ctx, phone, content)
		default:
			err = fmt.Errorf("不支持的短信提供商: %s", c.provider)
		}
		if err != nil {
			lastErr = err
		}
	}

	return lastErr
}

// sendAliyun 通过阿里云短信API发送
func (c *SMSChannel) sendAliyun(ctx context.Context, phone, content string) error {
	endpoint := c.endpoint
	if endpoint == "" {
		endpoint = "https://dysmsapi.aliyuncs.com"
	}

	params := url.Values{
		"PhoneNumbers":     {phone},
		"SignName":         {c.signName},
		"TemplateCode":     {c.templateCode},
		"AccessKeyId":      {c.apiKey},
		"Action":           {"SendSms"},
		"Format":           {"JSON"},
		"Version":          {"2017-05-25"},
		"Timestamp":        {time.Now().UTC().Format(time.RFC3339)},
		"SignatureMethod":  {"HMAC-SHA1"},
		"SignatureVersion": {"1.0"},
		"SignatureNonce":   {fmt.Sprintf("%d", time.Now().UnixNano())},
	}

	templateParam := fmt.Sprintf(`{"content":"%s"}`, content)
	params.Set("TemplateParam", templateParam)

	req, err := http.NewRequestWithContext(ctx, "GET", endpoint+"?"+params.Encode(), nil)
	if err != nil {
		return err
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("阿里云短信发送失败: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("阿里云短信API返回状态码: %d", resp.StatusCode)
	}
	return nil
}

// sendTencent 通过腾讯云短信API发送
func (c *SMSChannel) sendTencent(ctx context.Context, phone, content string) error {
	endpoint := c.endpoint
	if endpoint == "" {
		endpoint = "https://sms.tencentcloudapi.com"
	}

	payload := fmt.Sprintf(`{
		"PhoneNumber": "%s",
		"SignName": "%s",
		"TemplateId": "%s",
		"TemplateParamSet": ["%s"],
		"SmsSdkAppId": "%s"
	}`, phone, c.signName, c.templateCode, content, c.apiKey)

	req, err := http.NewRequestWithContext(ctx, "POST", endpoint, strings.NewReader(payload))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+c.apiSecret)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("腾讯云短信发送失败: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("腾讯云短信API返回状态码: %d", resp.StatusCode)
	}
	return nil
}

// sendHuawei 通过华为云短信API发送
func (c *SMSChannel) sendHuawei(ctx context.Context, phone, content string) error {
	endpoint := c.endpoint
	if endpoint == "" {
		endpoint = "https://smsapi.cn-north-4.myhuaweicloud.com/sms/v1/sms/batchSendSms"
	}

	params := url.Values{
		"to":            {phone},
		"signature":     {c.signName},
		"templateID":    {c.templateCode},
		"templateParas": {fmt.Sprintf(`["%s"]`, content)},
	}

	req, err := http.NewRequestWithContext(ctx, "POST", endpoint, strings.NewReader(params.Encode()))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Authorization", "WSSE realm=\"SDS\", username=\""+c.apiKey+"\"")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("华为云短信发送失败: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("华为云短信API返回状态码: %d", resp.StatusCode)
	}
	return nil
}

// sendCustom 通过自定义HTTP接口发送短信
func (c *SMSChannel) sendCustom(ctx context.Context, phone, content string) error {
	if c.endpoint == "" {
		return fmt.Errorf("自定义短信接口URL未配置")
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
		return fmt.Errorf("自定义短信发送失败: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("自定义短信API返回状态码: %d", resp.StatusCode)
	}
	return nil
}
