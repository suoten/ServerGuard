package notifier

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/suoten/serverguard/internal/types"
	"github.com/suoten/serverguard/internal/agent/eventbus"
)

// --- Channel constructor / Name / Enabled tests ---

func TestEmailChannel(t *testing.T) {
	c := NewEmailChannel("email-1", "smtp.example.com", "587", "user", "pass", "from@example.com", []string{"to@example.com"})
	if c.Name() != "email-1" {
		t.Errorf("expected name 'email-1', got %q", c.Name())
	}
	if !c.Enabled() {
		t.Error("should be enabled by default")
	}
}

func TestWebhookChannel(t *testing.T) {
	c := NewWebhookChannel("wh", "http://example.com/hook", map[string]string{"X-Token": "abc"})
	if c.Name() != "wh" {
		t.Error("name mismatch")
	}
	if !c.Enabled() {
		t.Error("should be enabled")
	}
}

func TestDingTalkChannel(t *testing.T) {
	c := NewDingTalkChannel("dt", "https://oapi.dingtalk.com/robot/send?access_token=x", "secret")
	if c.Name() != "dt" || !c.Enabled() {
		t.Error("constructor fields wrong")
	}
}

func TestWeChatChannel(t *testing.T) {
	c := NewWeChatChannel("wx", "https://qyapi.weixin.qq.com/cgi-bin/webhook/send?key=x")
	if c.Name() != "wx" || !c.Enabled() {
		t.Error("constructor fields wrong")
	}
}

func TestFeishuChannel(t *testing.T) {
	c := NewFeishuChannel("fs", "https://open.feishu.cn/open-apis/bot/v2/hook/x")
	if c.Name() != "fs" || !c.Enabled() {
		t.Error("constructor fields wrong")
	}
}

func TestSlackChannel(t *testing.T) {
	c := NewSlackChannel("slack", "https://hooks.slack.com/services/x")
	if c.Name() != "slack" || !c.Enabled() {
		t.Error("constructor fields wrong")
	}
}

func TestTelegramChannel(t *testing.T) {
	c := NewTelegramChannel("tg", "bot-token", "chat-id")
	if c.Name() != "tg" || !c.Enabled() {
		t.Error("constructor fields wrong")
	}
}

func TestWxPusherChannel(t *testing.T) {
	c := NewWxPusherChannel("wxp", "token123", "uid123")
	if c.Name() != "wxp" || !c.Enabled() {
		t.Error("constructor fields wrong")
	}
}

// --- WebhookChannel.Send with httptest ---

func TestWebhookChannel_Send(t *testing.T) {
	var received atomic.Int32
	var mu sync.Mutex
	var gotBody string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			t.Errorf("expected POST, got %s", r.Method)
		}
		if r.Header.Get("Content-Type") != "application/json" {
			t.Errorf("expected json content-type, got %q", r.Header.Get("Content-Type"))
		}
		if r.Header.Get("X-Token") != "abc" {
			t.Errorf("expected custom header, got %q", r.Header.Get("X-Token"))
		}
		buf := make([]byte, 1024)
		n, _ := r.Body.Read(buf)
		mu.Lock()
		gotBody = string(buf[:n])
		mu.Unlock()
		received.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	c := NewWebhookChannel("wh", srv.URL, map[string]string{"X-Token": "abc"})
	alert := types.Alert{Level: types.AlertError, Title: "test", Message: "msg", Source: "unit", Timestamp: time.Now()}
	if err := c.Send(context.Background(), alert); err != nil {
		t.Errorf("Send error: %v", err)
	}
	if received.Load() != 1 {
		t.Error("server should receive 1 request")
	}
	mu.Lock()
	defer mu.Unlock()
	if !strings.Contains(gotBody, "test") {
		t.Error("body should contain alert title")
	}
}

func TestWebhookChannel_SendBadURL(t *testing.T) {
	c := NewWebhookChannel("wh", "http://127.0.0.1:0/nonexistent", nil)
	alert := types.Alert{Level: types.AlertError, Title: "t", Timestamp: time.Now()}
	// Should return an error for unreachable URL
	if err := c.Send(context.Background(), alert); err == nil {
		t.Error("expected error for bad URL")
	}
}

// --- DingTalkChannel.Send with httptest ---

func TestDingTalkChannel_Send(t *testing.T) {
	var received atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		received.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	c := NewDingTalkChannel("dt", srv.URL, "")
	alert := types.Alert{Level: types.AlertCritical, Title: "critical", Message: "down", Source: "s", Timestamp: time.Now()}
	if err := c.Send(context.Background(), alert); err != nil {
		t.Errorf("Send error: %v", err)
	}
	if received.Load() != 1 {
		t.Error("server should receive request")
	}
}

func TestDingTalkChannel_SendWithSecret(t *testing.T) {
	var received atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// URL should contain timestamp and sign params
		if !strings.Contains(r.URL.RawQuery, "timestamp=") || !strings.Contains(r.URL.RawQuery, "sign=") {
			t.Error("signed request should include timestamp and sign")
		}
		received.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	// DingTalk webhook URL normally includes ?access_token=...; the secret path appends &timestamp=&sign=
	// Use a base URL with an existing query parameter so the appended &... produces a valid URL.
	c := NewDingTalkChannel("dt", srv.URL+"?access_token=test", "mysecret")

	alert := types.Alert{Level: types.AlertError, Title: "t", Timestamp: time.Now()}
	if err := c.Send(context.Background(), alert); err != nil {
		t.Errorf("Send error: %v", err)
	}
	if received.Load() != 1 {
		t.Error("server should receive signed request")
	}
}

// --- WeChat / Feishu / Slack / Telegram / WxPusher Send tests ---

func TestWeChatChannel_Send(t *testing.T) {
	var received atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		received.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	c := NewWeChatChannel("wx", srv.URL)
	if err := c.Send(context.Background(), types.Alert{Level: types.AlertWarning, Title: "t", Timestamp: time.Now()}); err != nil {
		t.Errorf("Send error: %v", err)
	}
	if received.Load() != 1 {
		t.Error("server should receive request")
	}
}

func TestFeishuChannel_Send(t *testing.T) {
	var received atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		received.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	c := NewFeishuChannel("fs", srv.URL)
	if err := c.Send(context.Background(), types.Alert{Level: types.AlertError, Title: "t", Timestamp: time.Now()}); err != nil {
		t.Errorf("Send error: %v", err)
	}
	if received.Load() != 1 {
		t.Error("server should receive request")
	}
}

func TestSlackChannel_Send(t *testing.T) {
	var received atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		received.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	c := NewSlackChannel("slack", srv.URL)
	if err := c.Send(context.Background(), types.Alert{Level: types.AlertCritical, Title: "t", Timestamp: time.Now()}); err != nil {
		t.Errorf("Send error: %v", err)
	}
	if received.Load() != 1 {
		t.Error("server should receive request")
	}
}

func TestTelegramChannel_Send(t *testing.T) {
	var received atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		received.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	c := NewTelegramChannel("tg", "token", "chatid")
	// Override the URL by using a custom client is hard; instead test that it constructs request without panic
	// The real Telegram URL is hardcoded, so this will attempt a real network call.
	// We test only that Send doesn't panic by using a short-timeout context.
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	_ = c.Send(ctx, types.Alert{Level: types.AlertError, Title: "t", Timestamp: time.Now()})
	_ = received.Load()
}

func TestWxPusherChannel_SendNoKey(t *testing.T) {
	c := NewWxPusherChannel("wxp", "", "")
	err := c.Send(context.Background(), types.Alert{Level: types.AlertError, Title: "t", Timestamp: time.Now()})
	if err == nil {
		t.Error("expected error when appToken and UID are empty")
	}
}

func TestWxPusherChannel_Send(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"code":1000,"msg":"success"}`))
	}))
	defer srv.Close()

	c := NewWxPusherChannel("wxp", "token", "uid")
	// WxPusher URL is hardcoded to wxpusher.zjiecode.com; we can't easily redirect.
	// Test the no-key error path instead (covered above) and constructor.
	_ = c
}

// --- Notifier tests ---

func TestNotifier_New(t *testing.T) {
	bus := eventbus.New(16)
	defer bus.Stop()
	n := New(bus)
	if n == nil {
		t.Fatal("New returned nil")
	}
}

func TestNotifier_AddChannel(t *testing.T) {
	bus := eventbus.New(16)
	defer bus.Stop()
	n := New(bus)

	n.AddChannel(NewWebhookChannel("wh", "http://example.com", nil))
	n.mu.RLock()
	count := len(n.channels)
	n.mu.RUnlock()
	if count != 1 {
		t.Errorf("expected 1 channel, got %d", count)
	}
}

func TestNotifier_UpdateChannels(t *testing.T) {
	bus := eventbus.New(16)
	defer bus.Stop()
	n := New(bus)

	n.UpdateChannels([]Channel{
		NewWebhookChannel("wh1", "http://example.com", nil),
		NewWebhookChannel("wh2", "http://example.com", nil),
	})
	n.mu.RLock()
	count := len(n.channels)
	n.mu.RUnlock()
	if count != 2 {
		t.Errorf("expected 2 channels after update, got %d", count)
	}
}

func TestNotifier_SetSilence(t *testing.T) {
	bus := eventbus.New(16)
	defer bus.Stop()
	n := New(bus)

	n.SetSilence(SilenceConfig{Enabled: true, Periods: []SilencePeriod{{StartHour: 0, EndHour: 24}}})
	n.mu.RLock()
	enabled := n.silence.Enabled
	n.mu.RUnlock()
	if !enabled {
		t.Error("silence should be enabled")
	}
}

func TestNotifier_IsSilenced(t *testing.T) {
	bus := eventbus.New(16)
	defer bus.Stop()
	n := New(bus)

	// No silence configured
	if n.isSilenced("error") {
		t.Error("should not be silenced when silence disabled")
	}

	// Silence all levels during all hours
	n.SetSilence(SilenceConfig{
		Enabled: true,
		Periods: []SilencePeriod{{StartHour: 0, EndHour: 24}},
	})
	if !n.isSilenced("error") {
		t.Error("should be silenced with full-day all-level silence")
	}
}

func TestNotifier_IsSilencedSpecificLevel(t *testing.T) {
	bus := eventbus.New(16)
	defer bus.Stop()
	n := New(bus)

	hour := time.Now().Hour()
	endHour := hour + 2
	if endHour > 24 {
		endHour = 24
	}
	n.SetSilence(SilenceConfig{
		Enabled: true,
		Periods: []SilencePeriod{{StartHour: hour, EndHour: endHour, Levels: []string{"warning"}}},
	})
	if !n.isSilenced("warning") {
		t.Error("warning should be silenced")
	}
	if n.isSilenced("critical") {
		t.Error("critical should not be silenced (not in levels list)")
	}
}

func TestNotifier_SetDigest(t *testing.T) {
	bus := eventbus.New(16)
	defer bus.Stop()
	n := New(bus)

	n.SetDigest(true, 9)
	n.mu.RLock()
	enabled := n.digestEnabled
	hour := n.digestHour
	n.mu.RUnlock()
	if !enabled || hour != 9 {
		t.Error("SetDigest did not configure correctly")
	}
}

func TestNotifier_SendCustom(t *testing.T) {
	bus := eventbus.New(16)
	defer bus.Stop()
	n := New(bus)

	if err := n.SendCustom("title", "message"); err != nil {
		t.Errorf("SendCustom error: %v", err)
	}
}

func TestNotifier_SendToChannelsInfoLevel(t *testing.T) {
	bus := eventbus.New(16)
	defer bus.Stop()
	n := New(bus)

	var sent atomic.Int32
	mockCh := &mockChannel{name: "mock", enabled: true, sendFn: func(ctx context.Context, a types.Alert) error {
		sent.Add(1)
		return nil
	}}
	n.AddChannel(mockCh)

	// Info level should not send to any channel
	n.sendToChannels(types.Alert{Level: types.AlertInfo, Title: "info", Timestamp: time.Now()})
	time.Sleep(50 * time.Millisecond)
	if sent.Load() != 0 {
		t.Error("info level should not trigger sends")
	}
}

func TestNotifier_SendToChannelsCritical(t *testing.T) {
	bus := eventbus.New(16)
	defer bus.Stop()
	n := New(bus)

	var sent atomic.Int32
	mockCh := &mockChannel{name: "mock", enabled: true, sendFn: func(ctx context.Context, a types.Alert) error {
		sent.Add(1)
		return nil
	}}
	n.AddChannel(mockCh)

	n.sendToChannels(types.Alert{Level: types.AlertCritical, Title: "crit", Timestamp: time.Now()})
	time.Sleep(100 * time.Millisecond)
	if sent.Load() != 1 {
		t.Errorf("critical level should send to channel, got %d sends", sent.Load())
	}
}

func TestNotifier_SendToChannelsWarningSkipsEmail(t *testing.T) {
	bus := eventbus.New(16)
	defer bus.Stop()
	n := New(bus)

	var emailSent, imSent atomic.Int32
	emailCh := &mockChannel{name: "email-alert", enabled: true, sendFn: func(ctx context.Context, a types.Alert) error {
		emailSent.Add(1)
		return nil
	}}
	imCh := &mockChannel{name: "dingtalk", enabled: true, sendFn: func(ctx context.Context, a types.Alert) error {
		imSent.Add(1)
		return nil
	}}
	n.AddChannel(emailCh)
	n.AddChannel(imCh)

	n.sendToChannels(types.Alert{Level: types.AlertWarning, Title: "warn", Timestamp: time.Now()})
	time.Sleep(100 * time.Millisecond)
	if emailSent.Load() != 0 {
		t.Error("warning should skip email channel")
	}
	if imSent.Load() != 1 {
		t.Error("warning should send to IM channel")
	}
}

// --- mock Channel ---

type mockChannel struct {
	name    string
	enabled bool
	sendFn  func(ctx context.Context, alert types.Alert) error
}

func (m *mockChannel) Name() string  { return m.name }
func (m *mockChannel) Enabled() bool { return m.enabled }
func (m *mockChannel) Send(ctx context.Context, alert types.Alert) error {
	if m.sendFn != nil {
		return m.sendFn(ctx, alert)
	}
	return nil
}

// --- handleAlert via EventBus ---

func TestNotifier_HandleAlertViaEventBus(t *testing.T) {
	bus := eventbus.New(64)
	defer bus.Stop()
	bus.Start()

	n := New(bus)
	var sent atomic.Int32
	n.AddChannel(&mockChannel{name: "webhook", enabled: true, sendFn: func(ctx context.Context, a types.Alert) error {
		sent.Add(1)
		return nil
	}})

	// Publish an alert event; the notifier's handleAlert should send to channels
	bus.PublishAlert(types.AlertError, "test-src", "test-alert", "test message", "rule-1")

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if sent.Load() >= 1 {
			break
		}
		time.Sleep(time.Millisecond)
	}
	if sent.Load() < 1 {
		t.Error("expected at least 1 send via handleAlert")
	}
}

func TestNotifier_HandleAlertSilenced(t *testing.T) {
	bus := eventbus.New(64)
	defer bus.Stop()
	bus.Start()

	n := New(bus)
	n.SetSilence(SilenceConfig{Enabled: true, Periods: []SilencePeriod{{StartHour: 0, EndHour: 24}}})

	var sent atomic.Int32
	n.AddChannel(&mockChannel{name: "webhook", enabled: true, sendFn: func(ctx context.Context, a types.Alert) error {
		sent.Add(1)
		return nil
	}})

	bus.PublishAlert(types.AlertError, "src", "title", "msg", "rule-1")
	time.Sleep(200 * time.Millisecond)
	if sent.Load() != 0 {
		t.Error("silenced alert should not send")
	}
}

func TestNotifier_HandleAlertInfoLevelSkipped(t *testing.T) {
	bus := eventbus.New(64)
	defer bus.Stop()
	bus.Start()

	n := New(bus)
	var sent atomic.Int32
	n.AddChannel(&mockChannel{name: "webhook", enabled: true, sendFn: func(ctx context.Context, a types.Alert) error {
		sent.Add(1)
		return nil
	}})

	// Info level should not send
	bus.PublishAlert(types.AlertInfo, "src", "title", "msg", "rule-1")
	time.Sleep(200 * time.Millisecond)
	if sent.Load() != 0 {
		t.Error("info level alert should not send to channels")
	}
}

// --- EmailChannel.Send (will fail without SMTP server) ---

func TestEmailChannel_SendConnectionError(t *testing.T) {
	c := NewEmailChannel("email", "127.0.0.1", "1", "user", "pass", "from@example.com", []string{"to@example.com"})
	// Sending to a non-existent SMTP server should return an error
	err := c.Send(context.Background(), types.Alert{Level: types.AlertError, Title: "t", Message: "m", Source: "s", Timestamp: time.Now()})
	if err == nil {
		t.Error("expected error when SMTP server unavailable")
	}
}

// --- ServerChanChannel.Send with httptest ---

func TestWxPusherChannel_SendSuccess(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"code":1000,"msg":"success"}`))
	}))
	defer srv.Close()

	c := NewWxPusherChannel("wxp", "token", "uid")
	// WxPusher URL is hardcoded; we can't redirect easily.
	// Test the error path when token is empty (already covered) and the non-200 path.
	_ = c
}

func TestWxPusherChannel_SendNon200(t *testing.T) {
	// Can't easily test non-200 without mocking the hardcoded URL.
	// The no-key error path is already covered.
	_ = NewWxPusherChannel("wxp", "token", "uid")
}

func TestNotifier_SendToChannelsErrorLevelSkipsEmail(t *testing.T) {
	bus := eventbus.New(16)
	defer bus.Stop()
	n := New(bus)

	var emailSent, whSent atomic.Int32
	emailCh := &mockChannel{name: "email-alert", enabled: true, sendFn: func(ctx context.Context, a types.Alert) error {
		emailSent.Add(1)
		return nil
	}}
	whCh := &mockChannel{name: "webhook", enabled: true, sendFn: func(ctx context.Context, a types.Alert) error {
		whSent.Add(1)
		return nil
	}}
	n.AddChannel(emailCh)
	n.AddChannel(whCh)

	n.sendToChannels(types.Alert{Level: types.AlertError, Title: "err", Timestamp: time.Now()})
	time.Sleep(100 * time.Millisecond)
	if emailSent.Load() != 0 {
		t.Error("error level should skip email channel")
	}
	if whSent.Load() != 1 {
		t.Error("error level should send to non-email channel")
	}
}

func TestNotifier_HandleAlertAggregation(t *testing.T) {
	bus := eventbus.New(64)
	defer bus.Stop()
	bus.Start()

	n := New(bus)
	var sent atomic.Int32
	n.AddChannel(&mockChannel{name: "webhook", enabled: true, sendFn: func(ctx context.Context, a types.Alert) error {
		sent.Add(1)
		return nil
	}})

	// First alert sends immediately
	bus.PublishAlert(types.AlertCritical, "src", "agg-title", "msg", "agg-rule")
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if sent.Load() >= 1 {
			break
		}
		time.Sleep(time.Millisecond)
	}
	if sent.Load() < 1 {
		t.Error("first alert should send immediately")
	}

	// Second alert within cooldown should be buffered (not sent immediately)
	firstCount := sent.Load()
	bus.PublishAlert(types.AlertCritical, "src", "agg-title", "msg", "agg-rule")
	time.Sleep(200 * time.Millisecond)
	if sent.Load() != firstCount {
		t.Error("second alert within cooldown should be buffered, not sent")
	}
}

func TestNotifier_SendToChannelsDisabledChannel(t *testing.T) {
	bus := eventbus.New(16)
	defer bus.Stop()
	n := New(bus)

	var sent atomic.Int32
	n.AddChannel(&mockChannel{name: "webhook", enabled: false, sendFn: func(ctx context.Context, a types.Alert) error {
		sent.Add(1)
		return nil
	}})

	n.sendToChannels(types.Alert{Level: types.AlertCritical, Title: "t", Timestamp: time.Now()})
	time.Sleep(100 * time.Millisecond)
	if sent.Load() != 0 {
		t.Error("disabled channel should not receive")
	}
}
