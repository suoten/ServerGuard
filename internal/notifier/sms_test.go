package notifier

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/suoten/serverguard/internal/types"
)

// --- SMSChannel tests ---

func TestSMSChannel_Constructor(t *testing.T) {
	c := NewSMSChannel("sms", "aliyun", "key", "secret", "sign", "tpl", []string{"13800000000"})
	if c.Name() != "sms" || !c.Enabled() {
		t.Error("constructor fields wrong")
	}
}

func TestSMSChannel_NoPhones(t *testing.T) {
	c := NewSMSChannel("sms", "aliyun", "key", "secret", "sign", "tpl", nil)
	err := c.Send(context.Background(), types.Alert{Level: types.AlertError, Title: "t", Timestamp: time.Now()})
	if err == nil {
		t.Error("expected error when no phones configured")
	}
}

func TestSMSChannel_UnsupportedProvider(t *testing.T) {
	c := NewSMSChannel("sms", "unknown-provider", "key", "secret", "sign", "tpl", []string{"13800000000"})
	err := c.Send(context.Background(), types.Alert{Level: types.AlertError, Title: "t", Timestamp: time.Now()})
	if err == nil {
		t.Error("expected error for unsupported provider")
	}
}

func TestSMSChannel_SetEnabled(t *testing.T) {
	c := NewSMSChannel("sms", "aliyun", "k", "s", "sign", "tpl", []string{"1"})
	c.SetEnabled(false)
	if c.Enabled() {
		t.Error("SetEnabled(false) should disable")
	}
	c.SetEnabled(true)
	if !c.Enabled() {
		t.Error("SetEnabled(true) should enable")
	}
}

func TestSMSChannel_CustomProvider(t *testing.T) {
	var received atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		received.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	c := NewSMSChannel("sms", "custom", "key", "secret", "sign", "tpl", []string{"13800000000"})
	c.endpoint = srv.URL

	err := c.Send(context.Background(), types.Alert{Level: types.AlertError, Title: "test", Message: "msg", Timestamp: time.Now()})
	if err != nil {
		t.Errorf("custom provider Send error: %v", err)
	}
	if received.Load() != 1 {
		t.Error("custom endpoint should receive request")
	}
}

func TestSMSChannel_CustomProviderNoEndpoint(t *testing.T) {
	c := NewSMSChannel("sms", "custom", "key", "secret", "sign", "tpl", []string{"13800000000"})
	// endpoint is empty
	err := c.Send(context.Background(), types.Alert{Level: types.AlertError, Title: "t", Timestamp: time.Now()})
	if err == nil {
		t.Error("expected error when custom endpoint not configured")
	}
}

func TestSMSChannel_LongContent(t *testing.T) {
	var received atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		received.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	c := NewSMSChannel("sms", "custom", "key", "secret", "sign", "tpl", []string{"13800000000"})
	c.endpoint = srv.URL

	longMsg := string(make([]byte, 600))
	err := c.Send(context.Background(), types.Alert{Level: types.AlertError, Title: "t", Message: longMsg, Timestamp: time.Now()})
	if err != nil {
		t.Errorf("Send with long content error: %v", err)
	}
	if received.Load() != 1 {
		t.Error("should still send truncated content")
	}
}

func TestSMSChannel_AliyunProvider(t *testing.T) {
	var received atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		received.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	c := NewSMSChannel("sms", "aliyun", "key", "secret", "sign", "tpl", []string{"13800000000"})
	c.endpoint = srv.URL

	err := c.Send(context.Background(), types.Alert{Level: types.AlertCritical, Title: "crit", Message: "msg", Timestamp: time.Now()})
	if err != nil {
		t.Errorf("aliyun Send error: %v", err)
	}
	if received.Load() != 1 {
		t.Error("aliyun endpoint should receive request")
	}
}

func TestSMSChannel_TencentProvider(t *testing.T) {
	var received atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		received.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	c := NewSMSChannel("sms", "tencent", "key", "secret", "sign", "tpl", []string{"13800000000"})
	c.endpoint = srv.URL

	err := c.Send(context.Background(), types.Alert{Level: types.AlertCritical, Title: "crit", Message: "msg", Timestamp: time.Now()})
	if err != nil {
		t.Errorf("tencent Send error: %v", err)
	}
	if received.Load() != 1 {
		t.Error("tencent endpoint should receive request")
	}
}

func TestSMSChannel_HuaweiProvider(t *testing.T) {
	var received atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		received.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	c := NewSMSChannel("sms", "huawei", "key", "secret", "sign", "tpl", []string{"13800000000"})
	c.endpoint = srv.URL

	err := c.Send(context.Background(), types.Alert{Level: types.AlertCritical, Title: "crit", Message: "msg", Timestamp: time.Now()})
	if err != nil {
		t.Errorf("huawei Send error: %v", err)
	}
	if received.Load() != 1 {
		t.Error("huawei endpoint should receive request")
	}
}

func TestSMSChannel_MultiplePhones(t *testing.T) {
	var received atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		received.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	c := NewSMSChannel("sms", "custom", "key", "secret", "sign", "tpl", []string{"13800000000", "13900000000", "13700000000"})
	c.endpoint = srv.URL

	err := c.Send(context.Background(), types.Alert{Level: types.AlertError, Title: "t", Timestamp: time.Now()})
	if err != nil {
		t.Errorf("Send error: %v", err)
	}
	if received.Load() != 3 {
		t.Errorf("expected 3 requests for 3 phones, got %d", received.Load())
	}
}
