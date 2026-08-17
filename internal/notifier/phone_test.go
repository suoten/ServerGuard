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

// --- PhoneChannel tests ---

func TestPhoneChannel_Constructor(t *testing.T) {
	c := NewPhoneChannel("phone", "aliyun", "key", "secret", []string{"13800000000"})
	if c.Name() != "phone" || !c.Enabled() {
		t.Error("constructor fields wrong")
	}
}

func TestPhoneChannel_NoPhones(t *testing.T) {
	c := NewPhoneChannel("phone", "aliyun", "k", "s", nil)
	err := c.Send(context.Background(), types.Alert{Level: types.AlertCritical, Title: "t", Timestamp: time.Now()})
	if err == nil {
		t.Error("expected error when no phones configured")
	}
}

func TestPhoneChannel_SetEnabled(t *testing.T) {
	c := NewPhoneChannel("phone", "aliyun", "k", "s", []string{"1"})
	c.SetEnabled(false)
	if c.Enabled() {
		t.Error("should be disabled")
	}
}

func TestPhoneChannel_SetMinLevel(t *testing.T) {
	c := NewPhoneChannel("phone", "aliyun", "k", "s", []string{"1"})
	c.SetMinLevel(types.AlertFatal)

	var received atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		received.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	c.endpoint = srv.URL

	// Critical below Fatal threshold -> should not call
	err := c.Send(context.Background(), types.Alert{Level: types.AlertCritical, Title: "t", Timestamp: time.Now()})
	if err != nil {
		t.Errorf("Send error: %v", err)
	}
	if received.Load() != 0 {
		t.Error("should not call when level below minLevel")
	}
}

func TestPhoneChannel_RateLimit(t *testing.T) {
	c := NewPhoneChannel("phone", "custom", "k", "s", []string{"13800000000"})
	c.SetRateLimit(1 * time.Hour)

	var received atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		received.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	c.endpoint = srv.URL

	// First call should succeed
	err := c.Send(context.Background(), types.Alert{Level: types.AlertCritical, Title: "t", Timestamp: time.Now()})
	if err != nil {
		t.Errorf("first Send error: %v", err)
	}
	if received.Load() != 1 {
		t.Errorf("expected 1 call, got %d", received.Load())
	}

	// Second call within rate limit should fail
	err = c.Send(context.Background(), types.Alert{Level: types.AlertCritical, Title: "t", Timestamp: time.Now()})
	if err == nil {
		t.Error("expected rate limit error on second call")
	}
}

func TestPhoneChannel_CustomProvider(t *testing.T) {
	var received atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		received.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	c := NewPhoneChannel("phone", "custom", "k", "s", []string{"13800000000"})
	c.endpoint = srv.URL
	c.SetRateLimit(0) // disable rate limit for test

	err := c.Send(context.Background(), types.Alert{Level: types.AlertCritical, Title: "crit", Message: "msg", Timestamp: time.Now()})
	if err != nil {
		t.Errorf("custom provider Send error: %v", err)
	}
	if received.Load() != 1 {
		t.Error("custom endpoint should receive call")
	}
}

func TestPhoneChannel_CustomProviderNoEndpoint(t *testing.T) {
	c := NewPhoneChannel("phone", "custom", "k", "s", []string{"13800000000"})
	c.SetRateLimit(0)
	err := c.Send(context.Background(), types.Alert{Level: types.AlertCritical, Title: "t", Timestamp: time.Now()})
	if err == nil {
		t.Error("expected error when custom endpoint not configured")
	}
}

func TestPhoneChannel_AliyunProvider(t *testing.T) {
	var received atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		received.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	c := NewPhoneChannel("phone", "aliyun", "k", "s", []string{"13800000000"})
	c.endpoint = srv.URL
	c.SetRateLimit(0)

	err := c.Send(context.Background(), types.Alert{Level: types.AlertCritical, Title: "t", Timestamp: time.Now()})
	if err != nil {
		t.Errorf("aliyun Send error: %v", err)
	}
	if received.Load() != 1 {
		t.Error("aliyun endpoint should receive call")
	}
}

func TestPhoneChannel_TencentProvider(t *testing.T) {
	var received atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		received.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	c := NewPhoneChannel("phone", "tencent", "k", "s", []string{"13800000000"})
	c.endpoint = srv.URL
	c.SetRateLimit(0)

	err := c.Send(context.Background(), types.Alert{Level: types.AlertCritical, Title: "t", Timestamp: time.Now()})
	if err != nil {
		t.Errorf("tencent Send error: %v", err)
	}
	if received.Load() != 1 {
		t.Error("tencent endpoint should receive call")
	}
}

func TestPhoneChannel_UnsupportedProvider(t *testing.T) {
	c := NewPhoneChannel("phone", "unknown", "k", "s", []string{"13800000000"})
	c.SetRateLimit(0)
	err := c.Send(context.Background(), types.Alert{Level: types.AlertCritical, Title: "t", Timestamp: time.Now()})
	if err == nil {
		t.Error("expected error for unsupported provider")
	}
}

func TestPhoneChannel_MultiplePhones(t *testing.T) {
	var received atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		received.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	c := NewPhoneChannel("phone", "custom", "k", "s", []string{"13800000000", "13900000000"})
	c.endpoint = srv.URL
	c.SetRateLimit(0)

	err := c.Send(context.Background(), types.Alert{Level: types.AlertCritical, Title: "t", Timestamp: time.Now()})
	if err != nil {
		t.Errorf("Send error: %v", err)
	}
	if received.Load() != 2 {
		t.Errorf("expected 2 calls for 2 phones, got %d", received.Load())
	}
}

// --- shouldCall / alertSeverityRank tests ---

func TestAlertSeverityRank(t *testing.T) {
	cases := []struct {
		level types.AlertLevel
		rank  int
	}{
		{types.AlertInfo, 1},
		{types.AlertWarning, 2},
		{types.AlertError, 3},
		{types.AlertCritical, 4},
		{types.AlertFatal, 5},
		{"unknown", 0},
	}
	for _, tc := range cases {
		if got := alertSeverityRank(tc.level); got != tc.rank {
			t.Errorf("alertSeverityRank(%s) = %d, want %d", tc.level, got, tc.rank)
		}
	}
}

func TestShouldCall(t *testing.T) {
	cases := []struct {
		alert    types.AlertLevel
		min      types.AlertLevel
		expected bool
	}{
		{types.AlertFatal, types.AlertCritical, true},
		{types.AlertCritical, types.AlertCritical, true},
		{types.AlertError, types.AlertCritical, false},
		{types.AlertInfo, types.AlertFatal, false},
		{types.AlertFatal, types.AlertInfo, true},
	}
	for _, tc := range cases {
		if got := shouldCall(tc.alert, tc.min); got != tc.expected {
			t.Errorf("shouldCall(%s, %s) = %v, want %v", tc.alert, tc.min, got, tc.expected)
		}
	}
}

func TestPhoneChannel_LongContent(t *testing.T) {
	var received atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		received.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	c := NewPhoneChannel("phone", "custom", "k", "s", []string{"13800000000"})
	c.endpoint = srv.URL
	c.SetRateLimit(0)

	longMsg := string(make([]byte, 300))
	err := c.Send(context.Background(), types.Alert{Level: types.AlertCritical, Title: "t", Message: longMsg, Timestamp: time.Now()})
	if err != nil {
		t.Errorf("Send error: %v", err)
	}
	if received.Load() != 1 {
		t.Error("should send with truncated content")
	}
}
