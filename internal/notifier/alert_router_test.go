package notifier

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/suoten/serverguard/internal/types"
)

// --- AlertRouter tests ---

func TestNewAlertRouter(t *testing.T) {
	r := NewAlertRouter()
	if r == nil {
		t.Fatal("NewAlertRouter returned nil")
	}
	routes := r.GetRoutes()
	if len(routes) == 0 {
		t.Error("expected default routes")
	}
	// Fatal should route to many channels
	if len(routes[types.AlertFatal]) == 0 {
		t.Error("fatal should have routes")
	}
}

func TestAlertRouter_DefaultRoutes(t *testing.T) {
	r := NewAlertRouter()
	routes := r.GetRoutes()

	cases := []struct {
		level       types.AlertLevel
		minChannels int
	}{
		{types.AlertFatal, 5},
		{types.AlertCritical, 5},
		{types.AlertError, 3},
		{types.AlertWarning, 2},
		{types.AlertInfo, 1},
	}
	for _, tc := range cases {
		if len(routes[tc.level]) < tc.minChannels {
			t.Errorf("level %s: expected >= %d channels, got %d", tc.level, tc.minChannels, len(routes[tc.level]))
		}
	}
}

func TestAlertRouter_SetRoute(t *testing.T) {
	r := NewAlertRouter()
	r.SetRoute(types.AlertWarning, []string{"email", "sms"})

	routes := r.GetRoutes()
	if got := routes[types.AlertWarning]; len(got) != 2 || got[0] != "email" || got[1] != "sms" {
		t.Errorf("expected [email sms], got %v", got)
	}
}

func TestAlertRouter_RegisterChannelAndRoute(t *testing.T) {
	r := NewAlertRouter()

	var sent atomic.Int32
	mockCh := &mockChannel{name: "email", enabled: true, sendFn: func(ctx context.Context, a types.Alert) error {
		sent.Add(1)
		return nil
	}}
	r.RegisterChannel("email", mockCh)
	r.SetRoute(types.AlertError, []string{"email"})

	errs := r.Route(context.Background(), types.Alert{Level: types.AlertError, Title: "t", Timestamp: time.Now()})
	if len(errs) != 0 {
		t.Errorf("expected no errors, got %v", errs)
	}
	if sent.Load() != 1 {
		t.Error("email channel should receive alert")
	}
}

func TestAlertRouter_RouteMultipleChannels(t *testing.T) {
	r := NewAlertRouter()

	var sent atomic.Int32
	makeMock := func(name string) *mockChannel {
		return &mockChannel{name: name, enabled: true, sendFn: func(ctx context.Context, a types.Alert) error {
			sent.Add(1)
			return nil
		}}
	}
	r.RegisterChannel("email", makeMock("email"))
	r.RegisterChannel("sms", makeMock("sms"))
	r.RegisterChannel("webhook", makeMock("webhook"))

	r.SetRoute(types.AlertCritical, []string{"email", "sms", "webhook"})
	errs := r.Route(context.Background(), types.Alert{Level: types.AlertCritical, Title: "t", Timestamp: time.Now()})
	if len(errs) != 0 {
		t.Errorf("expected no errors, got %v", errs)
	}
	if sent.Load() != 3 {
		t.Errorf("expected 3 sends, got %d", sent.Load())
	}
}

func TestAlertRouter_RouteCollectsErrors(t *testing.T) {
	r := NewAlertRouter()

	errCh := &mockChannel{name: "email", enabled: true, sendFn: func(ctx context.Context, a types.Alert) error {
		return errors.New("send failed")
	}}
	r.RegisterChannel("email", errCh)
	r.SetRoute(types.AlertError, []string{"email"})

	errs := r.Route(context.Background(), types.Alert{Level: types.AlertError, Title: "t", Timestamp: time.Now()})
	if len(errs) != 1 {
		t.Fatalf("expected 1 error, got %d", len(errs))
	}
	if errs[0].Error() != "send failed" {
		t.Errorf("unexpected error: %v", errs[0])
	}
}

func TestAlertRouter_RouteSkipsDisabledChannels(t *testing.T) {
	r := NewAlertRouter()

	var sent atomic.Int32
	mockCh := &mockChannel{name: "email", enabled: false, sendFn: func(ctx context.Context, a types.Alert) error {
		sent.Add(1)
		return nil
	}}
	r.RegisterChannel("email", mockCh)
	r.SetRoute(types.AlertError, []string{"email"})

	r.Route(context.Background(), types.Alert{Level: types.AlertError, Title: "t", Timestamp: time.Now()})
	if sent.Load() != 0 {
		t.Error("disabled channel should not be called")
	}
}

func TestAlertRouter_RouteUnregisteredChannel(t *testing.T) {
	r := NewAlertRouter()
	r.SetRoute(types.AlertError, []string{"nonexistent"})
	errs := r.Route(context.Background(), types.Alert{Level: types.AlertError, Title: "t", Timestamp: time.Now()})
	if len(errs) != 0 {
		t.Error("unregistered channel should be skipped without error")
	}
}

func TestAlertRouter_ShouldRoute(t *testing.T) {
	r := NewAlertRouter()

	if !r.ShouldRoute(types.AlertError, nil) {
		t.Error("nil silence should allow routing")
	}

	disabled := &SilenceConfig{Enabled: false}
	if !r.ShouldRoute(types.AlertError, disabled) {
		t.Error("disabled silence should allow routing")
	}

	enabled := &SilenceConfig{
		Enabled: true,
		Periods: []SilencePeriod{{Levels: []string{"warning"}}},
	}
	if r.ShouldRoute(types.AlertWarning, enabled) {
		t.Error("warning should not route when silenced")
	}
	if !r.ShouldRoute(types.AlertError, enabled) {
		t.Error("error should still route (not in silence levels)")
	}
}

func TestAlertRouter_GetRoutesReturnsCopy(t *testing.T) {
	r := NewAlertRouter()
	routes := r.GetRoutes()
	routes[types.AlertFatal] = []string{"modified"}

	routes2 := r.GetRoutes()
	if containsStr(routes2[types.AlertFatal], "modified") {
		t.Error("GetRoutes should return a copy, not the internal map")
	}
}

func containsStr(slice []string, s string) bool {
	for _, v := range slice {
		if v == s {
			return true
		}
	}
	return false
}
