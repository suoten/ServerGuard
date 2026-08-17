package notifier

import (
	"context"
	"strings"
	"sync"

	"github.com/suoten/serverguard/internal/types"
)

type AlertRouter struct {
	mu       sync.RWMutex
	rules    map[types.AlertLevel][]string
	channels map[string]Channel
}

func NewAlertRouter() *AlertRouter {
	r := &AlertRouter{
		rules:    make(map[types.AlertLevel][]string),
		channels: make(map[string]Channel),
	}
	r.setDefaultRules()
	return r
}

func (r *AlertRouter) setDefaultRules() {
	r.rules[types.AlertFatal] = []string{"email", "sms", "phone", "webhook", "wechat", "dingtalk", "feishu", "slack", "telegram"}
	r.rules[types.AlertCritical] = []string{"email", "sms", "webhook", "wechat", "dingtalk", "feishu", "slack", "telegram"}
	r.rules[types.AlertError] = []string{"email", "wechat", "dingtalk", "feishu", "slack"}
	r.rules[types.AlertWarning] = []string{"email", "wechat", "dingtalk"}
	r.rules[types.AlertInfo] = []string{"panel"}
}

func (r *AlertRouter) RegisterChannel(name string, ch Channel) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.channels[name] = ch
}

func (r *AlertRouter) SetRoute(level types.AlertLevel, channels []string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.rules[level] = channels
}

func (r *AlertRouter) Route(ctx context.Context, alert types.Alert) []error {
	r.mu.RLock()
	channelNames := r.rules[alert.Level]
	channels := make([]Channel, 0, len(channelNames))
	for _, name := range channelNames {
		if ch, ok := r.channels[name]; ok && ch.Enabled() {
			channels = append(channels, ch)
		}
	}
	r.mu.RUnlock()

	var errs []error
	for _, ch := range channels {
		if err := ch.Send(ctx, alert); err != nil {
			errs = append(errs, err)
		}
	}
	return errs
}

func (r *AlertRouter) GetRoutes() map[types.AlertLevel][]string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	result := make(map[types.AlertLevel][]string)
	for k, v := range r.rules {
		result[k] = v
	}
	return result
}

func (r *AlertRouter) ShouldRoute(level types.AlertLevel, silence *SilenceConfig) bool {
	if silence == nil || !silence.Enabled {
		return true
	}
	for _, period := range silence.Periods {
		for _, l := range period.Levels {
			if strings.EqualFold(string(level), l) {
				return false
			}
		}
	}
	return true
}
