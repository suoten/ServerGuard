package notifier

import (
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/suoten/serverguard/internal/types"
)

// ────────────────────────────────────────────────
// V4.0 — 通知双向交互
// 微信/钉钉告警里带编号，回复"1"确认、"2"暂停自动修复
// 人在手机上就能完成闭环
// ────────────────────────────────────────────────

// AlertReply 告警回复
type AlertReply struct {
	AlertID  string    `json:"alert_id"`
	Action   string    `json:"action"`    // "confirm" / "pause" / "resume" / "escalate"
	UserID   string    `json:"user_id"`   // 回复者标识
	UserName string    `json:"user_name"` // 回复者名称
	Time     time.Time `json:"time"`
	Message  string    `json:"message"`   // 原始回复内容
}

// ReplyHandler 回复处理器
type ReplyHandler func(reply AlertReply) error

// BidirectionalNotifier 双向通知管理器
type BidirectionalNotifier struct {
	mu          sync.RWMutex
	pendingAlerts map[string]*PendingAlert // alertShortID -> alert
	handlers    map[string]ReplyHandler    // action -> handler
	maxPending  int
}

// PendingAlert 待回复的告警
type PendingAlert struct {
	AlertID    string    `json:"alert_id"`
	ShortID    string    `json:"short_id"` // 6位短编号，用于回复
	Alert      types.Alert `json:"alert"`
	SentAt     time.Time `json:"sent_at"`
	Acked      bool      `json:"acked"`
	Paused     bool      `json:"paused"`
	ReplyCount int       `json:"reply_count"`
}

// NewBidirectionalNotifier 创建双向通知管理器
func NewBidirectionalNotifier() *BidirectionalNotifier {
	return &BidirectionalNotifier{
		pendingAlerts: make(map[string]*PendingAlert),
		handlers:      make(map[string]ReplyHandler),
		maxPending:    100,
	}
}

// RegisterHandler 注册回复处理函数
func (b *BidirectionalNotifier) RegisterHandler(action string, handler ReplyHandler) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.handlers[action] = handler
}

// TrackAlert 跟踪一个已发送的告警，等待用户回复
func (b *BidirectionalNotifier) TrackAlert(alert types.Alert) string {
	shortID := generateShortID(alert.ID)

	b.mu.Lock()
	defer b.mu.Unlock()

	// 清理过多的待处理告警
	if len(b.pendingAlerts) >= b.maxPending {
		b.cleanupOldPending()
	}

	b.pendingAlerts[shortID] = &PendingAlert{
		AlertID: alert.ID,
		ShortID: shortID,
		Alert:   alert,
		SentAt:  time.Now(),
	}

	return shortID
}

// FormatAlertWithActionCode 格式化告警消息，附带回复编号
func (b *BidirectionalNotifier) FormatAlertWithActionCode(alert types.Alert) (string, string) {
	shortID := b.TrackAlert(alert)

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("【%s】%s\n", alert.Level, alert.Title))
	sb.WriteString(fmt.Sprintf("%s\n", alert.Message))
	sb.WriteString(fmt.Sprintf("来源：%s\n", alert.Source))
	sb.WriteString(fmt.Sprintf("时间：%s\n", alert.Timestamp.Format("15:04:05")))
	sb.WriteString(fmt.Sprintf("编号：%s\n", shortID))
	sb.WriteString("\n回复操作：\n")
	sb.WriteString(fmt.Sprintf("  回复 \"%s1\" - 确认告警\n", shortID))
	sb.WriteString(fmt.Sprintf("  回复 \"%s2\" - 暂停自动修复\n", shortID))
	sb.WriteString(fmt.Sprintf("  回复 \"%s3\" - 恢复自动修复\n", shortID))

	return shortID, sb.String()
}

// ProcessReply 处理用户回复
// replyText: 用户回复的完整文本（如 "ABC1231" 表示确认编号 ABC123 的告警）
func (b *BidirectionalNotifier) ProcessReply(replyText, userID, userName string) (*AlertReply, error) {
	replyText = strings.TrimSpace(replyText)
	if len(replyText) < 2 {
		return nil, fmt.Errorf("回复内容过短")
	}

	// 解析回复：最后一位是操作码，前面是告警编号
	actionCode := replyText[len(replyText)-1:]
	shortID := replyText[:len(replyText)-1]

	var action string
	switch actionCode {
	case "1":
		action = "confirm"
	case "2":
		action = "pause"
	case "3":
		action = "resume"
	default:
		return nil, fmt.Errorf("未知的操作码：%s（支持：1=确认 2=暂停 3=恢复）", actionCode)
	}

	b.mu.Lock()
	defer b.mu.Unlock()

	pending, exists := b.pendingAlerts[shortID]
	if !exists {
		return nil, fmt.Errorf("未找到编号为 %s 的告警（可能已过期）", shortID)
	}

	reply := AlertReply{
		AlertID:  pending.AlertID,
		Action:   action,
		UserID:   userID,
		UserName: userName,
		Time:     time.Now(),
		Message:  replyText,
	}

	// 更新待处理状态
	switch action {
	case "confirm":
		pending.Acked = true
	case "pause":
		pending.Paused = true
	case "resume":
		pending.Paused = false
	}
	pending.ReplyCount++

	// 调用注册的处理器
	if handler, exists := b.handlers[action]; exists {
		go func() {
			defer func() {
				if r := recover(); r != nil {
					fmt.Printf("[BidirectionalNotifier] handler panicked: %v\n", r)
				}
			}()
			if err := handler(reply); err != nil {
				fmt.Printf("[BidirectionalNotifier] 处理回复失败: %v\n", err)
			}
		}()
	}

	return &reply, nil
}

// GetPendingAlerts 获取所有待处理告警
func (b *BidirectionalNotifier) GetPendingAlerts() []PendingAlert {
	b.mu.RLock()
	defer b.mu.RUnlock()

	var result []PendingAlert
	for _, p := range b.pendingAlerts {
		result = append(result, *p)
	}
	return result
}

// IsPaused 检查某个告警关联的自动修复是否被暂停
func (b *BidirectionalNotifier) IsPaused(alertID string) bool {
	b.mu.RLock()
	defer b.mu.RUnlock()
	for _, p := range b.pendingAlerts {
		if p.AlertID == alertID {
			return p.Paused
		}
	}
	return false
}

// cleanupOldPending 清理过期的待处理告警（超过 24 小时）
func (b *BidirectionalNotifier) cleanupOldPending() {
	cutoff := time.Now().Add(-24 * time.Hour)
	for id, p := range b.pendingAlerts {
		if p.SentAt.Before(cutoff) {
			delete(b.pendingAlerts, id)
		}
	}
}

// generateShortID 从完整告警 ID 生成 6 位短编号
func generateShortID(fullID string) string {
	if len(fullID) < 6 {
		// 不够 6 位则用时间戳补
		return fmt.Sprintf("%06d", time.Now().UnixNano()%1000000)
	}
	// 取 ID 的后 6 位，转大写
	suffix := fullID[len(fullID)-6:]
	return strings.ToUpper(suffix)
}

// FormatReplyConfirmation 格式化回复确认消息
func FormatReplyConfirmation(reply AlertReply) string {
	var actionText string
	switch reply.Action {
	case "confirm":
		actionText = "已确认告警"
	case "pause":
		actionText = "已暂停自动修复"
	case "resume":
		actionText = "已恢复自动修复"
	default:
		actionText = "未知操作"
	}

	return fmt.Sprintf("✅ 操作成功\n告警编号：%s\n操作：%s\n操作人：%s\n时间：%s",
		reply.AlertID, actionText, reply.UserName, reply.Time.Format("15:04:05"))
}

// AckByShortCode 通过短编号确认告警
func (b *BidirectionalNotifier) AckByShortCode(shortCode string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	for _, p := range b.pendingAlerts {
		if p.ShortID == shortCode {
			p.Acked = true
			return
		}
	}
}
