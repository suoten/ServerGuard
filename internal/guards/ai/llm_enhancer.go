package ai

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/suoten/serverguard/internal/types"
)

// ────────────────────────────────────────────────
// V4.0 — LLM 增强层（可选开关，默认关闭）
// 设计原则：本地规则做检测，LLM 只做"解释和报告生成"
// 目标用户场景（国内服务器、低内存）不适合依赖外部 API
// ────────────────────────────────────────────────

// LLMConfig LLM 增强层配置
type LLMConfig struct {
	Enabled    bool   `json:"enabled" yaml:"enabled"`
	Provider   string `json:"provider" yaml:"provider"`      // "openai" / "azure" / "custom"
	APIKey     string `json:"-" yaml:"api_key"`              // 不序列化到 JSON
	BaseURL    string `json:"base_url" yaml:"base_url"`      // 自定义 API 地址（兼容 OpenAI 格式）
	Model      string `json:"model" yaml:"model"`            // 模型名（如 gpt-4o-mini, qwen-plus）
	MaxTokens  int    `json:"max_tokens" yaml:"max_tokens"`  // 最大输出 token
	TimeoutSec int    `json:"timeout_sec" yaml:"timeout_sec"` // 请求超时
}

// DefaultLLMConfig 返回默认配置（关闭状态）
func DefaultLLMConfig() LLMConfig {
	return LLMConfig{
		Enabled:    false,
		Provider:   "openai",
		Model:      "gpt-4o-mini",
		MaxTokens:  2000,
		TimeoutSec: 30,
	}
}

// LLMEnhancer LLM 增强器
// 职责：
//  1. 周报复盘报告生成（把一周的告警/事件/知识库条目整理成人话）
//  2. 告警人话化升级（把"CPU 98% → 3σ 偏离"翻译成"服务器CPU满载，可能是XX程序占用过高"）
//  3. 故障解释（根因链 → 自然语言解释）
type LLMEnhancer struct {
	mu     sync.RWMutex
	config LLMConfig
	client *http.Client
}

// NewLLMEnhancer 创建 LLM 增强器
func NewLLMEnhancer(cfg LLMConfig) *LLMEnhancer {
	timeout := time.Duration(cfg.TimeoutSec) * time.Second
	if timeout <= 0 {
		timeout = 30 * time.Second
	}
	return &LLMEnhancer{
		config: cfg,
		client: &http.Client{Timeout: timeout},
	}
}

// IsEnabled 返回 LLM 是否启用
func (l *LLMEnhancer) IsEnabled() bool {
	l.mu.RLock()
	defer l.mu.RUnlock()
	return l.config.Enabled && l.config.APIKey != ""
}

// UpdateConfig 更新配置
func (l *LLMEnhancer) UpdateConfig(cfg LLMConfig) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.config = cfg
	timeout := time.Duration(cfg.TimeoutSec) * time.Second
	if timeout <= 0 {
		timeout = 30 * time.Second
	}
	l.client = &http.Client{Timeout: timeout}
}

// HumanizeAlert 告警人话化
// 输入原始告警，输出更易理解的描述
func (l *LLMEnhancer) HumanizeAlert(alert types.Alert) string {
	if !l.IsEnabled() {
		// 未启用 LLM 时返回原始消息
		return alert.Message
	}

	prompt := fmt.Sprintf(`你是服务器运维助手。把以下告警翻译成运维人员能立即理解的人话（1-2句话），包含：1）发生了什么 2）可能的影响 3）建议的排查方向。

告警标题：%s
告警内容：%s
来源模块：%s
告警级别：%s

请用中文回复，简洁直接，不要说"根据告警内容"之类的废话。`,
		alert.Title, alert.Message, alert.Source, alert.Level)

	resp, err := l.callLLM(prompt)
	if err != nil || resp == "" {
		return alert.Message // 降级为原始消息
	}
	return resp
}

// GenerateWeeklyReport 生成周报复盘
// 输入一周的告警统计、故障事件、知识库条目
func (l *LLMEnhancer) GenerateWeeklyReport(stats WeeklyReportData) string {
	if !l.IsEnabled() {
		return l.generateDefaultWeeklyReport(stats)
	}

	// 构建周报输入
	var incidentsText strings.Builder
	for _, inc := range stats.Incidents {
		incidentsText.WriteString(fmt.Sprintf("- %s（%s）：关联 %d 条告警\n  摘要：%s\n",
			inc.RootTitle, inc.RootTime.Format("01-02 15:04"), len(inc.MemberAlerts), inc.Summary))
	}

	var recurringText strings.Builder
	for _, r := range stats.RecurringIssues {
		recurringText.WriteString(fmt.Sprintf("- %s（出现 %d 次，上次处置：%s）\n",
			r.Symptom, r.OccurrenceCount, r.Action))
	}

	prompt := fmt.Sprintf(`你是服务器运维助手。根据以下一周数据生成一份简洁的周报，包含：
1. 本周概况（告警数、故障事件数、解决率）
2. 重点关注事件（按影响排序，附根因分析）
3. 反复出现的问题（需彻底解决的）
4. 建议的优化方向

数据：
- 告警总数：%d，其中 P0:%d P1:%d P2:%d P3:%d
- 已解决：%d，未解决：%d
- 故障事件：%d 个
- 反复故障：%d 个

故障事件详情：
%s
反复故障列表：
%s

请用中文回复，格式清晰，重点突出。`,
		stats.TotalAlerts, stats.P0Count, stats.P1Count, stats.P2Count, stats.P3Count,
		stats.ResolvedAlerts, stats.UnresolvedAlerts,
		len(stats.Incidents), len(stats.RecurringIssues),
		incidentsText.String(), recurringText.String())

	resp, err := l.callLLM(prompt)
	if err != nil || resp == "" {
		return l.generateDefaultWeeklyReport(stats)
	}
	return resp
}

// ExplainIncident 故障事件解释
// 把因果链翻译成自然语言
func (l *LLMEnhancer) ExplainIncident(inc types.Incident) string {
	if !l.IsEnabled() {
		return inc.Summary
	}

	var chainText strings.Builder
	for _, link := range inc.Chain {
		chainText.WriteString(fmt.Sprintf("  %s → %s（依据：%s）\n", link.From, link.To, link.Via))
	}

	prompt := fmt.Sprintf(`你是服务器运维助手。用 2-3 句话解释以下故障事件的因果关系，让运维人员快速理解发生了什么。

根因：%s（发生时间：%s）
因果链：
%s
已执行动作：%v

请用中文回复，简洁直接。`,
		inc.RootTitle, inc.RootTime.Format("15:04:05"),
		chainText.String(), inc.Actions)

	resp, err := l.callLLM(prompt)
	if err != nil || resp == "" {
		return inc.Summary
	}
	return resp
}

// WeeklyReportData 周报输入数据
type WeeklyReportData struct {
	TotalAlerts      int
	P0Count          int
	P1Count          int
	P2Count          int
	P3Count          int
	ResolvedAlerts   int
	UnresolvedAlerts int
	Incidents        []types.Incident
	RecurringIssues  []RecurringIssue
}

// RecurringIssue 反复故障（简化版，避免直接依赖 knowledge 包）
type RecurringIssue struct {
	Symptom         string `json:"symptom"`
	OccurrenceCount int    `json:"occurrence_count"`
	Action          string `json:"action"`
	LastSeen        time.Time `json:"last_seen"`
}

// callLLM 调用 LLM API（兼容 OpenAI 格式）
func (l *LLMEnhancer) callLLM(prompt string) (string, error) {
	l.mu.RLock()
	cfg := l.config
	client := l.client
	l.mu.RUnlock()

	baseURL := cfg.BaseURL
	if baseURL == "" {
		switch cfg.Provider {
		case "openai":
			baseURL = "https://api.openai.com/v1"
		case "azure":
			baseURL = "https://api.openai.azure.com"
		default:
			baseURL = "https://api.openai.com/v1"
		}
	}

	reqBody := map[string]interface{}{
		"model":       cfg.Model,
		"messages":    []map[string]string{{"role": "user", "content": prompt}},
		"max_tokens":  cfg.MaxTokens,
		"temperature": 0.3,
	}

	bodyBytes, err := json.Marshal(reqBody)
	if err != nil {
		return "", err
	}

	req, err := http.NewRequest("POST", baseURL+"/chat/completions", strings.NewReader(string(bodyBytes)))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+cfg.APIKey)

	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("LLM API 返回 %d", resp.StatusCode)
	}

	var result struct {
		Choices []struct {
			Message struct {
				Content string `json:"content"`
			} `json:"message"`
		} `json:"choices"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", err
	}
	if len(result.Choices) == 0 {
		return "", fmt.Errorf("LLM 返回空结果")
	}
	return strings.TrimSpace(result.Choices[0].Message.Content), nil
}

// generateDefaultWeeklyReport 未启用 LLM 时的默认周报
func (l *LLMEnhancer) generateDefaultWeeklyReport(stats WeeklyReportData) string {
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("## ServerGuard 周报（%s ~ %s）\n\n",
		time.Now().Add(-7*24*time.Hour).Format("01-02"), time.Now().Format("01-02")))

	sb.WriteString("### 本周概况\n")
	sb.WriteString(fmt.Sprintf("- 告警总数：%d（P0:%d P1:%d P2:%d P3:%d）\n",
		stats.TotalAlerts, stats.P0Count, stats.P1Count, stats.P2Count, stats.P3Count))
	sb.WriteString(fmt.Sprintf("- 已解决：%d，未解决：%d\n", stats.ResolvedAlerts, stats.UnresolvedAlerts))
	sb.WriteString(fmt.Sprintf("- 故障事件：%d 个，反复故障：%d 个\n\n", len(stats.Incidents), len(stats.RecurringIssues)))

	if len(stats.Incidents) > 0 {
		sb.WriteString("### 重点关注事件\n")
		for i, inc := range stats.Incidents {
			if i >= 10 {
				break
			}
			sb.WriteString(fmt.Sprintf("%d. **%s**（%s）\n   %s\n\n",
				i+1, inc.RootTitle, inc.RootTime.Format("01-02 15:04"), inc.Summary))
		}
	}

	if len(stats.RecurringIssues) > 0 {
		sb.WriteString("### 反复出现的问题\n")
		for i, r := range stats.RecurringIssues {
			if i >= 5 {
				break
			}
			sb.WriteString(fmt.Sprintf("%d. %s（出现 %d 次，上次处置：%s）\n",
				i+1, r.Symptom, r.OccurrenceCount, r.Action))
		}
	}

	return sb.String()
}

// GetEnvLLMConfig 从环境变量读取 LLM 配置
func GetEnvLLMConfig() LLMConfig {
	cfg := DefaultLLMConfig()
	if key := os.Getenv("SG_LLM_API_KEY"); key != "" {
		cfg.APIKey = key
		cfg.Enabled = true
	}
	if model := os.Getenv("SG_LLM_MODEL"); model != "" {
		cfg.Model = model
	}
	if url := os.Getenv("SG_LLM_BASE_URL"); url != "" {
		cfg.BaseURL = url
	}
	if provider := os.Getenv("SG_LLM_PROVIDER"); provider != "" {
		cfg.Provider = provider
	}
	return cfg
}
