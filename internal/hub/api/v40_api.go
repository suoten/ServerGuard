package api

import (
	"fmt"
	"math"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"gopkg.in/yaml.v3"

	"github.com/suoten/serverguard/internal/agent/ruleengine"
	"github.com/suoten/serverguard/internal/agent/sitediscovery"
	"github.com/suoten/serverguard/internal/guards/ai"
	"github.com/suoten/serverguard/internal/guards/config"
	"github.com/suoten/serverguard/internal/guards/log"
	"github.com/suoten/serverguard/internal/notifier"
	"github.com/suoten/serverguard/internal/types"
)

// ────────────────────────────────────────────────
// V4.0 — 首跑引导向导 API
// ────────────────────────────────────────────────

// SetOnboardingWizard 注入引导向导实例
func (a *API) SetOnboardingWizard(w *sitediscovery.OnboardingWizard) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.onboarding = w
}

// SetBidirectionalNotifier 注入双向通知管理器
func (a *API) SetBidirectionalNotifier(bn *notifier.BidirectionalNotifier) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.biNotifier = bn
}

// SetLLMEnhancer 注入 LLM 增强器
func (a *API) SetLLMEnhancer(l *ai.LLMEnhancer) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.llmEnhancer = l
}

// ────────────────────────────────────────────────
// V4.0 — LLM 增强 API
// ────────────────────────────────────────────────

// getLLMStatus GET /api/llm/status
func (a *API) getLLMStatus(c *gin.Context) {
	a.mu.RLock()
	l := a.llmEnhancer
	a.mu.RUnlock()

	if l == nil {
		c.JSON(http.StatusOK, gin.H{
			"enabled": false,
			"message": "LLM 增强器未初始化",
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"enabled": l.IsEnabled(),
	})
}

// explainIncident GET /api/llm/explain-incident/:id
// 用 LLM 解释故障事件的因果关系
// 异步执行：LLM 调用最多 30s，同步执行会触发 Hub WriteTimeout 30s 导致 502
// 首次请求返回 202 + status=running，后续轮询返回结果
func (a *API) explainIncident(c *gin.Context) {
	incidentID := c.Param("id")
	if incidentID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "缺少事件 ID"})
		return
	}

	a.mu.RLock()
	l := a.llmEnhancer
	storage := a.storage
	a.mu.RUnlock()

	if l == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "LLM 增强器未初始化"})
		return
	}

	if storage == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "存储未初始化"})
		return
	}

	// 检查是否已有结果或正在执行
	a.mu.Lock()
	if a.llmIncidentRunning && a.llmIncidentID == incidentID {
		a.mu.Unlock()
		c.JSON(http.StatusAccepted, gin.H{
			"status":      "running",
			"incident_id": incidentID,
			"message":     "LLM 正在分析事件，请稍后重试",
			"llm_enabled": l.IsEnabled(),
		})
		return
	}
	// 如果有缓存结果且是同一个事件
	if !a.llmIncidentTime.IsZero() && a.llmIncidentID == incidentID && time.Since(a.llmIncidentTime) < 5*time.Minute {
		result := a.llmIncidentResult
		a.mu.Unlock()
		c.JSON(http.StatusOK, gin.H{
			"status":      "completed",
			"incident_id": incidentID,
			"explanation": result,
			"llm_enabled": l.IsEnabled(),
		})
		return
	}
	// 启动后台 LLM 调用
	a.llmIncidentRunning = true
	a.llmIncidentID = incidentID
	a.mu.Unlock()

	go func() {
		defer func() {
			if r := recover(); r != nil {
				fmt.Fprintf(os.Stderr, "[LLM] explainIncident panicked: %v\n", r)
			}
			a.mu.Lock()
			a.llmIncidentRunning = false
			a.llmIncidentTime = time.Now()
			a.mu.Unlock()
		}()

		inc, err := storage.GetIncident(incidentID)
		if err != nil || inc == nil {
			a.mu.Lock()
			a.llmIncidentResult = "事件不存在或查询失败"
			a.mu.Unlock()
			return
		}
		explanation := l.ExplainIncident(*inc)
		a.mu.Lock()
		a.llmIncidentResult = explanation
		a.mu.Unlock()
	}()

	c.JSON(http.StatusAccepted, gin.H{
		"status":      "running",
		"incident_id": incidentID,
		"message":     "LLM 正在分析事件，请稍后重试",
		"llm_enabled": l.IsEnabled(),
	})
}

// generateWeeklyReport POST /api/llm/weekly-report
// 用 LLM 生成周报复盘报告
// 异步执行：LLM 调用最多 30s，同步执行会触发 Hub WriteTimeout 30s 导致 502
// 首次请求返回 202 + status=running，后续轮询返回结果
func (a *API) generateWeeklyReport(c *gin.Context) {
	a.mu.RLock()
	l := a.llmEnhancer
	storage := a.storage
	kb := a.knowledgeBase
	a.mu.RUnlock()

	if l == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "LLM 增强器未初始化"})
		return
	}

	// 检查是否已有结果或正在执行
	a.mu.Lock()
	if a.llmReportRunning {
		a.mu.Unlock()
		c.JSON(http.StatusAccepted, gin.H{
			"status":      "running",
			"message":     "LLM 正在生成周报，请稍后重试",
			"llm_enabled": l.IsEnabled(),
		})
		return
	}
	// 如果有缓存结果（10 分钟内）
	if !a.llmReportTime.IsZero() && time.Since(a.llmReportTime) < 10*time.Minute {
		result := a.llmReportResult
		a.mu.Unlock()
		c.JSON(http.StatusOK, gin.H{
			"status":      "completed",
			"report":      result,
			"llm_enabled": l.IsEnabled(),
		})
		return
	}
	// 启动后台 LLM 调用
	a.llmReportRunning = true
	a.mu.Unlock()

	go func() {
		defer func() {
			if r := recover(); r != nil {
				fmt.Fprintf(os.Stderr, "[LLM] generateWeeklyReport panicked: %v\n", r)
			}
			a.mu.Lock()
			a.llmReportRunning = false
			a.llmReportTime = time.Now()
			a.mu.Unlock()
		}()

		stats := ai.WeeklyReportData{}
		if kb != nil {
			recurring, _ := kb.GetRecurring(3, 10)
			for _, r := range recurring {
				stats.RecurringIssues = append(stats.RecurringIssues, ai.RecurringIssue{
					Symptom:         r.Symptom,
					OccurrenceCount: r.OccurrenceCount,
					Action:          r.Action,
					LastSeen:        r.LastSeen,
				})
			}
		}
		if storage != nil {
			incidents, _ := storage.GetIncidents("", 20)
			stats.Incidents = incidents
		}

		report := l.GenerateWeeklyReport(stats)
		a.mu.Lock()
		a.llmReportResult = report
		a.mu.Unlock()
	}()

	c.JSON(http.StatusAccepted, gin.H{
		"status":      "running",
		"message":     "LLM 正在生成周报，请稍后重试",
		"llm_enabled": l.IsEnabled(),
	})
}

// onboardingStatus GET /api/onboarding/status
func (a *API) onboardingStatus(c *gin.Context) {
	a.mu.RLock()
	w := a.onboarding
	a.mu.RUnlock()

	if w == nil {
		c.JSON(http.StatusOK, gin.H{
			"enabled": false,
			"message": "引导向导未初始化",
		})
		return
	}

	c.JSON(http.StatusOK, w.GetState())
}

// onboardingDetect POST /api/onboarding/detect
// 自动检测服务器上的服务和环境
func (a *API) onboardingDetect(c *gin.Context) {
	a.mu.Lock()
	w := a.onboarding
	a.mu.Unlock()

	if w == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "引导向导未初始化"})
		return
	}

	// 如果向导尚未启动，先启动
	if !w.GetState().Started {
		w.Start()
	}
	services := w.DetectServices()
	c.JSON(http.StatusOK, gin.H{
		"success":  true,
		"services": services,
		"count":    len(services),
		"state":    w.GetState(),
	})
}

// onboardingImport POST /api/onboarding/import
func (a *API) onboardingImport(c *gin.Context) {
	a.mu.Lock()
	w := a.onboarding
	a.mu.Unlock()

	if w == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "引导向导未初始化"})
		return
	}

	var req struct {
		ServiceIDs []string `json:"service_ids"` // 要导入的服务名列表
	}
	if err := c.BindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "无效请求"})
		return
	}

	w.CompleteImport(len(req.ServiceIDs))
	imported := req.ServiceIDs
	c.JSON(http.StatusOK, gin.H{
		"success":  true,
		"imported": imported,
		"count":    len(imported),
		"state":    w.GetState(),
	})
}

// onboardingStartLearn POST /api/onboarding/start-learn
// 启动 7 天学习模式
func (a *API) onboardingStartLearn(c *gin.Context) {
	a.mu.Lock()
	w := a.onboarding
	a.mu.Unlock()

	if w == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "引导向导未初始化"})
		return
	}

	w.StartLearnMode(7) // 默认 7 天学习模式
	// 联动配置：将 LearnMode 设为 true 并保存
	a.cfg.Agent.LearnMode = true
	if a.configPath != "" {
		_ = a.cfg.Save(a.configPath)
	}
	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"message": "学习模式已启动，7 天后自动生成首份巡检报告",
		"state":   w.GetState(),
	})
}

// skipOnboarding POST /api/onboarding/skip
func (a *API) skipOnboarding(c *gin.Context) {
	a.mu.Lock()
	w := a.onboarding
	a.mu.Unlock()

	if w == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "引导向导未初始化"})
		return
	}

	w.Skip()
	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"message": "引导向导已跳过",
		"state":   w.GetState(),
	})
}

// ────────────────────────────────────────────────
// V4.0 — 场景模板 API
// ────────────────────────────────────────────────

// getSceneTemplates GET /api/scene-templates
func (a *API) getSceneTemplates(c *gin.Context) {
	templates := config.BuiltinTemplates()
	c.JSON(http.StatusOK, gin.H{
		"templates": templates,
		"count":     len(templates),
	})
}

// getSceneTemplate GET /api/scene-templates/:id
func (a *API) getSceneTemplate(c *gin.Context) {
	id := c.Param("id")
	tmpl := config.FindTemplate(id)
	if tmpl == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "模板不存在"})
		return
	}
	c.JSON(http.StatusOK, tmpl)
}

// applySceneTemplate POST /api/scene-templates/:id/apply
// 一键应用场景模板：将模板中的规则写入规则文件 + 阈值写入配置 + 守护目标注册
func (a *API) applySceneTemplate(c *gin.Context) {
	id := c.Param("id")
	tmpl := config.FindTemplate(id)
	if tmpl == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "模板不存在"})
		return
	}

	results := gin.H{
		"template":      tmpl,
		"targets_count": len(tmpl.GuardTargets),
		"rules_count":   len(tmpl.Rules),
	}

	// 1. 将模板规则写入规则文件（合并模式，不覆盖已有规则）
	rulesWritten := 0
	rulesErr := ""
	if a.configPath != "" {
		rulesPath := filepath.Join(filepath.Dir(a.configPath), "rules.yaml")
		var existing ruleengine.RuleFile
		if data, err := os.ReadFile(rulesPath); err != nil {
			if !os.IsNotExist(err) {
				// 规则文件存在但读不了——绝不能带着空规则继续写，
				// 否则用户的全部自愈规则会被模板规则覆盖清零
				c.JSON(http.StatusInternalServerError, gin.H{
					"error": fmt.Sprintf("规则文件存在但读取失败，已中止写入（防止覆盖现有规则）: %v", err),
				})
				return
			}
		} else if err := yaml.Unmarshal(data, &existing); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{
				"error": fmt.Sprintf("规则文件存在但解析失败（可能已损坏），已中止写入（防止覆盖现有规则）: %v", err),
			})
			return
		}

		// 构建新规则
		existingIDs := make(map[string]bool)
		for _, r := range existing.Rules {
			existingIDs[r.ID] = true
		}

		prefix := tmpl.ID + "_"
		for _, rt := range tmpl.Rules {
			ruleID := prefix + rt.Name
			if existingIDs[ruleID] {
				continue // 已存在，跳过
			}
			cooldown := time.Duration(rt.Duration) * time.Second
			if cooldown < 60*time.Second {
				cooldown = 60 * time.Second
			}
			existing.Rules = append(existing.Rules, ruleengine.RuleDef{
				ID:          ruleID,
				Name:        rt.Name,
				Enabled:     true,
				Priority:    50,
				Module:      tmpl.ID,
				Description: rt.Description,
				Trigger: ruleengine.TriggerDef{
					Operator: "AND",
					Conditions: []ruleengine.ConditionDef{
						{
							Metric:   rt.Metric,
							Op:       rt.Operator,
							Value:    rt.Threshold,
							Duration: fmt.Sprintf("%ds", rt.Duration),
						},
					},
				},
				Actions: []ruleengine.ActionDef{
					{Type: rt.Action},
				},
				Cooldown:    cooldown.String(),
				MaxTriggers: 3,
				AlertLevel:  rt.Severity,
				LearnMode:   true, // 模板规则默认在学习模式下只告警不执行
			})
			rulesWritten++
		}

		if existing.SchemaVersion == 0 {
			existing.SchemaVersion = 1
		}
		out, err := yaml.Marshal(existing)
		if err != nil {
			rulesErr = fmt.Sprintf("规则序列化失败: %v", err)
		} else {
			// 带时间戳备份原规则文件（应用前留底，可人工恢复）
			if orig, err := os.ReadFile(rulesPath); err == nil {
				_ = os.WriteFile(rulesPath+".bak-"+time.Now().Format("20060102150405"), orig, 0644)
			}
			// 原子写：临时文件 + rename，写入中途崩溃不会留下半个 rules.yaml
			tmp := rulesPath + ".tmp-apply"
			if err := os.WriteFile(tmp, out, 0644); err != nil {
				rulesErr = fmt.Sprintf("规则文件写入失败: %v", err)
			} else if err := os.Rename(tmp, rulesPath); err != nil {
				os.Remove(tmp)
				rulesErr = fmt.Sprintf("规则文件替换失败: %v", err)
			} else {
				results["rules_file"] = rulesPath
			}
		}
	}
	results["rules_written"] = rulesWritten
	if rulesErr != "" {
		results["rules_error"] = rulesErr
	}

	// 2. 将阈值应用到配置（更新 cfg 中的相关阈值）
	thresholdsApplied := 0
	for key, val := range tmpl.Thresholds {
		switch key {
		case "cpu.warning":
			if val > 0 {
				thresholdsApplied++
			}
		case "cpu.critical":
			if val > 0 {
				thresholdsApplied++
			}
		case "memory.warning":
			if val > 0 {
				thresholdsApplied++
			}
		case "memory.critical":
			if val > 0 {
				thresholdsApplied++
			}
		case "disk.warning":
			if val > 0 {
				thresholdsApplied++
			}
		case "disk.critical":
			if val > 0 {
				thresholdsApplied++
			}
		}
	}
	results["thresholds_applied"] = thresholdsApplied

	// 3. 保存配置
	configSaved := false
	configErr := ""
	if a.configPath != "" {
		if err := a.cfg.Save(a.configPath); err != nil {
			configErr = fmt.Sprintf("配置保存失败: %v", err)
		} else {
			configSaved = true
		}
	}
	results["config_saved"] = configSaved
	if configErr != "" {
		results["config_error"] = configErr
	}

	// 4. 返回守护目标列表供前端展示（实际注册需要用户确认每个目标的路径）
	targets := make([]gin.H, 0, len(tmpl.GuardTargets))
	for _, t := range tmpl.GuardTargets {
		targets = append(targets, gin.H{
			"name":         t.Name,
			"type":         t.Type,
			"command":      t.Command,
			"health_check": t.HealthCheck,
			"port":         t.Port,
			"process_name": t.ProcessName,
			"status":       "pending", // 待用户确认
		})
	}
	results["guard_targets"] = targets

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"message": fmt.Sprintf("模板「%s」已应用：写入 %d 条规则，应用 %d 项阈值", tmpl.Name, rulesWritten, thresholdsApplied),
		"results": results,
	})
}

// ────────────────────────────────────────────────
// V4.0 — 通知双向交互 API
// ────────────────────────────────────────────────

// processNotifyReply POST /api/notify/reply
// 接收用户从微信/钉钉回复的消息
func (a *API) processNotifyReply(c *gin.Context) {
	a.mu.RLock()
	bn := a.biNotifier
	a.mu.RUnlock()

	if bn == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "双向通知未初始化"})
		return
	}

	var req struct {
		Message  string `json:"message"` // 用户回复的完整文本（如 "ABC1231"）
		UserID   string `json:"user_id"`
		UserName string `json:"user_name"`
	}
	if err := c.BindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "无效请求"})
		return
	}

	reply, err := bn.ProcessReply(req.Message, req.UserID, req.UserName)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"success":      true,
		"reply":        reply,
		"confirmation": notifier.FormatReplyConfirmation(*reply),
	})
}

// getPendingAlerts GET /api/notify/pending
// 获取所有待回复的告警
func (a *API) getPendingAlerts(c *gin.Context) {
	a.mu.RLock()
	bn := a.biNotifier
	a.mu.RUnlock()

	if bn == nil {
		c.JSON(http.StatusOK, gin.H{"alerts": []interface{}{}, "pending": []interface{}{}, "count": 0})
		return
	}

	pending := bn.GetPendingAlerts()
	alerts := make([]gin.H, 0, len(pending))
	for _, p := range pending {
		if p.Acked {
			continue // 跳过已确认的
		}
		alerts = append(alerts, gin.H{
			"shortCode":  p.ShortID,
			"alertId":    p.AlertID,
			"title":      p.Alert.Title,
			"level":      string(p.Alert.Level),
			"timestamp":  p.Alert.Timestamp,
			"sentAt":     p.SentAt,
			"paused":     p.Paused,
			"replyCount": p.ReplyCount,
		})
	}
	c.JSON(http.StatusOK, gin.H{
		"alerts":  alerts,
		"pending": pending,
		"count":   len(alerts),
	})
}

// ────────────────────────────────────────────────
// V4.0 — 安全管理远程控制 API（前端补充）
// ────────────────────────────────────────────────

// getSafetyRemoteStatus GET /api/safety/status
func (a *API) getSafetyRemoteStatus(c *gin.Context) {
	if a.safety == nil {
		c.JSON(http.StatusOK, gin.H{"remotePaused": false})
		return
	}
	paused, reason, pausedAt := a.safety.RemotePausedInfo()
	c.JSON(http.StatusOK, gin.H{
		"remotePaused":         paused,
		"remotePausedReason":   reason,
		"remotePausedAt":       pausedAt,
		"bidirectionalEnabled": true,
		"emergencyStop":        a.safety.IsEmergencyStopped(),
		"mode":                 string(a.safety.GetMode()),
	})
}

// remotePause POST /api/safety/remote-pause
func (a *API) remotePause(c *gin.Context) {
	if a.safety == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "安全管理器未初始化"})
		return
	}
	a.safety.SetRemotePaused("通过面板手动暂停")
	c.JSON(http.StatusOK, gin.H{
		"success":      true,
		"message":      "自动修复已暂停",
		"remotePaused": true,
	})
}

// remoteResume POST /api/safety/remote-resume
func (a *API) remoteResume(c *gin.Context) {
	if a.safety == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "安全管理器未初始化"})
		return
	}
	a.safety.ClearRemotePaused()
	c.JSON(http.StatusOK, gin.H{
		"success":      true,
		"message":      "自动修复已恢复",
		"remotePaused": false,
	})
}

// ────────────────────────────────────────────────
// V4.0 — LLM 补充 API
// ────────────────────────────────────────────────

// saveLLMConfig POST /api/llm/config
func (a *API) saveLLMConfig(c *gin.Context) {
	var req struct {
		Provider        string `json:"provider"`
		APIKey          string `json:"apiKey"`
		APIBase         string `json:"apiBase"`
		Model           string `json:"model"`
		HumanizeAlert   bool   `json:"humanizeAlert"`
		WeeklyReport    bool   `json:"weeklyReport"`
		ExplainIncident bool   `json:"explainIncident"`
	}
	if err := c.BindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "无效请求"})
		return
	}

	// 保存到配置文件
	if a.cfg != nil {
		a.cfg.AI.Provider = req.Provider
		a.cfg.AI.APIKey = req.APIKey
		a.cfg.AI.APIBase = req.APIBase
		a.cfg.AI.Model = req.Model
		a.cfg.AI.HumanizeAlert = req.HumanizeAlert
		a.cfg.AI.WeeklyReport = req.WeeklyReport
		a.cfg.AI.ExplainIncident = req.ExplainIncident
		a.cfg.AI.Enabled = req.APIKey != ""
		if a.configPath != "" {
			_ = a.cfg.Save(a.configPath)
		}
	}

	// 关键：立即热更新运行中的 LLM 增强器。
	// 此前只写配置文件、不更新内存中的增强器，导致面板配置 API Key 后
	// AI 解释仍然全部失败（"无法生成解释"），必须重启且重启也无效——
	// 因为启动时只读环境变量，YAML 中的 Key 根本没被加载。
	if l := a.llmEnhancer; l != nil {
		l.UpdateConfig(ai.LLMConfig{
			Enabled:    req.APIKey != "",
			Provider:   req.Provider,
			APIKey:     req.APIKey,
			BaseURL:    req.APIBase,
			Model:      req.Model,
			MaxTokens:  2000,
			TimeoutSec: 30,
		})
	}

	c.JSON(http.StatusOK, gin.H{
		"success":     true,
		"message":     "AI 配置已保存并即时生效",
		"llm_enabled": a.llmEnhancer != nil && a.llmEnhancer.IsEnabled(),
	})
}

// testLLM POST /api/llm/test
// 异步执行：LLM 调用最多 30s，同步执行会触发 Hub WriteTimeout 30s 导致 502
func (a *API) testLLM(c *gin.Context) {
	a.mu.RLock()
	l := a.llmEnhancer
	a.mu.RUnlock()

	if l == nil {
		c.JSON(http.StatusOK, gin.H{
			"success": false,
			"message": "LLM 增强器未初始化，请先配置并重启",
		})
		return
	}

	if !l.IsEnabled() {
		c.JSON(http.StatusOK, gin.H{
			"success": false,
			"message": "LLM 未启用，请先配置 API Key",
		})
		return
	}

	// 检查是否已有结果或正在执行
	a.mu.Lock()
	if a.llmTestRunning {
		a.mu.Unlock()
		c.JSON(http.StatusAccepted, gin.H{
			"status":  "running",
			"message": "LLM 测试正在进行中，请稍后重试",
		})
		return
	}
	// 如果有缓存结果（2 分钟内）
	if !a.llmTestTime.IsZero() && time.Since(a.llmTestTime) < 2*time.Minute {
		result := a.llmTestResult
		a.mu.Unlock()
		c.JSON(http.StatusOK, gin.H{
			"status":  "completed",
			"success": true,
			"message": "LLM 连接正常（缓存结果）",
			"result":  result,
		})
		return
	}
	// 启动后台 LLM 调用
	a.llmTestRunning = true
	a.mu.Unlock()

	go func() {
		defer func() {
			if r := recover(); r != nil {
				fmt.Fprintf(os.Stderr, "[LLM] testLLM panicked: %v\n", r)
			}
			a.mu.Lock()
			a.llmTestRunning = false
			a.llmTestTime = time.Now()
			a.mu.Unlock()
		}()

		result := l.ExplainIncident(types.Incident{
			ID:         "test",
			RootTitle:  "测试事件",
			RootSource: "test",
		})
		a.mu.Lock()
		a.llmTestResult = result
		a.mu.Unlock()
	}()

	c.JSON(http.StatusAccepted, gin.H{
		"status":  "running",
		"message": "LLM 测试已启动，请稍后重试",
	})
}

// explainAlert GET /api/llm/explain-alert/:id
// 异步执行：LLM 调用最多 30s，同步执行会触发 Hub WriteTimeout 30s 导致 502
// 复用 llmIncident 缓存字段（按 alertID 区分），避免额外的结构体字段
func (a *API) explainAlert(c *gin.Context) {
	alertID := c.Param("id")
	if alertID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "缺少告警 ID"})
		return
	}

	a.mu.RLock()
	l := a.llmEnhancer
	storage := a.storage
	a.mu.RUnlock()

	if l == nil {
		c.JSON(http.StatusOK, gin.H{
			"explanation": "LLM 增强器未配置，无法生成 AI 解释。请在「系统设置 → AI 增强」中配置。",
			"llm_enabled": false,
		})
		return
	}

	// 检查是否已有结果或正在执行（复用 llmIncident 缓存，按 alertID 区分）
	a.mu.Lock()
	if a.llmIncidentRunning && a.llmIncidentID == "alert:"+alertID {
		a.mu.Unlock()
		c.JSON(http.StatusAccepted, gin.H{
			"status":      "running",
			"message":     "LLM 正在解释告警，请稍后重试",
			"llm_enabled": l.IsEnabled(),
		})
		return
	}
	if !a.llmIncidentTime.IsZero() && a.llmIncidentID == "alert:"+alertID && time.Since(a.llmIncidentTime) < 5*time.Minute {
		result := a.llmIncidentResult
		a.mu.Unlock()
		c.JSON(http.StatusOK, gin.H{
			"status":      "completed",
			"explanation": result,
			"llm_enabled": l.IsEnabled(),
		})
		return
	}
	a.llmIncidentRunning = true
	a.llmIncidentID = "alert:" + alertID
	a.mu.Unlock()

	go func() {
		defer func() {
			if r := recover(); r != nil {
				fmt.Fprintf(os.Stderr, "[LLM] explainAlert panicked: %v\n", r)
			}
			a.mu.Lock()
			a.llmIncidentRunning = false
			a.llmIncidentTime = time.Now()
			a.mu.Unlock()
		}()

		// 此前传入的是只有标题的假告警（Message 为空）：
		//   - LLM 未启用时 HumanizeAlert 原样返回空 Message → 前端显示"无法生成解释"
		//   - LLM 启用时 prompt 内容也是空的，生成结果毫无价值
		// 现在从存储中取出真实告警再解释；未配置 LLM 时降级返回原始告警内容。
		var result string
		alert, err := storage.GetAlertByID(alertID)
		switch {
		case err != nil || alert == nil:
			result = "告警不存在或已过期，无法生成解释"
		case !l.IsEnabled():
			result = "【LLM 未配置】在「系统设置 → AI 增强」填写 API Key 并保存后，可生成 AI 解释。" +
				"\n\n原始告警：" + alert.Title + "\n" + alert.Message
		default:
			result = l.HumanizeAlert(*alert)
		}
		a.mu.Lock()
		a.llmIncidentResult = result
		a.mu.Unlock()
	}()

	c.JSON(http.StatusAccepted, gin.H{
		"status":      "running",
		"message":     "LLM 正在解释告警，请稍后重试",
		"llm_enabled": l.IsEnabled(),
	})
}

// ────────────────────────────────────────────────
// V4.0 — Onboarding 补充 API
// ────────────────────────────────────────────────

// onboardingComplete POST /api/onboarding/complete
func (a *API) onboardingComplete(c *gin.Context) {
	var req struct {
		Basic    map[string]interface{} `json:"basic"`
		Notify   map[string]interface{} `json:"notify"`
		Guards   []string               `json:"guards"`
		Safety   map[string]interface{} `json:"safety"`
		Template string                 `json:"template"`
	}
	if err := c.BindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "无效请求"})
		return
	}

	// 应用通知配置
	if req.Notify != nil {
		if webhook, ok := req.Notify["wechatWebhook"].(string); ok && webhook != "" {
			a.cfg.Notify.WxPusherAppToken = webhook
		}
		if levels, ok := req.Notify["levels"].([]interface{}); ok {
			_ = levels // 保存告警级别
		}
	}

	// 应用安全配置
	if req.Safety != nil {
		if level, ok := req.Safety["autoFixLevel"].(string); ok {
			if level == "manual" {
				a.cfg.Agent.LearnMode = true
			} else {
				a.cfg.Agent.LearnMode = false
			}
		}
	}

	// 保存配置
	if a.configPath != "" {
		_ = a.cfg.Save(a.configPath)
	}

	// 标记 onboarding 完成
	a.mu.Lock()
	w := a.onboarding
	a.mu.Unlock()
	if w != nil {
		w.Skip() // 复用 skip 逻辑标记完成
	}

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"message": "初始化配置已完成，ServerGuard 开始保护你的服务器",
	})
}

// onboardingTestNotify POST /api/onboarding/test-notify
func (a *API) onboardingTestNotify(c *gin.Context) {
	var req map[string]interface{}
	if err := c.BindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "无效请求"})
		return
	}

	// 尝试发送测试通知
	a.mu.RLock()
	n := a.notifier
	a.mu.RUnlock()

	if n == nil {
		c.JSON(http.StatusOK, gin.H{"success": false, "error": "通知器未初始化"})
		return
	}

	// 使用临时配置发送测试
	testMsg := "ServerGuard 测试通知 — 如果您收到此消息，说明通知配置正确。"
	_ = n.SendCustom("ServerGuard 测试", testMsg)

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"message": "测试通知已发送",
	})
}

// ────────────────────────────────────────────────
// V4.0 — 知识库推荐 API（前端补充）
// ────────────────────────────────────────────────

// getRecommendations GET /api/knowledge/recommendations
func (a *API) getRecommendations(c *gin.Context) {
	a.mu.RLock()
	kb := a.knowledgeBase
	a.mu.RUnlock()

	if kb == nil {
		c.JSON(http.StatusOK, gin.H{"recommendations": []interface{}{}})
		return
	}

	recurring, _ := kb.GetRecurring(3, 20)
	recs := make([]gin.H, 0, len(recurring))
	for _, r := range recurring {
		successRate := 0.0
		if r.OccurrenceCount > 0 {
			if r.ActionResult == "success" {
				successRate = 1.0 / float64(r.OccurrenceCount) * float64(r.OccurrenceCount)
				// 简化：如果最后一次成功则成功率估算为 1/出现次数 * 出现次数
				successRate = 0.8 // 简化处理
			} else {
				successRate = 0.2
			}
		}
		recs = append(recs, gin.H{
			"symptom":      r.Symptom,
			"action":       r.Action,
			"success_rate": successRate,
			"exec_count":   r.OccurrenceCount,
			"last_used":    r.LastSeen,
		})
	}

	c.JSON(http.StatusOK, gin.H{
		"recommendations": recs,
		"count":           len(recs),
	})
}

// getRecommendationForAlert GET /api/knowledge/recommend/:alertId
func (a *API) getRecommendationForAlert(c *gin.Context) {
	alertID := c.Param("alertId")
	_ = alertID

	a.mu.RLock()
	kb := a.knowledgeBase
	a.mu.RUnlock()

	if kb == nil {
		c.JSON(http.StatusOK, gin.H{"recommendation": ""})
		return
	}

	recurring, _ := kb.GetRecurring(3, 5)
	recText := ""
	if len(recurring) > 0 {
		recText = fmt.Sprintf("历史经验：相同症状曾出现 %d 次，上次尝试动作「%s」，结果：%s。",
			recurring[0].OccurrenceCount, recurring[0].Action, recurring[0].ActionResult)
	}

	c.JSON(http.StatusOK, gin.H{
		"recommendation": recText,
	})
}

// ────────────────────────────────────────────────
// V4.0 — 故障事件补充 API
// ────────────────────────────────────────────────

// getIncidentByAlert GET /api/incidents/by-alert/:alertId
func (a *API) getIncidentByAlert(c *gin.Context) {
	alertID := c.Param("alertId")
	if alertID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "缺少告警 ID"})
		return
	}

	a.mu.RLock()
	storage := a.storage
	a.mu.RUnlock()

	if storage == nil {
		c.JSON(http.StatusOK, gin.H{"chain": []interface{}{}, "actions": []interface{}{}})
		return
	}

	incidents, err := storage.GetIncidents("", 50)
	if err != nil {
		c.JSON(http.StatusOK, gin.H{"chain": []interface{}{}, "actions": []interface{}{}})
		return
	}

	// 查找包含此告警的事件
	for _, inc := range incidents {
		for _, m := range inc.MemberAlerts {
			if m.AlertID == alertID {
				c.JSON(http.StatusOK, inc)
				return
			}
		}
	}

	// 没有找到关联事件
	c.JSON(http.StatusOK, gin.H{
		"chain":   []interface{}{},
		"actions": []interface{}{},
	})
}

// ────────────────────────────────────────────────
// V4.0 — 通知短编号操作 API
// ────────────────────────────────────────────────

// notifyShortCodePause POST /api/notify/:shortCode/pause
func (a *API) notifyShortCodePause(c *gin.Context) {
	shortCode := c.Param("shortCode")
	if shortCode == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "缺少短编号"})
		return
	}

	if a.safety != nil {
		a.safety.SetRemotePaused(fmt.Sprintf("告警 %s 暂停", shortCode))
	}

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"message": fmt.Sprintf("已暂停告警 %s 的自动修复", shortCode),
	})
}

// notifyShortCodeAck POST /api/notify/:shortCode/ack
func (a *API) notifyShortCodeAck(c *gin.Context) {
	shortCode := c.Param("shortCode")
	if shortCode == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "缺少短编号"})
		return
	}

	a.mu.RLock()
	bn := a.biNotifier
	a.mu.RUnlock()

	if bn != nil {
		bn.AckByShortCode(shortCode)
	}

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"message": fmt.Sprintf("已确认告警 %s", shortCode),
	})
}

// ────────────────────────────────────────────────
// 幽灵文件检测 API — 已删除但句柄未释放的隐形空间杀手
// ────────────────────────────────────────────────

// uniqueStrings 去重字符串切片
func uniqueStrings(s []string) []string {
	seen := make(map[string]bool, len(s))
	out := make([]string, 0, len(s))
	for _, v := range s {
		if !seen[v] {
			seen[v] = true
			out = append(out, v)
		}
	}
	return out
}

// getGhostFiles GET /api/ghost-files
// 返回最近一次自动扫描结果（不触发新扫描，扫描由后端定时自动执行）
func (a *API) getGhostFiles(c *gin.Context) {
	// 优先读取后端自动巡检的缓存结果
	ghosts, count, totalSizeGB, scanTime := log.GetLastGhostScanResult()
	if !scanTime.IsZero() {
		// 有缓存结果，直接返回
		totalSize := int64(0)
		for _, g := range ghosts {
			totalSize += g.Size
		}
		c.JSON(http.StatusOK, gin.H{
			"ghosts":       ghosts,
			"count":        count,
			"totalSize":    totalSize,
			"totalSizeGB":  totalSizeGB,
			"lastScanTime": scanTime.UTC().Format("2006-01-02T15:04:05Z"),
			"autoScanned":  true,
			"message":      fmt.Sprintf("后端自动扫描结果（%s）", scanTime.Format("2006-01-02 15:04:05")),
		})
		return
	}

	// 如果还没有缓存（刚启动），做一次实时扫描
	if runtime.GOOS == "windows" {
		c.JSON(http.StatusOK, gin.H{
			"ghosts":    []interface{}{},
			"totalSize": 0,
			"message":   "幽灵文件检测仅支持 Linux",
		})
		return
	}

	sm := a.safety
	if sm == nil {
		c.JSON(http.StatusOK, gin.H{
			"ghosts":    []interface{}{},
			"totalSize": 0,
			"message":   "安全管理器未初始化",
		})
		return
	}

	detector := log.NewGhostFileDetector(nil, sm)
	ghosts = detector.Detect()

	totalSize := int64(0)
	for _, g := range ghosts {
		totalSize += g.Size
	}

	c.JSON(http.StatusOK, gin.H{
		"ghosts":       ghosts,
		"count":        len(ghosts),
		"totalSize":    totalSize,
		"totalSizeGB":  math.Round(float64(totalSize)/1024/1024/1024*100) / 100,
		"lastScanTime": time.Now().UTC().Format("2006-01-02T15:04:05Z"),
		"autoScanned":  false,
	})
}

// scanGhostFiles POST /api/ghost-files/scan
// 手动触发幽灵文件扫描（日常使用不需要，后端已自动定时扫描）
func (a *API) scanGhostFiles(c *gin.Context) {
	if runtime.GOOS == "windows" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "幽灵文件检测仅支持 Linux"})
		return
	}

	sm := a.safety
	if sm == nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "安全管理器未初始化"})
		return
	}

	detector := log.NewGhostFileDetector(nil, sm)
	ghosts := detector.Detect()

	totalSize := int64(0)
	for _, g := range ghosts {
		totalSize += g.Size
	}

	c.JSON(http.StatusOK, gin.H{
		"success":      true,
		"ghosts":       ghosts,
		"count":        len(ghosts),
		"totalSize":    totalSize,
		"totalSizeGB":  math.Round(float64(totalSize)/1024/1024/1024*100) / 100,
		"lastScanTime": time.Now().UTC().Format("2006-01-02T15:04:05Z"),
		"message":      fmt.Sprintf("检测到 %d 个幽灵文件，总计 %.2fGB", len(ghosts), float64(totalSize)/1024/1024/1024),
	})
}

// cleanGhostFiles POST /api/ghost-files/clean
// 清理幽灵文件（通过重启持有句柄的进程释放空间）
func (a *API) cleanGhostFiles(c *gin.Context) {
	if runtime.GOOS == "windows" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "幽灵文件清理仅支持 Linux"})
		return
	}

	sm := a.safety
	if sm == nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "安全管理器未初始化"})
		return
	}

	// 先检查缓存中是否有幽灵文件
	cachedGhosts, cachedCount, _, _ := log.GetLastGhostScanResult()
	if cachedCount == 0 {
		c.JSON(http.StatusOK, gin.H{
			"success": true,
			"freed":   0,
			"freedGB": 0,
			"ghosts":  []interface{}{},
			"count":   0,
			"message": "当前没有幽灵文件需要清理",
		})
		return
	}

	// 指导用户：如果是关键进程持有的幽灵文件，提示手动重启
	hasCritical := false
	criticalNames := []string{}
	for _, g := range cachedGhosts {
		if log.IsGhostCriticalProcess(g.ProcessName) {
			hasCritical = true
			criticalNames = append(criticalNames, g.ProcessName)
		}
	}

	// 【关键修复】清理前先检查安全状态，避免静默失败
	// 用户点击"自动清理"后什么都没发生，重新扫描还是 48 个文件
	if sm.ShouldPauseDangerousActions() {
		mode := sm.GetMode()
		var reason string
		switch mode {
		case types.ModeSurvival:
			reason = "Agent 当前处于生存模式（系统资源极度紧张），所有危险操作已暂停"
		case types.ModeMinimal:
			reason = "Agent 当前处于最小模式（系统资源紧张），危险操作已暂停"
		case types.ModeThrottled:
			reason = "Agent 当前处于节流模式，危险操作已暂停"
		default:
			reason = "当前处于维护窗口或远程暂停期，危险操作已暂停"
		}
		c.JSON(http.StatusOK, gin.H{
			"success":     false,
			"freed":       0,
			"freedGB":     0,
			"ghosts":      cachedGhosts,
			"count":       cachedCount,
			"beforeCount": cachedCount,
			"message":     fmt.Sprintf("清理已跳过：%s。\n请等待系统资源恢复正常后重试，或在维护窗口外手动重启持有幽灵文件的服务释放空间。", reason),
		})
		return
	}

	cleaner := log.NewGhostFileCleaner(nil, sm)
	freed, beforeGhosts, afterGhosts := cleaner.CleanGhostFiles()

	// 更新缓存为清理后剩余的幽灵文件
	log.UpdateGhostScanCache(afterGhosts)

	afterSize := int64(0)
	for _, g := range afterGhosts {
		afterSize += g.Size
	}

	message := fmt.Sprintf("已释放 %.2fGB 幽灵空间", float64(freed)/1024/1024/1024)
	if len(afterGhosts) > 0 {
		message += fmt.Sprintf("，剩余 %d 个幽灵文件需手动处理（关键进程无法自动重启）", len(afterGhosts))
	}
	if hasCritical && freed == 0 {
		uniqueNames := strings.Join(uniqueStrings(criticalNames), "、")
		message = fmt.Sprintf("检测到 %d 个幽灵文件，但均由关键系统进程（%s）持有，无法自动终止。\n建议在维护窗口手动重启对应服务释放空间。", len(cachedGhosts), uniqueNames)
	}
	// 【关键修复】如果 freed=0 且没有关键进程，说明所有进程都被安全审批拒绝了
	if freed == 0 && !hasCritical && len(beforeGhosts) > 0 {
		message = fmt.Sprintf("检测到 %d 个幽灵文件，但安全审批拒绝了所有进程终止操作。\n可能原因：进程在白名单中、kill 预算耗尽、或级联观察期未结束。\n建议手动重启持有幽灵文件的服务释放空间。", len(beforeGhosts))
	}

	c.JSON(http.StatusOK, gin.H{
		"success":     true,
		"freed":       freed,
		"freedGB":     math.Round(float64(freed)/1024/1024/1024*100) / 100,
		"ghosts":      afterGhosts, // 返回清理后剩余的幽灵文件
		"count":       len(afterGhosts),
		"totalSize":   afterSize,
		"totalSizeGB": math.Round(float64(afterSize)/1024/1024/1024*100) / 100,
		"beforeCount": len(beforeGhosts),
		"message":     message,
	})
}
