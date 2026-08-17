package report

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/suoten/serverguard/internal/agent/forecast"
)

// ────────────────────────────────────────────────
// 运维日报/周报自动生成增强 (P15)
// 每周一早 8 点自动生成 Markdown 周报：
// 健康分趋势/资源峰值/故障数/证书到期/安全发现
// ────────────────────────────────────────────────

// GenerateWeekly 生成周报（Markdown 格式）
func (g *Generator) GenerateWeekly() string {
	now := time.Now()
	weekStart := now.Add(-7 * 24 * time.Hour)
	var sb strings.Builder

	fmt.Fprintf(&sb, "# ServerGuard 运维周报\n\n")
	fmt.Fprintf(&sb, "> **报告周期**：%s ~ %s\n", weekStart.Format("2006-01-02"), now.Format("2006-01-02"))
	fmt.Fprintf(&sb, "> **生成时间**：%s\n\n", now.Format("2006-01-02 15:04:05"))

	// ── 一、健康评分趋势 ──
	if g.scorer != nil {
		score := g.scorer.Get()
		fmt.Fprintf(&sb, "## 一、健康评分\n\n")
		fmt.Fprintf(&sb, "| 指标 | 数值 |\n|------|------|\n")
		fmt.Fprintf(&sb, "| 当前评分 | %d/100 |\n", score.Total)
		fmt.Fprintf(&sb, "| 趋势 | %s |\n", score.Trend)
		fmt.Fprintf(&sb, "| 性能 | %d |\n", score.Performance)
		fmt.Fprintf(&sb, "| 可用性 | %d |\n", score.Availability)
		fmt.Fprintf(&sb, "| 安全 | %d |\n\n", score.Security)
		if len(score.Deductions) > 0 {
			sb.WriteString("**主要扣分项**：\n")
			for i, d := range score.Deductions {
				if i >= 5 {
					break
				}
				fmt.Fprintf(&sb, "- %s（-%d）\n", d.Reason, d.Points)
			}
			sb.WriteString("\n")
		}
	}

	// ── 二、资源使用概览 ──
	if g.store != nil {
		fmt.Fprintf(&sb, "## 二、资源使用概览（近 7 天）\n\n")

		cpuMax, cpuAvg := g.metricStats("system.cpu_percent", weekStart)
		memMax, _ := g.metricStats("system.mem_percent", weekStart)
		diskMax, _ := g.metricStats("disk.used_percent", weekStart)

		fmt.Fprintf(&sb, "| 指标 | 峰值 | 均值 |\n|------|------|------|\n")
		if cpuMax >= 0 {
			fmt.Fprintf(&sb, "| CPU | %.0f%% | %.0f%% |\n", cpuMax, cpuAvg)
		}
		if memMax >= 0 {
			fmt.Fprintf(&sb, "| 内存 | %.0f%% | — |\n", memMax)
		}
		if diskMax >= 0 {
			fmt.Fprintf(&sb, "| 磁盘 | %.0f%% | — |\n\n", diskMax)
		}
	}

	// ── 三、故障与告警统计 ──
	if g.store != nil {
		fmt.Fprintf(&sb, "## 三、故障与告警统计\n\n")

		// 获取近 7 天的操作历史
		actions, _ := g.store.GetActionHistory(weekStart, 2000)
		if len(actions) > 0 {
			successCount := 0
			for _, a := range actions {
				if a.Success {
					successCount++
				}
			}
			successRate := float64(successCount) * 100 / float64(len(actions))
			fmt.Fprintf(&sb, "- **自动修复次数**：%d 次（成功 %d，成功率 %.0f%%）\n",
				len(actions), successCount, successRate)
		} else {
			sb.WriteString("- **自动修复次数**：0 次（本周无故障触发自动修复）\n")
		}

		// 未解决告警
		alerts, _ := g.store.GetUnresolvedAlerts()
		if len(alerts) > 0 {
			fmt.Fprintf(&sb, "- **当前未解决告警**：%d 条\n", len(alerts))
		} else {
			sb.WriteString("- **当前未解决告警**：0 条\n")
		}

		// 重复问题
		if repeated, err := g.store.GetTopRepeatedAlerts(weekStart, 3, 5); err == nil && len(repeated) > 0 {
			sb.WriteString("\n### 反复出现的问题（近 7 天）\n\n")
			for _, r := range repeated {
				fmt.Fprintf(&sb, "- **%s**（%d 次，最近 %s）——根因未除，建议彻底排查\n",
					r.Title, r.Count, r.Last.Format("01-02 15:04"))
			}
		}
		sb.WriteString("\n")
	}

	// ── 四、网站可用性 ──
	if g.probe != nil {
		sites := g.probe.GetSites()
		if len(sites) > 0 {
			fmt.Fprintf(&sb, "## 四、网站可用性\n\n")
			fmt.Fprintf(&sb, "| 站点 | URL | 状态 | 延迟 |\n|------|-----|------|------|\n")
			for _, s := range sites {
				status := "✅ 在线"
				if !s.Up {
					status = "❌ 离线"
				}
				fmt.Fprintf(&sb, "| %s | %s | %s | %dms |\n", s.Name, s.URL, status, s.Latency.Milliseconds())
			}
			sb.WriteString("\n")
		}
	}

	// ── 五、证书状态 ──
	if g.certGuard != nil {
		certs := g.certGuard.GetCerts()
		if len(certs) > 0 {
			fmt.Fprintf(&sb, "## 五、证书状态\n\n")
			var expiring []string
			for _, ci := range certs {
				if ci.DaysUntilExpiry <= 30 {
					expiring = append(expiring, fmt.Sprintf("%s（剩 %d 天）", ci.Domain, ci.DaysUntilExpiry))
				}
			}
			fmt.Fprintf(&sb, "- **证书总数**：%d 张\n", len(certs))
			if len(expiring) > 0 {
				sort.Strings(expiring)
				fmt.Fprintf(&sb, "- **30 天内到期**：%d 张\n", len(expiring))
				for _, e := range expiring {
					fmt.Fprintf(&sb, "  - %s\n", e)
				}
			} else {
				sb.WriteString("- **30 天内到期**：无\n")
			}
			sb.WriteString("\n")
		}
	}

	// ── 六、安全发现 ──
	if g.store != nil {
		if counts, err := g.store.GetFindingCountByScanner(); err == nil && len(counts) > 0 {
			total := 0
			for _, n := range counts {
				total += n
			}
			if total > 0 {
				fmt.Fprintf(&sb, "## 六、待处理安全发现\n\n")
				fmt.Fprintf(&sb, "- **待处理总数**：%d 项\n", total)
				for scanner, count := range counts {
					fmt.Fprintf(&sb, "  - %s：%d 项\n", scanner, count)
				}
				sb.WriteString("\n")
			}
		}
	}

	// ── 七、磁盘容量预测 ──
	if g.store != nil {
		if forecasts := forecast.GetForecasts(g.store); len(forecasts) > 0 {
			var lines []string
			for _, f := range forecasts {
				if f.DaysLeft < 0 {
					continue
				}
				if f.DaysLeft <= 30 {
					lines = append(lines, fmt.Sprintf("- **%s**：当前 %.0f%%，增速 %.1f%%/天，预计 %d 天后（%s）达到 90%%",
						f.Mount, f.Current, f.SlopePer, f.DaysLeft, f.FullDate))
				}
			}
			if len(lines) > 0 {
				fmt.Fprintf(&sb, "## 七、磁盘容量预测\n\n")
				for _, l := range lines {
					sb.WriteString(l + "\n")
				}
				sb.WriteString("\n")
			}
		}
	}

	sb.WriteString("---\n")
	sb.WriteString("\n*本报告由 ServerGuard 自动生成，如需调整推送时间请到面板 → 设置 → 通知配置*\n")

	return sb.String()
}
