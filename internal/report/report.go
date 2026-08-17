// Package report 生成每日巡检报告。
// 汇总健康评分、资源峰值、网站存活性、证书到期、告警统计与自愈动作，
// 通过通知渠道定时推送，也可在面板预览或立即发送。
package report

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/suoten/serverguard/internal/agent/healthscore"
	"github.com/suoten/serverguard/internal/agent/probe"
	"github.com/suoten/serverguard/internal/guards/cert"
	"github.com/suoten/serverguard/internal/storage"
	"github.com/suoten/serverguard/internal/agent/forecast"
)

// Generator 巡检报告生成器。
type Generator struct {
	store     *storage.Storage
	scorer    *healthscore.Scorer
	probe     *probe.Probe
	certGuard *cert.CertGuard
}

// New 创建报告生成器（各依赖均可为 nil，对应章节自动跳过）。
func New(store *storage.Storage, scorer *healthscore.Scorer, p *probe.Probe, cg *cert.CertGuard) *Generator {
	return &Generator{store: store, scorer: scorer, probe: p, certGuard: cg}
}

// Generate 生成纯文本巡检报告（适配微信/钉钉/邮件等纯文本渠道）。
func (g *Generator) Generate() string {
	now := time.Now()
	since := now.Add(-24 * time.Hour)
	var sb strings.Builder

	fmt.Fprintf(&sb, "【ServerGuard 每日巡检报告】%s\n", now.Format("2006-01-02"))

	// ── 健康评分 ──
	if g.scorer != nil {
		score := g.scorer.Get()
		trend := map[string]string{"up": "↑ 上升", "down": "↓ 下降", "stable": "→ 平稳"}[score.Trend]
		if trend == "" {
			trend = score.Trend
		}
		fmt.Fprintf(&sb, "\n🩺 健康评分：%d/100（趋势：%s）\n", score.Total, trend)
		fmt.Fprintf(&sb, "   性能 %d / 可用性 %d / 安全 %d\n", score.Performance, score.Availability, score.Security)
		if len(score.Deductions) > 0 {
			sb.WriteString("   主要扣分项：")
			for i, d := range score.Deductions {
				if i >= 3 {
					break
				}
				fmt.Fprintf(&sb, "%s(-%d) ", d.Reason, d.Points)
			}
			sb.WriteString("\n")
		}
	}

	// ── 资源峰值（近 24h） ──
	if g.store != nil {
		cpuMax, cpuAvg := g.metricStats("system.cpu_percent", since)
		memMax, _ := g.metricStats("system.mem_percent", since)
		diskMax, _ := g.metricStats("disk.used_percent", since)
		if cpuMax >= 0 {
			fmt.Fprintf(&sb, "\n💻 资源概览（近24h）：CPU 峰值 %.0f%% / 均值 %.0f%%；内存峰值 %.0f%%；磁盘最高 %.0f%%\n",
				cpuMax, cpuAvg, memMax, diskMax)
		}
	}

	// ── 网站存活性 ──
	if g.probe != nil {
		sites := g.probe.GetSites()
		if len(sites) > 0 {
			up := 0
			var downNames []string
			var totalLatency time.Duration
			latencyCount := 0
			for _, s := range sites {
				if s.Up {
					up++
					if s.Latency > 0 {
						totalLatency += s.Latency
						latencyCount++
					}
				} else {
					downNames = append(downNames, s.Name)
				}
			}
			fmt.Fprintf(&sb, "\n🌐 网站监控：在线 %d / 共 %d", up, len(sites))
			if latencyCount > 0 {
				fmt.Fprintf(&sb, "，平均延迟 %dms", totalLatency.Milliseconds()/int64(latencyCount))
			}
			sb.WriteString("\n")
			if len(downNames) > 0 {
				fmt.Fprintf(&sb, "   ⚠️ 宕机站点：%s\n", strings.Join(downNames, "、"))
			}
		}
	}

	// ── 证书到期 ──
	if g.certGuard != nil {
		certs := g.certGuard.GetCerts()
		if len(certs) > 0 {
			var expiring []string
			for _, ci := range certs {
				if ci.DaysUntilExpiry <= 30 {
					expiring = append(expiring, fmt.Sprintf("%s(剩%d天)", ci.Domain, ci.DaysUntilExpiry))
				}
			}
			fmt.Fprintf(&sb, "\n🔐 证书状态：共 %d 张", len(certs))
			if len(expiring) > 0 {
				sort.Strings(expiring)
				fmt.Fprintf(&sb, "；%d 张 30 天内到期：%s", len(expiring), strings.Join(expiring, "、"))
			} else {
				sb.WriteString("，均在有效期内")
			}
			sb.WriteString("\n")
		}
	}

	// ── 磁盘容量预测（智能） ──
	if g.store != nil {
		if forecasts := forecast.GetForecasts(g.store); len(forecasts) > 0 {
			var lines []string
			for _, f := range forecasts {
				if f.DaysLeft < 0 {
					continue // 稳定不增长
				}
				if f.DaysLeft <= 7 {
					lines = append(lines, fmt.Sprintf("⚠️ %s 当前 %.0f%%，增速 %.1f%%/天，预计 %d 天后（%s）达到 90%%",
						f.Mount, f.Current, f.SlopePer, f.DaysLeft, f.FullDate))
				} else if f.DaysLeft <= 30 {
					lines = append(lines, fmt.Sprintf("%s 当前 %.0f%%，预计 %d 天后达到 90%%（%s）",
						f.Mount, f.Current, f.DaysLeft, f.FullDate))
				}
			}
			if len(lines) > 0 {
				fmt.Fprintf(&sb, "\n📈 磁盘容量预测：\n")
				for _, l := range lines {
					fmt.Fprintf(&sb, "   · %s\n", l)
				}
			}
		}
	}

	// ── 重复问题根治建议（智能） ──
	// 同一告警 7 天内反复出现 = 根因未除，提示用户彻底排查而非反复救火
	if g.store != nil {
		if repeated, err := g.store.GetTopRepeatedAlerts(now.Add(-7*24*time.Hour), 3, 3); err == nil && len(repeated) > 0 {
			fmt.Fprintf(&sb, "\n🔁 重复问题根治建议（近7天反复出现）：\n")
			for _, r := range repeated {
				fmt.Fprintf(&sb, "   · %s（%d 次，最近 %s）——反复出现说明根因未除，建议彻底排查\n",
					r.Title, r.Count, r.Last.Format("01-02 15:04"))
			}
		}
	}

	// ── 未解决告警 ──
	if g.store != nil {
		if alerts, err := g.store.GetUnresolvedAlerts(); err == nil {
			byLevel := map[string]int{}
			for _, al := range alerts {
				byLevel[strings.ToLower(string(al.Level))]++
			}
			fmt.Fprintf(&sb, "\n🚨 未解决告警：共 %d 条", len(alerts))
			if len(alerts) > 0 {
				fmt.Fprintf(&sb, "（严重 %d / 错误 %d / 警告 %d / 提示 %d）\n",
					byLevel["critical"]+byLevel["fatal"], byLevel["error"], byLevel["warning"], byLevel["info"])
				sb.WriteString("   Top 告警：\n")
				for i, al := range alerts {
					if i >= 5 {
						fmt.Fprintf(&sb, "   …等共 %d 条\n", len(alerts))
						break
					}
					fmt.Fprintf(&sb, "   · [%s] %s\n", al.Level, al.Title)
				}
			} else {
				sb.WriteString("，系统无待处理风险\n")
			}
		}

		// ── 今日自愈动作 ──
		if actions, err := g.store.GetActionHistory(since, 500); err == nil && len(actions) > 0 {
			success := 0
			for _, act := range actions {
				if act.Success {
					success++
				}
			}
			fmt.Fprintf(&sb, "\n🛠 近24h自愈动作：共 %d 次（成功 %d，成功率 %.0f%%），最近：\n",
				len(actions), success, float64(success)*100/float64(len(actions)))
			for i, act := range actions {
				if i >= 3 {
					break
				}
				msg := act.Message
				if len([]rune(msg)) > 50 {
					msg = string([]rune(msg)[:50]) + "…"
				}
				fmt.Fprintf(&sb, "   · %s %s\n", act.Timestamp.Format("15:04"), msg)
			}
		}

		// ── 待处理安全发现 ──
		if counts, err := g.store.GetFindingCountByScanner(); err == nil && len(counts) > 0 {
			total := 0
			for _, n := range counts {
				total += n
			}
			if total > 0 {
				fmt.Fprintf(&sb, "\n🔍 待处理安全发现：%d 项（详见面板「安全发现」页）\n", total)
			}
		}
	}

	sb.WriteString("\n—— ServerGuard 服务器智能守护\n")
	return sb.String()
}

// metricStats 返回指标在时间范围内的峰值与均值；无数据时返回 -1, -1。
func (g *Generator) metricStats(name string, since time.Time) (max, avg float64) {
	metrics, err := g.store.GetMetrics("", name, since, 20000)
	if err != nil || len(metrics) == 0 {
		return -1, -1
	}
	var sum float64
	max = metrics[0].Value
	for _, m := range metrics {
		if m.Value > max {
			max = m.Value
		}
		sum += m.Value
	}
	return max, sum / float64(len(metrics))
}
