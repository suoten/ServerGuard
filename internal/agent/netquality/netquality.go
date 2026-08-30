// Package netquality 提供端到端网络质量地图能力。
// V3.9 — 持续 ping/trace/mtr → 记录延迟/丢包 → 面板绘制网络质量热力图
package netquality

import (
	"context"
	"fmt"
	"net"
	"os/exec"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/suoten/serverguard/internal/storage"
)

// ────────────────────────────────────────────────
// 端到端网络质量地图 (P9)
// ────────────────────────────────────────────────

// ProbeTarget 探测目标
type ProbeTarget struct {
	Name    string `json:"name"`
	Host    string `json:"host"`
	Comment string `json:"comment"`
}

// ProbeResult 探测结果
type ProbeResult struct {
	Target     string    `json:"target"`
	Host       string    `json:"host"`
	Alive      bool      `json:"alive"`
	RTTMin     float64   `json:"rtt_min_ms"`
	RTTAvg     float64   `json:"rtt_avg_ms"`
	RTTMax     float64   `json:"rtt_max_ms"`
	Jitter     float64   `json:"jitter_ms"`  // 抖动(max-min)/2
	Loss       float64   `json:"loss"`        // 丢包率（修复：之前是 loss_percent 导致前端读不到）
	Hops       int       `json:"hops"`        // traceroute 跳数
	Grade      string    `json:"grade"`       // 质量评级 A/B/C/D/F
	Assessment string    `json:"assessment"`  // 评估说明
	Timestamp  time.Time `json:"timestamp"`
}

// QualityReport 网络质量报告
type QualityReport struct {
	Timestamp time.Time     `json:"timestamp"`
	Results   []ProbeResult `json:"results"`
	Overall   string        `json:"overall"`     // 总体评估
}

// 默认探测目标
var defaultTargets = []ProbeTarget{
	{"网关", "", "本地网关"},
	{"DNS-114", "114.114.114.114", "国内公共 DNS"},
	{"DNS-8.8", "8.8.8.8", "Google DNS"},
	{"百度", "www.baidu.com", "国内站点"},
	{"阿里云", "www.aliyun.com", "国内云厂商"},
	{"GitHub", "github.com", "海外代码托管"},
}

// Monitor 网络质量监控器
type Monitor struct {
	store   *storage.Storage
	mu      sync.Mutex
	last    *QualityReport
	targets []ProbeTarget
}

// New 创建网络质量监控器
func New(store *storage.Storage) *Monitor {
	return &Monitor{
		store:   store,
		targets: defaultTargets,
	}
}

// GetTargets 返回探测目标列表
func (m *Monitor) GetTargets() []ProbeTarget {
	return m.targets
}

// AddTarget 添加探测目标
func (m *Monitor) AddTarget(name, host, comment string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.targets = append(m.targets, ProbeTarget{Name: name, Host: host, Comment: comment})
}

// 探测超时预算：网络故障（正是本模块最需要工作的场景）时，
// ping/traceroute 可能长时间不返回，必须用 context 强制兜底，否则探测 goroutine 会堆积
const (
	pingTimeout  = 20 * time.Second
	traceTimeout = 45 * time.Second
	routeTimeout = 5 * time.Second
)

// Probe 执行一轮探测。ctx 为 nil 时使用独立超时上下文（向后兼容）。
func (m *Monitor) Probe(ctx context.Context) *QualityReport {
	if ctx == nil {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(context.Background(), 2*time.Minute)
		defer cancel()
	}

	report := &QualityReport{
		Timestamp: time.Now(),
	}

	// 探测网关
	gatewayIP := detectGateway(ctx)

	for _, target := range m.targets {
		// 如果是网关目标且 Host 为空，使用检测到的网关 IP
		t := target
		if t.Host == "" && t.Name == "网关" {
			if gatewayIP != "" {
				t.Host = gatewayIP
			} else {
				// 无法检测网关，标记为不可用
				report.Results = append(report.Results, ProbeResult{
					Target:     target.Name,
					Host:       "未知",
					Alive:      false,
					Timestamp:  time.Now(),
					Assessment: "无法检测默认网关地址",
					Grade:      "F",
				})
				continue
			}
		}

		result := probeTarget(ctx, t)
		report.Results = append(report.Results, result)
	}

	// 生成总体评估
	report.Overall = generateOverallAssessment(report.Results)

	m.mu.Lock()
	m.last = report
	m.mu.Unlock()

	return report
}

// GetLastReport 返回最近一次报告
func (m *Monitor) GetLastReport() *QualityReport {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.last
}

// detectGateway 检测默认网关 IP
func detectGateway(ctx context.Context) string {
	if ctx == nil {
		ctx = context.Background()
	}
	if runtime.GOOS == "windows" {
		// route print
		cmd := exec.CommandContext(ctx, "route", "print", "0.0.0.0")
		output, err := cmd.CombinedOutput()
		if err == nil {
			lines := strings.Split(string(output), "\n")
			for _, line := range lines {
				if strings.Contains(line, "0.0.0.0") && strings.Contains(line, "0.0.0.0") {
					fields := strings.Fields(line)
					for i, f := range fields {
						if f == "0.0.0.0" && i > 0 {
							// 网关在 "0.0.0.0    0.0.0.0    <gateway>    <interface>" 中
							if i+2 < len(fields) {
								gw := fields[i+2]
								if net.ParseIP(gw) != nil {
									return gw
								}
							}
						}
					}
				}
			}
		}
	} else {
		// Linux: ip route show default
		routeCtx, cancel := context.WithTimeout(ctx, routeTimeout)
		defer cancel()
		cmd := exec.CommandContext(routeCtx, "ip", "route", "show", "default")
		output, err := cmd.CombinedOutput()
		if err == nil {
			// "default via 192.168.1.1 dev eth0"
			line := strings.TrimSpace(string(output))
			if strings.HasPrefix(line, "default via ") {
				parts := strings.Fields(line)
				if len(parts) >= 3 {
					return parts[2]
				}
			}
		}
		// fallback: route -n
		cmd2 := exec.CommandContext(routeCtx, "route", "-n")
		output2, err := cmd2.CombinedOutput()
		if err == nil {
			lines := strings.Split(string(output2), "\n")
			for _, line := range lines {
				if strings.Contains(line, "0.0.0.0") && strings.Contains(line, "UG") {
					fields := strings.Fields(line)
					if len(fields) >= 2 {
						return fields[1]
					}
				}
			}
		}
	}
	return ""
}

// probeTarget 探测单个目标
func probeTarget(ctx context.Context, target ProbeTarget) ProbeResult {
	result := ProbeResult{
		Target:    target.Name,
		Host:      target.Host,
		Timestamp: time.Now(),
	}

	// ping 探测（带独立超时）
	pingCtx, pingCancel := context.WithTimeout(ctx, pingTimeout)
	minRTT, avgRTT, maxRTT, loss, alive := pingHost(pingCtx, target.Host)
	pingCancel()
	result.Alive = alive
	result.RTTMin = minRTT
	result.RTTAvg = avgRTT
	result.RTTMax = maxRTT
	result.Loss = loss

	// 抖动 = (max - min) / 2
	result.Jitter = (maxRTT - minRTT) / 2

	// traceroute 跳数（仅当存活时，带独立超时——traceroute 在丢包网络下可能极慢）
	if alive {
		traceCtx, traceCancel := context.WithTimeout(ctx, traceTimeout)
		result.Hops = traceHops(traceCtx, target.Host)
		traceCancel()
	}

	// 评级和评估
	result.Grade, result.Assessment = assessQuality(avgRTT, loss, alive, result.Jitter)

	return result
}

// assessQuality 根据延迟、丢包、抖动评估网络质量
func assessQuality(avgRTT, loss float64, alive bool, jitter float64) (grade, assessment string) {
	if !alive {
		return "F", "不可达，目标主机无法响应"
	}

	// 综合评分
	score := 100
	if loss > 0 {
		score -= int(loss * 2) // 每丢 1% 扣 2 分
	}
	if avgRTT > 200 {
		score -= 30
	} else if avgRTT > 100 {
		score -= 15
	} else if avgRTT > 50 {
		score -= 5
	}
	if jitter > 50 {
		score -= 15
	} else if jitter > 20 {
		score -= 8
	}

	switch {
	case score >= 90:
		grade = "A"
	case score >= 75:
		grade = "B"
	case score >= 60:
		grade = "C"
	case score >= 40:
		grade = "D"
	default:
		grade = "F"
	}

	// 生成评估说明
	var parts []string
	if loss == 0 {
		parts = append(parts, "无丢包")
	} else {
		parts = append(parts, fmt.Sprintf("丢包 %.0f%%", loss))
	}
	if avgRTT < 50 {
		parts = append(parts, fmt.Sprintf("延迟 %.0fms 极低", avgRTT))
	} else if avgRTT < 150 {
		parts = append(parts, fmt.Sprintf("延迟 %.0fms 正常", avgRTT))
	} else if avgRTT < 300 {
		parts = append(parts, fmt.Sprintf("延迟 %.0fms 偏高", avgRTT))
	} else {
		parts = append(parts, fmt.Sprintf("延迟 %.0fms 较高", avgRTT))
	}
	if jitter > 30 {
		parts = append(parts, fmt.Sprintf("抖动 %.0fms 较大", jitter))
	}

	assessment = strings.Join(parts, "，")

	// 特殊评估
	if loss >= 50 {
		assessment += "，网络连接严重不稳定"
	} else if loss > 0 && loss < 25 {
		assessment += "，存在轻微丢包"
	}

	return
}

// generateOverallAssessment 生成总体网络质量评估
func generateOverallAssessment(results []ProbeResult) string {
	if len(results) == 0 {
		return "暂无探测数据"
	}

	var alive, total float64
	var totalRTT float64
	var rttCount int
	var totalLoss float64
	gradeCount := map[string]int{}

	for _, r := range results {
		total++
		if r.Alive {
			alive++
			totalRTT += r.RTTAvg
			rttCount++
			totalLoss += r.Loss
			gradeCount[r.Grade]++
		}
	}

	if alive == 0 {
		return "所有目标均不可达，请检查网络连接"
	}

	avgRTT := totalRTT / float64(rttCount)
	avgLoss := totalLoss / float64(rttCount)
	aliveRate := alive / total * 100

	var sb strings.Builder
	fmt.Fprintf(&sb, "网络存活率 %.0f%%", aliveRate)
	if avgLoss == 0 {
		sb.WriteString("，无丢包")
	} else {
		fmt.Fprintf(&sb, "，平均丢包 %.1f%%", avgLoss)
	}
	fmt.Fprintf(&sb, "，平均延迟 %.0fms", avgRTT)

	// 评级统计
	bestGrade := "A"
	gradeOrder := map[string]int{"A": 5, "B": 4, "C": 3, "D": 2, "F": 1}
	bestScore := 0
	for g, count := range gradeCount {
		score := gradeOrder[g] * count
		if score > bestScore {
			bestScore = score
			bestGrade = g
		}
	}
	fmt.Fprintf(&sb, "，综合评级 %s", bestGrade)

	return sb.String()
}

// pingHost 执行 ping 并解析结果（ctx 超时强制兜底）
func pingHost(ctx context.Context, host string) (min, avg, max, loss float64, alive bool) {
	var cmd *exec.Cmd
	if runtime.GOOS == "windows" {
		cmd = exec.CommandContext(ctx, "ping", "-n", "4", "-w", "3000", host)
	} else {
		cmd = exec.CommandContext(ctx, "ping", "-c", "4", "-W", "3", host)
	}
	output, err := cmd.CombinedOutput()
	if err != nil {
		if len(output) == 0 {
			return 0, 0, 0, 100, false
		}
	}
	out := string(output)

	if runtime.GOOS == "windows" {
		min = parsePingValue(out, "Minimum = ")
		max = parsePingValue(out, "Maximum = ")
		avg = parsePingValue(out, "Average = ")
		loss = parseWindowsLoss(out)
	} else {
		// Linux: rtt min/avg/max/mdev = 1.234/2.345/3.456/0.123 ms
		if idx := strings.Index(out, "min/avg/max"); idx >= 0 {
			line := out[idx:]
			eqIdx := strings.Index(line, "=")
			if eqIdx >= 0 {
				nums := strings.Fields(line[eqIdx+1:])
				if len(nums) > 0 {
					parts := strings.Split(nums[0], "/")
					if len(parts) >= 3 {
						min, _ = strconv.ParseFloat(parts[0], 64)
						avg, _ = strconv.ParseFloat(parts[1], 64)
						max, _ = strconv.ParseFloat(parts[2], 64)
					}
				}
			}
		}
		loss = parseLinuxLoss(out)
	}

	alive = avg > 0 || loss < 100
	return
}

func parsePingValue(text, prefix string) float64 {
	idx := strings.Index(text, prefix)
	if idx < 0 {
		return 0
	}
	rest := text[idx+len(prefix):]
	numStr := ""
	for _, c := range rest {
		if (c >= '0' && c <= '9') || c == '.' {
			numStr += string(c)
		} else if numStr != "" {
			break
		}
	}
	val, _ := strconv.ParseFloat(numStr, 64)
	return val
}

func parseWindowsLoss(text string) float64 {
	idx := strings.Index(text, "loss")
	if idx < 0 {
		return 0
	}
	rest := text[:idx]
	percentIdx := strings.LastIndex(rest, "(")
	if percentIdx < 0 {
		return 0
	}
	numStr := ""
	for _, c := range rest[percentIdx+1:] {
		if (c >= '0' && c <= '9') || c == '.' {
			numStr += string(c)
		} else if c == '%' {
			break
		}
	}
	val, _ := strconv.ParseFloat(numStr, 64)
	return val
}

func parseLinuxLoss(text string) float64 {
	lines := strings.Split(text, "\n")
	for _, line := range lines {
		if strings.Contains(line, "packet loss") {
			if idx := strings.Index(line, ","); idx >= 0 {
				rest := line[idx:]
				if pctIdx := strings.Index(rest, "%"); pctIdx >= 0 {
					numStr := ""
					for i := pctIdx - 1; i >= 0; i-- {
						c := rest[i]
						if (c >= '0' && c <= '9') || c == '.' || c == ' ' {
							if c != ' ' {
								numStr = string(c) + numStr
							} else if numStr != "" {
								break
							}
						}
					}
					val, _ := strconv.ParseFloat(numStr, 64)
					return val
				}
			}
		}
	}
	return 0
}

// traceHops 执行 traceroute 并返回跳数（ctx 超时强制兜底）
func traceHops(ctx context.Context, host string) int {
	var cmd *exec.Cmd
	if runtime.GOOS == "windows" {
		cmd = exec.CommandContext(ctx, "tracert", "-d", "-h", "15", "-w", "1000", host)
	} else {
		if _, err := exec.LookPath("mtr"); err == nil {
			cmd = exec.CommandContext(ctx, "mtr", "-r", "-c", "1", "-n", host)
		} else if _, err := exec.LookPath("traceroute"); err == nil {
			cmd = exec.CommandContext(ctx, "traceroute", "-n", "-w", "1", "-m", "15", host)
		} else {
			return 0
		}
	}
	output, err := cmd.CombinedOutput()
	if err != nil {
		return 0
	}
	lines := strings.Split(string(output), "\n")
	hops := 0
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "HOST") || strings.HasPrefix(line, "Start") {
			continue
		}
		if len(line) > 0 && line[0] >= '0' && line[0] <= '9' {
			hops++
		} else if runtime.GOOS == "windows" && strings.Contains(line, "ms") {
			hops++
		}
	}
	return hops
}

// FormatReport 格式化报告为文本（用于通知）
func FormatReport(report *QualityReport) string {
	if report == nil {
		return "网络质量报告：无数据"
	}
	var sb strings.Builder
	fmt.Fprintf(&sb, "【网络质量报告】%s\n", report.Timestamp.Format("01-02 15:04"))
	if report.Overall != "" {
		fmt.Fprintf(&sb, "总体: %s\n", report.Overall)
	}

	// 按评级排序（A 在前）
	sorted := make([]ProbeResult, len(report.Results))
	copy(sorted, report.Results)
	sort.Slice(sorted, func(i, j int) bool {
		gradeOrder := map[string]int{"A": 5, "B": 4, "C": 3, "D": 2, "F": 1}
		return gradeOrder[sorted[i].Grade] > gradeOrder[sorted[j].Grade]
	})

	for _, r := range sorted {
		if !r.Alive {
			fmt.Fprintf(&sb, "  ❌ %s (%s) — 不可达\n", r.Target, r.Host)
		} else {
			status := "✅"
			if r.Grade == "C" || r.Grade == "D" {
				status = "⚠️"
			} else if r.Grade == "F" {
				status = "❌"
			}
			fmt.Fprintf(&sb, "  %s [%s] %s (%s) — %.0fms (抖动%.0fms), 丢包%.0f%%, %d跳\n",
				status, r.Grade, r.Target, r.Host, r.RTTAvg, r.Jitter, r.Loss, r.Hops)
		}
	}
	return sb.String()
}
