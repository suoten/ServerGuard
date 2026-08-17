package api

import (
	"fmt"
	"net/http"
	"os"
	"runtime"
	"sort"
	"strconv"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/shirou/gopsutil/v3/cpu"
	"github.com/shirou/gopsutil/v3/disk"
	"github.com/shirou/gopsutil/v3/mem"
	"github.com/suoten/serverguard/internal/version"
)

// ────────────────────────────────────────────────
// Prometheus /metrics 导出端点
// 供 Prometheus 抓取，配合 Grafana 实现多机大盘与告警联动。
// 安全：支持可选访问令牌（store key "metrics_token"，配置后需 ?token= 携带）。
// 只读端点，不暴露任何敏感配置。
// ────────────────────────────────────────────────

// promMetrics GET /metrics —— Prometheus 文本暴露格式。
func (a *API) promMetrics(c *gin.Context) {
	// 可选访问令牌保护
	if tok, err := a.storage.Get("metrics_token"); err == nil && tok != "" {
		if c.Query("token") != tok {
			c.String(http.StatusForbidden, "forbidden: invalid metrics token\n")
			return
		}
	}

	var b strings.Builder

	writeGauge := func(name, help string, value float64, labels ...string) {
		fmt.Fprintf(&b, "# HELP %s %s\n# TYPE %s gauge\n", name, help, name)
		if len(labels) > 0 {
			fmt.Fprintf(&b, "%s{%s} %s\n", name, strings.Join(labels, ","), formatFloat(value))
		} else {
			fmt.Fprintf(&b, "%s %s\n", name, formatFloat(value))
		}
	}
	labelPair := func(k, v string) string {
		return fmt.Sprintf(`%s=%q`, k, v)
	}

	// 版本信息
	fmt.Fprintf(&b, "# HELP serverguard_info ServerGuard 版本信息\n# TYPE serverguard_info gauge\n")
	fmt.Fprintf(&b, "serverguard_info{%s} 1\n", labelPair("version", version.ShortVersion()))

	// 健康评分
	if a.scorer != nil {
		score := a.scorer.Get()
		writeGauge("serverguard_health_score", "健康评分 (0-100)", float64(score.Total))
	}

	// CPU / 内存（瞬时采样，非阻塞）
	if percents, err := cpu.Percent(0, false); err == nil && len(percents) > 0 {
		writeGauge("serverguard_cpu_percent", "CPU 使用率 (%)", percents[0])
	}
	if memInfo, err := mem.VirtualMemory(); err == nil {
		writeGauge("serverguard_mem_percent", "内存使用率 (%)", memInfo.UsedPercent)
	}

	// 磁盘（每挂载点一条）
	if partitions, err := disk.Partitions(false); err == nil {
		fmt.Fprintf(&b, "# HELP serverguard_disk_used_percent 磁盘使用率 (%%)\n# TYPE serverguard_disk_used_percent gauge\n")
		for _, part := range partitions {
			if usage, err := disk.Usage(part.Mountpoint); err == nil {
				fmt.Fprintf(&b, "serverguard_disk_used_percent{%s} %s\n",
					labelPair("mount", part.Mountpoint), formatFloat(usage.UsedPercent))
			}
		}
	}

	// 进程 / 僵尸进程数（非宝塔模式从 /proc 轻量计数；Windows 跳过）
	if runtime.GOOS != "windows" {
		procCount, zombieCount := countProcsLight()
		writeGauge("serverguard_processes", "进程总数", float64(procCount))
		writeGauge("serverguard_zombies", "僵尸进程数", float64(zombieCount))
	}

	// 紧急停止 / 维护窗口状态
	emergency := 0.0
	if a.safety != nil && a.safety.IsEmergencyStopped() {
		emergency = 1
	}
	writeGauge("serverguard_emergency_stop", "紧急停止状态 (0=正常, 1=已停止)", emergency)
	maintenance := 0.0
	if a.IsInMaintenance() {
		maintenance = 1
	}
	writeGauge("serverguard_maintenance_active", "维护窗口激活状态 (0=否, 1=是)", maintenance)

	// 未解决告警（按级别）
	if alerts, err := a.storage.GetUnresolvedAlerts(); err == nil {
		byLevel := map[string]int{}
		for _, al := range alerts {
			byLevel[strings.ToLower(string(al.Level))]++
		}
		fmt.Fprintf(&b, "# HELP serverguard_alerts_unresolved 未解决告警数\n# TYPE serverguard_alerts_unresolved gauge\n")
		levels := make([]string, 0, len(byLevel))
		for lv := range byLevel {
			levels = append(levels, lv)
		}
		sort.Strings(levels)
		for _, lv := range levels {
			fmt.Fprintf(&b, "serverguard_alerts_unresolved{%s} %d\n", labelPair("level", lv), byLevel[lv])
		}
		if len(levels) == 0 {
			b.WriteString("serverguard_alerts_unresolved 0\n")
		}
	}

	// 网站存活性与延迟
	if a.probe != nil {
		sites := a.probe.GetSites()
		fmt.Fprintf(&b, "# HELP serverguard_website_up 网站存活性 (0=宕机, 1=在线)\n# TYPE serverguard_website_up gauge\n")
		fmt.Fprintf(&b, "# HELP serverguard_website_latency_ms 网站响应延迟 (ms)\n# TYPE serverguard_website_latency_ms gauge\n")
		for _, s := range sites {
			labels := labelPair("site", s.Name) + "," + labelPair("url", s.URL)
			up := 0.0
			if s.Up {
				up = 1
			}
			fmt.Fprintf(&b, "serverguard_website_up{%s} %s\n", labels, formatFloat(up))
			fmt.Fprintf(&b, "serverguard_website_latency_ms{%s} %s\n", labels, formatFloat(float64(s.Latency.Milliseconds())))
		}
	}

	// 证书剩余天数
	if a.certGuard != nil {
		certs := a.certGuard.GetCerts()
		fmt.Fprintf(&b, "# HELP serverguard_cert_days_remaining 证书剩余有效天数\n# TYPE serverguard_cert_days_remaining gauge\n")
		for _, ci := range certs {
			fmt.Fprintf(&b, "serverguard_cert_days_remaining{%s} %d\n",
				labelPair("domain", ci.Domain), ci.DaysUntilExpiry)
		}
	}

	c.Header("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
	c.String(http.StatusOK, b.String())
}

// countProcsLight 通过 /proc 目录轻量统计进程数与僵尸进程数（不做 per-process syscall 风暴）。
func countProcsLight() (procCount, zombieCount int) {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return 0, 0
	}
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		if _, err := strconv.Atoi(entry.Name()); err != nil {
			continue
		}
		procCount++
		if statData, err := os.ReadFile("/proc/" + entry.Name() + "/stat"); err == nil {
			statStr := string(statData)
			if idx := strings.LastIndex(statStr, ")"); idx >= 0 && idx+1 < len(statStr) {
				state := strings.TrimSpace(statStr[idx+1:])
				if len(state) > 0 && (state[0] == 'Z' || state[0] == 'z') {
					zombieCount++
				}
			}
		}
	}
	return procCount, zombieCount
}

func formatFloat(v float64) string {
	return strconv.FormatFloat(v, 'f', 2, 64)
}
