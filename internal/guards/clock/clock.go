package clock

import (
	"context"
	"fmt"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/suoten/serverguard/internal/agent/eventbus"
	"github.com/suoten/serverguard/internal/types"
)

// ClockGuard implements Module N: Clock Guard
// Covers: clock drift detection (real chronyc parsing), sync suggestions, GB28181/JT808 protocol awareness
//
// SAFETY: Never auto-executes `chronyc makestep` or `w32tm /resync`.
// Time jumps can corrupt databases (MySQL replication, PostgreSQL transaction timestamps),
// break TLS certificate validation, and disrupt scheduled tasks.
// Instead, it parses the real drift value and provides precise remediation commands.
type ClockGuard struct {
	mu             sync.RWMutex
	eventBus       *eventbus.EventBus
	maxDrift       time.Duration
	protocolAware  bool
	lastDriftValue float64 // seconds, last measured drift
}

func New(bus *eventbus.EventBus) *ClockGuard {
	return &ClockGuard{
		eventBus:      bus,
		maxDrift:      500 * time.Millisecond, // 500ms threshold for alerting
		protocolAware: true,
	}
}

func (g *ClockGuard) Check(ctx context.Context) {
	if runtime.GOOS != "windows" {
		// Check chrony
		if output, err := exec.CommandContext(ctx, "chronyc", "tracking").Output(); err == nil {
			g.analyzeChrony(ctx, string(output))
		} else {
			// chrony not installed, try ntpdate or timedatectl
			g.checkTimedatectl(ctx)
		}
	} else {
		// Windows: check w32tm
		if output, err := exec.CommandContext(ctx, "w32tm", "/query", "/status").Output(); err == nil {
			g.analyzeW32tm(ctx, string(output))
		}
	}
}

// analyzeChrony parses `chronyc tracking` output to extract the real System offset.
// Example output:
//   Reference ID    : CA80E932 (ntp.aliyun.com)
//   Stratum         : 3
//   Ref time (UTC)  : Mon Aug 17 03:00:00 2025
//   System time     :   0.000123456 seconds fast of NTP time
//   Last offset     : +0.000123456 seconds
//   RMS offset      : 0.000123456 seconds
//   Frequency       : 5.123 ppm slow
//   ...
func (g *ClockGuard) analyzeChrony(ctx context.Context, output string) {
	if output == "" {
		return
	}

	g.mu.Lock()
	g.lastDriftValue = 0
	g.mu.Unlock()

	var systemOffsetSec float64
	var lastOffsetSec float64
	var found bool

	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(line)
		// "System time     :   0.000123456 seconds fast of NTP time"
		// "System time     :  -0.000123456 seconds slow of NTP time"
		if strings.HasPrefix(line, "System time") {
			offset := parseChronyOffset(line)
			if offset != 0 {
				systemOffsetSec = offset
				found = true
			}
		}
		if strings.HasPrefix(line, "Last offset") {
			offset := parseChronyOffset(line)
			if offset != 0 {
				lastOffsetSec = offset
			}
		}
	}

	if !found {
		return
	}

	absDrift := time.Duration(absFloat(systemOffsetSec) * float64(time.Second))

	g.mu.Lock()
	g.lastDriftValue = systemOffsetSec
	g.mu.Unlock()

	if absDrift > g.maxDrift {
		level := types.AlertWarning
		msg := fmt.Sprintf("检测到时钟漂移 %.3f 秒（阈值 %.3f 秒）", systemOffsetSec, g.maxDrift.Seconds())
		detail := fmt.Sprintf("系统时间偏移: %.6f 秒\n最近偏移: %.6f 秒\n\n"+
			"建议手动执行以下命令同步时间:\n"+
			"  sudo chronyc makestep\n\n"+
			"注意: 时间跳变可能影响 MySQL 主从复制、TLS 证书验证和定时任务，\n"+
			"请确认安全后手动执行。",
			systemOffsetSec, lastOffsetSec)

		if g.protocolAware {
			msg += "（GB28181/JT808协议对时间精度敏感，请优先处理）"
			detail += "\n\n⚠ GB28181/JT808 协议要求时间精度 < 1秒，请立即处理！"
			level = types.AlertError
		}

		// 检查 NTP 源是否正常
		if strings.Contains(output, "Not synchronised") || strings.Contains(output, "Cannot communicate") {
			level = types.AlertCritical
			detail += "\n\n⚠ NTP 源不可达！请检查:\n" +
				"  1. 防火墙是否放行 UDP 123 端口\n" +
				"  2. NTP 服务器是否可达: chronyc sources\n" +
				"  3. 备用 NTP: ntp.aliyun.com, ntp.tencent.com"
		}

		g.eventBus.PublishAlert(level, "clock", "时钟漂移", detail, "clock-drift-001")
	} else if absDrift > g.maxDrift/2 {
		// Early warning at half threshold
		g.eventBus.PublishAlert(types.AlertInfo, "clock",
			"时钟轻微漂移",
			fmt.Sprintf("系统时间偏移 %.3f 秒，在可接受范围内但呈增长趋势", systemOffsetSec),
			"clock-drift-001")
	}
}

// parseChronyOffset extracts the numeric offset from a chronyc line.
// e.g., "System time     :   0.000123456 seconds fast of NTP time" -> 0.000123456
//        "System time     :  -0.000123456 seconds slow of NTP time" -> -0.000123456
func parseChronyOffset(line string) float64 {
	// Find the colon, then parse the number after it
	idx := strings.Index(line, ":")
	if idx < 0 {
		return 0
	}
	rest := strings.TrimSpace(line[idx+1:])
	// "0.000123456 seconds fast of NTP time" or "-0.000123456 seconds slow of NTP time"
	parts := strings.Fields(rest)
	if len(parts) < 2 {
		return 0
	}
	val, err := strconv.ParseFloat(parts[0], 64)
	if err != nil {
		return 0
	}
	return val
}

func absFloat(v float64) float64 {
	if v < 0 {
		return -v
	}
	return v
}

// checkTimedatectl checks time sync status via timedatectl (systemd).
func (g *ClockGuard) checkTimedatectl(ctx context.Context) {
	output, err := exec.CommandContext(ctx, "timedatectl", "status").Output()
	if err != nil {
		return
	}
	s := string(output)

	// Check if NTP synchronized
	if strings.Contains(s, "NTP synchronized: no") || strings.Contains(s, "NTP service: inactive") {
		g.eventBus.PublishAlert(types.AlertWarning, "clock",
			"NTP 未同步",
			"系统 NTP 同步未启用或未同步。建议:\n"+
				"  1. 启用 NTP: sudo timedatectl set-ntp true\n"+
				"  2. 或安装 chrony: sudo apt install chrony  (Debian/Ubuntu)\n"+
				"             sudo yum install chrony  (CentOS/RHEL)\n"+
				"  3. 检查防火墙是否放行 UDP 123 端口",
			"clock-drift-001")
	}
}

func (g *ClockGuard) analyzeW32tm(ctx context.Context, output string) {
	if output == "" {
		return
	}

	// Parse w32tm output for time offset
	// "Source: ..." "The command completed successfully."
	// Look for error indicators
	if strings.Contains(strings.ToLower(output), "error") {
		g.eventBus.PublishAlert(types.AlertWarning, "clock",
			"Windows 时钟同步异常",
			"检测到 Windows 时间服务异常。建议手动执行:\n"+
				"  w32tm /resync\n"+
				"  w32tm /query /status\n\n"+
				"注意: 时间跳变可能影响数据库和证书验证，请确认后手动执行。",
			"clock-drift-001")
		return
	}

	// Try to get more precise offset via w32tm /query /status /verbose
	verboseOutput, err := exec.CommandContext(ctx, "w32tm", "/query", "/status", "/verbose").Output()
	if err == nil {
		vs := string(verboseOutput)
		// Look for "Phase offset" or similar
		for _, line := range strings.Split(vs, "\n") {
			line = strings.TrimSpace(line)
			if strings.Contains(strings.ToLower(line), "offset") {
				// Just report the raw info, don't auto-sync
				if strings.Contains(line, "error") {
					g.eventBus.PublishAlert(types.AlertWarning, "clock",
						"Windows 时钟漂移",
						fmt.Sprintf("w32tm 报告: %s\n\n建议手动执行: w32tm /resync", line),
						"clock-drift-001")
				}
				break
			}
		}
	}
}

// GetLastDrift returns the last measured drift in seconds.
func (g *ClockGuard) GetLastDrift() float64 {
	g.mu.RLock()
	defer g.mu.RUnlock()
	return g.lastDriftValue
}

// SetMaxDrift allows configuring the drift threshold.
func (g *ClockGuard) SetMaxDrift(d time.Duration) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.maxDrift = d
}

func contains(s, substr string) bool {
	return strings.Contains(s, substr)
}
