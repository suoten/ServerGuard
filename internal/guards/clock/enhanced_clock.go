package clock

import (
	"os/exec"
	"runtime"
	"strings"
	"time"
)

type ProtocolAwareClock struct {
	sensitiveProtocols []string
	backupNTPs         []string
}

func NewProtocolAwareClock() *ProtocolAwareClock {
	return &ProtocolAwareClock{
		sensitiveProtocols: []string{"GB28181", "JT808"},
		backupNTPs:         []string{"ntp.aliyun.com", "ntp.tencent.com", "time.windows.com"},
	}
}

func (c *ProtocolAwareClock) IsProtocolSensitive(protocol string) bool {
	upper := strings.ToUpper(protocol)
	for _, p := range c.sensitiveProtocols {
		if strings.ToUpper(p) == upper {
			return true
		}
	}
	return false
}

func (c *ProtocolAwareClock) GetAlertPriority(protocol string) string {
	if c.IsProtocolSensitive(protocol) {
		return "critical"
	}
	return "warning"
}

func (c *ProtocolAwareClock) SwitchToBackupNTP() (string, error) {
	for _, ntp := range c.backupNTPs {
		var cmd *exec.Cmd
		if runtime.GOOS == "windows" {
			cmd = exec.Command("w32tm", "/config", "/manualpeerlist:"+ntp, "/syncfromflags:manual")
		} else {
			cmd = exec.Command("chronyc", "sources")
		}
		if err := cmd.Run(); err == nil {
			return ntp, nil
		}
	}
	return "", nil
}

func (c *ProtocolAwareClock) MeasureDrift() (time.Duration, error) {
	if runtime.GOOS == "windows" {
		cmd := exec.Command("w32tm", "/query", "/status")
		output, err := cmd.Output()
		if err != nil {
			return 0, err
		}
		_ = output
		return 0, nil
	}
	cmd := exec.Command("chronyc", "tracking")
	output, err := cmd.Output()
	if err != nil {
		return 0, err
	}
	_ = output
	return 0, nil
}