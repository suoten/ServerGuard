package fd

import (
	"fmt"
	"os/exec"
	"runtime"
	"strings"
)

type UlimitAdvisor struct{}

func NewUlimitAdvisor() *UlimitAdvisor { return &UlimitAdvisor{} }

type UlimitAdvice struct {
	CurrentSoft int    `json:"current_soft"`
	CurrentHard int    `json:"current_hard"`
	Recommended int    `json:"recommended"`
	NeedsChange bool   `json:"needs_change"`
	Suggestion  string `json:"suggestion"`
}

func (a *UlimitAdvisor) Analyze() (*UlimitAdvice, error) {
	if runtime.GOOS == "windows" {
		return &UlimitAdvice{
			CurrentSoft: 16384,
			CurrentHard: 16384,
			Recommended: 65535,
			Suggestion:  "Windows 默认句柄数通常足够，如遇问题调整注册表",
		}, nil
	}

	cmd := exec.Command("sh", "-c", "ulimit -n")
	output, err := cmd.Output()
	if err != nil {
		return nil, err
	}

	var soft int
	fmt.Sscanf(strings.TrimSpace(string(output)), "%d", &soft)

	recommended := 65535
	needsChange := soft < recommended

	suggestion := ""
	if needsChange {
		suggestion = fmt.Sprintf("当前软限制 %d 低于推荐值 %d，建议修改 /etc/security/limits.conf:\n"+
			"* soft nofile %d\n* hard nofile %d", soft, recommended, recommended, recommended)
	}

	return &UlimitAdvice{
		CurrentSoft: soft,
		CurrentHard: soft,
		Recommended: recommended,
		NeedsChange: needsChange,
		Suggestion:  suggestion,
	}, nil
}

func (a *UlimitAdvisor) CheckSystemLevel() (int, error) {
	if runtime.GOOS == "windows" {
		return 16384, nil
	}
	cmd := exec.Command("cat", "/proc/sys/fs/file-max")
	output, err := cmd.Output()
	if err != nil {
		return 0, err
	}
	var max int
	fmt.Sscanf(strings.TrimSpace(string(output)), "%d", &max)
	return max, nil
}
