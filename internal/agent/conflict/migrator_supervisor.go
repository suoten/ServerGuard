package conflict

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/google/uuid"
	"github.com/suoten/serverguard/internal/types"
	"gopkg.in/yaml.v3"
)

// SupervisorMigrator supervisor 配置迁移器。
// 解析 /etc/supervisor/conf.d/*.conf 中的 [program:x] 段。
type SupervisorMigrator struct{}

func (m *SupervisorMigrator) Name() string { return "supervisor" }

// supervisorProgram supervisor [program:x] 段配置
type supervisorProgram struct {
	Name          string `yaml:"name"`
	Command       string `yaml:"command"`
	ProcessName   string `yaml:"process_name"`
	AutoStart     string `yaml:"autostart"`
	AutoRestart   string `yaml:"autorestart"`
	StartSecs     string `yaml:"startsecs"`
	StopSignal    string `yaml:"stopsignal"`
	StdoutLogfile string `yaml:"stdout_logfile"`
}

// Parse 解析 supervisor 配置文件（INI 格式 [program:x] 段）。
func (m *SupervisorMigrator) Parse(configPath string) ([]types.GuardTarget, error) {
	var configs []string

	info, err := os.Stat(configPath)
	if err != nil {
		return nil, fmt.Errorf("supervisor config path: %w", err)
	}

	if info.IsDir() {
		entries, err := os.ReadDir(configPath)
		if err != nil {
			return nil, err
		}
		for _, entry := range entries {
			if entry.IsDir() {
				continue
			}
			name := entry.Name()
			if strings.HasSuffix(name, ".conf") || strings.HasSuffix(name, ".ini") {
				configs = append(configs, filepath.Join(configPath, name))
			}
		}
	} else {
		configs = append(configs, configPath)
	}

	var targets []types.GuardTarget

	for _, cfgFile := range configs {
		data, err := os.ReadFile(cfgFile)
		if err != nil {
			continue
		}

		programs := parseSupervisorINI(string(data))
		for _, prog := range programs {
			target := types.GuardTarget{
				ID:            uuid.New().String(),
				Name:          prog.Name,
				Type:          types.TargetBare,
				Command:       prog.Command,
				ProcessName:   prog.Name,
				Enabled:       prog.AutoStart != "false",
				RestartPolicy: types.DefaultRestartPolicy(),
				Tags:          []string{"migrated-from-supervisor"},
			}
			if prog.AutoRestart == "false" {
				target.RestartPolicy.MaxRetries = 0
			}
			targets = append(targets, target)
		}
	}

	return targets, nil
}

// parseSupervisorINI 解析 supervisor INI 格式配置，提取 [program:x] 段。
func parseSupervisorINI(content string) []supervisorProgram {
	var programs []supervisorProgram
	var current *supervisorProgram

	for _, line := range strings.Split(content, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}

		if strings.HasPrefix(line, "[program:") {
			if current != nil {
				programs = append(programs, *current)
			}
			name := strings.TrimSuffix(strings.TrimPrefix(line, "[program:"), "]")
			current = &supervisorProgram{Name: name}
			continue
		}

		if current == nil {
			continue
		}

		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			continue
		}
		key := strings.TrimSpace(parts[0])
		val := strings.TrimSpace(parts[1])

		switch key {
		case "command":
			current.Command = val
		case "process_name":
			current.ProcessName = val
		case "autostart":
			current.AutoStart = val
		case "autorestart":
			current.AutoRestart = val
		case "startsecs":
			current.StartSecs = val
		case "stopsignal":
			current.StopSignal = val
		case "stdout_logfile":
			current.StdoutLogfile = val
		}
	}
	if current != nil {
		programs = append(programs, *current)
	}
	return programs
}

// Ensure yaml.v3 is used (for potential future YAML config support)
var _ = yaml.Marshal
