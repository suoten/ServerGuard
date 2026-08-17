package conflict

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"github.com/google/uuid"
	"github.com/suoten/serverguard/internal/types"
)

// SystemdMigrator systemd 配置迁移器。
// 解析 /etc/systemd/system/*.service 或 /lib/systemd/system/*.service unit 文件。
type SystemdMigrator struct{}

func (m *SystemdMigrator) Name() string { return "systemd" }

// Parse 解析 systemd unit 文件，提取服务守护目标。
// 支持 unit 文件或包含 unit 文件的目录。
func (m *SystemdMigrator) Parse(configPath string) ([]types.GuardTarget, error) {
	var configs []string

	info, err := os.Stat(configPath)
	if err != nil {
		return nil, fmt.Errorf("systemd config path: %w", err)
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
			if strings.HasSuffix(name, ".service") {
				configs = append(configs, filepath.Join(configPath, name))
			}
		}
	} else {
		configs = append(configs, configPath)
	}

	var targets []types.GuardTarget
	execStartRe := regexp.MustCompile(`ExecStart=(.+?)(?:\n|$)`)
	execStopRe := regexp.MustCompile(`ExecStop=(.+?)(?:\n|$)`)
	restartRe := regexp.MustCompile(`Restart=(\w+)`)
	portRe := regexp.MustCompile(`#.*?port[:\s]+(\d+)`)

	for _, cfgFile := range configs {
		data, err := os.ReadFile(cfgFile)
		if err != nil {
			continue
		}
		content := string(data)

		// 跳过非 service 类型
		if !strings.Contains(content, "[Service]") && !strings.Contains(content, "[Unit]") {
			continue
		}

		serviceName := strings.TrimSuffix(filepath.Base(cfgFile), ".service")

		target := types.GuardTarget{
			ID:            uuid.New().String(),
			Name:          serviceName,
			Type:          types.TargetSystemd,
			Enabled:       true,
			RestartPolicy: types.DefaultRestartPolicy(),
			Tags:          []string{"migrated-from-systemd"},
		}

		if sm := execStartRe.FindStringSubmatch(content); sm != nil {
			target.Command = strings.TrimSpace(sm[1])
		}
		if sm := execStopRe.FindStringSubmatch(content); sm != nil {
			target.StopCommand = strings.TrimSpace(sm[1])
		}
		if sm := restartRe.FindStringSubmatch(content); sm != nil {
			if sm[1] == "no" {
				target.RestartPolicy.MaxRetries = 0
			}
		}
		if sm := portRe.FindStringSubmatch(content); sm != nil {
			if port, err := strconv.Atoi(sm[1]); err == nil {
				target.Port = port
			}
		}

		targets = append(targets, target)
	}

	return targets, nil
}
