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

// MonitMigrator monit 配置迁移器。
// 解析 /etc/monit/monitrc 或 /etc/monit/conf.d/*.conf 中的 check 进程定义。
type MonitMigrator struct{}

func (m *MonitMigrator) Name() string { return "monit" }

// Parse 解析 monit 配置文件，提取进程守护目标。
// monit 语法示例：
//
//	check process nginx with pidfile /var/run/nginx.pid
//	  start program = "/usr/sbin/nginx"
//	  stop program = "/usr/sbin/nginx -s stop"
//	  if failed port 80 then restart
func (m *MonitMigrator) Parse(configPath string) ([]types.GuardTarget, error) {
	var configs []string

	info, err := os.Stat(configPath)
	if err != nil {
		return nil, fmt.Errorf("monit config path: %w", err)
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
			if strings.HasSuffix(name, ".conf") || strings.HasSuffix(name, ".monitrc") {
				configs = append(configs, filepath.Join(configPath, name))
			}
		}
	} else {
		configs = append(configs, configPath)
	}

	var targets []types.GuardTarget
	checkProcessRe := regexp.MustCompile(`check\s+process\s+(\S+)\s+with\s+pidfile\s+(\S+)`)
	startProgRe := regexp.MustCompile(`start\s+program\s*=\s*"([^"]+)"`)
	stopProgRe := regexp.MustCompile(`stop\s+program\s*=\s*"([^"]+)"`)
	portRe := regexp.MustCompile(`if\s+failed\s+port\s+(\d+)`)

	for _, cfgFile := range configs {
		data, err := os.ReadFile(cfgFile)
		if err != nil {
			continue
		}
		content := string(data)

		matches := checkProcessRe.FindAllStringSubmatch(content, -1)
		for _, match := range matches {
			name := match[1]
			pidfile := match[2]

			target := types.GuardTarget{
				ID:            uuid.New().String(),
				Name:          name,
				Type:          types.TargetBare,
				ProcessName:   name,
				Enabled:       true,
				RestartPolicy: types.DefaultRestartPolicy(),
				Tags:          []string{"migrated-from-monit"},
			}
			_ = pidfile

			if sm := startProgRe.FindStringSubmatch(content); sm != nil {
				target.Command = sm[1]
			}
			if sm := stopProgRe.FindStringSubmatch(content); sm != nil {
				target.StopCommand = sm[1]
			}
			if sm := portRe.FindStringSubmatch(content); sm != nil {
				if port, err := strconv.Atoi(sm[1]); err == nil {
					target.Port = port
				}
			}

			targets = append(targets, target)
		}
	}

	return targets, nil
}
