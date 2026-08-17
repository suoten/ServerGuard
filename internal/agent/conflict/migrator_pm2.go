package conflict

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"strings"

	"github.com/google/uuid"
	"github.com/suoten/serverguard/internal/types"
)

// PM2Migrator PM2 配置迁移器。
// 解析 PM2 ecosystem 配置文件（JSON 格式）或通过 pm2 jlist 获取当前进程列表。
type PM2Migrator struct{}

func (m *PM2Migrator) Name() string { return "pm2" }

// pm2Process PM2 进程配置
type pm2Process struct {
	Name        string `json:"name"`
	Script      string `json:"script"`
	Cwd         string `json:"cwd"`
	ExecMode    string `json:"exec_mode"`
	Instances   int    `json:"instances"`
	AutoRestart bool   `json:"autorestart"`
	Args        string `json:"args"`
}

// pm2Ecosystem PM2 ecosystem 配置文件结构
type pm2Ecosystem struct {
	Apps []pm2Process `json:"apps"`
}

// Parse 解析 PM2 配置。
// configPath 可以是：
//   - ecosystem.config.json 文件
//   - 空字符串：通过 `pm2 jlist` 获取当前运行进程
func (m *PM2Migrator) Parse(configPath string) ([]types.GuardTarget, error) {
	var processes []pm2Process

	if configPath == "" {
		// 通过 pm2 jlist 获取当前进程
		cmd := exec.Command("pm2", "jlist")
		output, err := cmd.Output()
		if err != nil {
			return nil, fmt.Errorf("pm2 jlist: %w", err)
		}
		if err := json.Unmarshal(output, &processes); err != nil {
			return nil, fmt.Errorf("parse pm2 jlist: %w", err)
		}
	} else {
		data, err := os.ReadFile(configPath)
		if err != nil {
			return nil, fmt.Errorf("read pm2 config: %w", err)
		}

		// 尝试解析为 ecosystem 格式
		var ecosystem pm2Ecosystem
		if err := json.Unmarshal(data, &ecosystem); err == nil && len(ecosystem.Apps) > 0 {
			processes = ecosystem.Apps
		} else {
			// 尝试解析为进程数组
			if err := json.Unmarshal(data, &processes); err != nil {
				return nil, fmt.Errorf("parse pm2 config: %w", err)
			}
		}
	}

	var targets []types.GuardTarget
	for _, proc := range processes {
		target := types.GuardTarget{
			ID:            uuid.New().String(),
			Name:          proc.Name,
			Type:          types.TargetBare,
			ProcessName:   proc.Name,
			Enabled:       true,
			RestartPolicy: types.DefaultRestartPolicy(),
			Tags:          []string{"migrated-from-pm2"},
		}

		// 构建启动命令
		cmd := proc.Script
		if proc.Args != "" {
			cmd += " " + proc.Args
		}
		target.Command = cmd

		if !proc.AutoRestart {
			target.RestartPolicy.MaxRetries = 0
		}

		if proc.ExecMode == "cluster" {
			target.Tags = append(target.Tags, "pm2-cluster")
		}

		targets = append(targets, target)
	}

	return targets, nil
}

// Ensure strings is used
var _ = strings.TrimSpace
