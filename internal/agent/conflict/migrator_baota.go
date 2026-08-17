package conflict

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/google/uuid"
	"github.com/suoten/serverguard/internal/types"
)

// BaotaMigrator 宝塔面板配置迁移器。
// 解析宝塔管理的服务配置（/www/server/panel/data/ 下的 JSON 配置文件）。
type BaotaMigrator struct{}

func (m *BaotaMigrator) Name() string { return "baota" }

// baotaSiteConfig 宝塔站点配置 JSON 结构（简化）
type baotaSiteConfig struct {
	Name      string `json:"name"`
	Path      string `json:"path"`
	Port      int    `json:"port"`
	PS        string `json:"ps"`
	Status    string `json:"status"`
	SSL       bool   `json:"ssl"`
	ProxyName string `json:"proxy_name"`
}

// Parse 解析宝塔配置。
// configPath 可以是：
//   - /www/server/panel/data/ 目录（扫描所有站点配置）
//   - 单个 JSON 配置文件
func (m *BaotaMigrator) Parse(configPath string) ([]types.GuardTarget, error) {
	var configs []string

	info, err := os.Stat(configPath)
	if err != nil {
		return nil, fmt.Errorf("baota config path: %w", err)
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
			if strings.HasSuffix(name, ".json") {
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

		// 尝试解析为单个站点配置
		var site baotaSiteConfig
		if err := json.Unmarshal(data, &site); err == nil && site.Name != "" {
			target := baotaSiteToTarget(site)
			targets = append(targets, target)
			continue
		}

		// 尝试解析为站点列表
		var sites []baotaSiteConfig
		if err := json.Unmarshal(data, &sites); err == nil {
			for _, s := range sites {
				targets = append(targets, baotaSiteToTarget(s))
			}
		}
	}

	return targets, nil
}

func baotaSiteToTarget(site baotaSiteConfig) types.GuardTarget {
	target := types.GuardTarget{
		ID:            uuid.New().String(),
		Name:          site.Name,
		Type:          types.TargetHTTP,
		Port:          site.Port,
		Enabled:       site.Status != "stop",
		RestartPolicy: types.DefaultRestartPolicy(),
		Tags:          []string{"migrated-from-baota"},
	}
	if site.Path != "" {
		target.HealthCheck = fmt.Sprintf("http://127.0.0.1:%d/", site.Port)
	}
	if site.PS != "" {
		target.Tags = append(target.Tags, site.PS)
	}
	return target
}
