package config

import (
	"fmt"
	"os"
	"path/filepath"
	"time"

	"gopkg.in/yaml.v3"
)

// CurrentSchemaVersion 当前配置 schema 版本
const CurrentSchemaVersion = 3

// MigrationFunc 单版本迁移函数
type MigrationFunc func(cfg *Config) error

// migrations 注册所有版本迁移路径
var migrations = map[int]MigrationFunc{
	1: migrateV1ToV2,
	2: migrateV2ToV3,
}

// Migrate 将配置从 from 版本迁移到 to 版本
// 迁移前自动备份配置文件
func Migrate(cfg *Config, configPath string, from, to int) error {
	if from == to {
		return nil
	}
	if from > to {
		return fmt.Errorf("不支持降级迁移: v%d → v%d", from, to)
	}

	// 迁移前备份
	if configPath != "" {
		if err := backupConfig(configPath, from); err != nil {
			return fmt.Errorf("迁移前备份失败: %w", err)
		}
	}

	// 逐版本迁移
	for v := from; v < to; v++ {
		migrateFn, ok := migrations[v]
		if !ok {
			return fmt.Errorf("无迁移路径: v%d → v%d", v, v+1)
		}
		if err := migrateFn(cfg); err != nil {
			return fmt.Errorf("迁移 v%d → v%d 失败: %w", v, v+1, err)
		}
		cfg.SchemaVersion = v + 1
	}

	return nil
}

// backupConfig 备份配置文件到 ~/.serverguard/config.backup.<version>.yaml
func backupConfig(configPath string, version int) error {
	data, err := os.ReadFile(configPath)
	if err != nil {
		return err
	}

	homeDir, err := os.UserHomeDir()
	if err != nil {
		return err
	}

	backupDir := filepath.Join(homeDir, ".serverguard")
	if err := os.MkdirAll(backupDir, 0750); err != nil {
		return err
	}

	backupPath := filepath.Join(backupDir, fmt.Sprintf("config.backup.v%d.%s.yaml", version, time.Now().Format("20060102-150405")))
	return os.WriteFile(backupPath, data, 0600)
}

// migrateV1ToV2 v1 → v2 迁移：新增安全扫描模块配置
func migrateV1ToV2(cfg *Config) error {
	// v2 新增了 W/X/Y/Z 安全扫描模块的配置节
	// 这些配置在 DefaultConfig 中已有默认值，无需特殊处理
	// 仅需确保新增字段有合理默认值
	if cfg.Agent.CollectInterval.Duration() == 0 {
		cfg.Agent.CollectInterval = Duration(10 * time.Second)
	}
	return nil
}

// migrateV2ToV3 v2 → v3 迁移：新增资源地板/证书错峰/告警升级/保留策略配置
func migrateV2ToV3(cfg *Config) error {
	if cfg.Safety.MaxDiskIOWaitPercent == 0 {
		cfg.Safety.MaxDiskIOWaitPercent = 50
	}
	if cfg.Safety.MinDiskAvailableMB == 0 {
		cfg.Safety.MinDiskAvailableMB = 500
	}
	if cfg.Safety.TrashRetentionDays == 0 {
		cfg.Safety.TrashRetentionDays = 7
	}
	if cfg.Log.RetentionDays == 0 {
		cfg.Log.RetentionDays = 30
	}
	return nil
}

// LoadWithMigration 加载配置并自动迁移到当前版本
func LoadWithMigration(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file: %w", err)
	}

	cfg := DefaultConfig()
	if err := yaml.Unmarshal(data, cfg); err != nil {
		return nil, fmt.Errorf("failed to parse config: %w", err)
	}

	// 检测并执行迁移
	if cfg.SchemaVersion < CurrentSchemaVersion {
		if err := Migrate(cfg, path, cfg.SchemaVersion, CurrentSchemaVersion); err != nil {
			return nil, fmt.Errorf("config migration failed: %w", err)
		}
		// 保存迁移后的配置
		if err := cfg.Save(path); err != nil {
			return nil, fmt.Errorf("failed to save migrated config: %w", err)
		}
	} else if cfg.SchemaVersion > CurrentSchemaVersion {
		return nil, fmt.Errorf("config schema version %d is newer than supported %d, please upgrade agent", cfg.SchemaVersion, CurrentSchemaVersion)
	}

	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("config validation failed: %w", err)
	}

	return cfg, nil
}
