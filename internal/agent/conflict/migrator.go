package conflict

import (
	"github.com/suoten/serverguard/internal/types"
)

// ConfigMigrator 配置迁移器接口。
// 各进程管理工具（monit/supervisor/systemd/baota/pm2）实现此接口，
// 将其配置解析为统一的 GuardTarget 列表，批量导入 ServerGuard。
type ConfigMigrator interface {
	Name() string
	Parse(configPath string) ([]types.GuardTarget, error)
}

// GetAllMigrators 返回所有已实现的配置迁移器。
func GetAllMigrators() []ConfigMigrator {
	return []ConfigMigrator{
		&MonitMigrator{},
		&SupervisorMigrator{},
		&SystemdMigrator{},
		&BaotaMigrator{},
		&PM2Migrator{},
	}
}

// GetMigrator 按名称获取迁移器。
func GetMigrator(name string) ConfigMigrator {
	for _, m := range GetAllMigrators() {
		if m.Name() == name {
			return m
		}
	}
	return nil
}
