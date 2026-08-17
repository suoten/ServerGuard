package platform

import (
	"context"
	"time"

	"github.com/suoten/serverguard/internal/types"
)

// ServiceManager 抽象跨平台服务管理（Linux systemd / Windows Service）
type ServiceManager interface {
	Start(ctx context.Context, name string) error
	Stop(ctx context.Context, name string) error
	Restart(ctx context.Context, name string) error
	Status(ctx context.Context, name string) (ServiceStatus, error)
	Enable(ctx context.Context, name string) error
	Disable(ctx context.Context, name string) error
	List(ctx context.Context) ([]ServiceInfo, error)
	Register(ctx context.Context, name string, config ServiceConfig) error
	Unregister(ctx context.Context, name string) error
	IsManaged(ctx context.Context, name string) (bool, error)
}

// ServiceStatus 服务状态
type ServiceStatus string

const (
	ServiceStatusRunning  ServiceStatus = "running"
	ServiceStatusStopped  ServiceStatus = "stopped"
	ServiceStatusFailed   ServiceStatus = "failed"
	ServiceStatusUnknown  ServiceStatus = "unknown"
	ServiceStatusDegraded ServiceStatus = "degraded"
)

// ServiceInfo 服务信息
type ServiceInfo struct {
	Name        string        `json:"name"`
	DisplayName string        `json:"display_name"`
	Status      ServiceStatus `json:"status"`
	Enabled     bool          `json:"enabled"`
	PID         int32         `json:"pid"`
	Uptime      time.Duration `json:"uptime"`
	Manager     string        `json:"manager"` // systemd, windows-service, docker, supervisor, bare
}

// ServiceConfig 服务注册配置
type ServiceConfig struct {
	Name        string            `json:"name"`
	DisplayName string            `json:"display_name"`
	Command     string            `json:"command"`
	Args        []string          `json:"args"`
	WorkDir     string            `json:"work_dir"`
	Env         map[string]string `json:"env"`
	AutoStart   bool              `json:"auto_start"`
	Restart     string            `json:"restart"` // always, on-failure, no
}

// ProcessCollector 抽象跨平台进程采集与控制
type ProcessCollector interface {
	List(ctx context.Context, maxCount int) ([]types.ProcessInfo, error)
	Get(ctx context.Context, pid int32) (types.ProcessInfo, error)
	Kill(ctx context.Context, pid int32, signal ProcessSignal) error
	Nice(ctx context.Context, pid int32, priority int) error
	Children(ctx context.Context, pid int32) ([]int32, error)
	IsZombie(ctx context.Context, pid int32) (bool, error)
	IsKernelThread(ctx context.Context, pid int32) (bool, error)
	OpenFiles(ctx context.Context, pid int32) (int32, error)
	Connections(ctx context.Context, pid int32) ([]ConnectionInfo, error)
}

// ProcessSignal 进程信号
type ProcessSignal string

const (
	SignalSIGTERM ProcessSignal = "SIGTERM"
	SignalSIGKILL ProcessSignal = "SIGKILL"
	SignalSIGHUP  ProcessSignal = "SIGHUP"
	SignalSIGINT  ProcessSignal = "SIGINT"
)

// ConnectionInfo 网络连接信息
type ConnectionInfo struct {
	LocalAddr  string `json:"local_addr"`
	LocalPort  uint16 `json:"local_port"`
	RemoteAddr string `json:"remote_addr"`
	RemotePort uint16 `json:"remote_port"`
	Status     string `json:"status"`
	Protocol   string `json:"protocol"`
	PID        int32  `json:"pid"`
}

// LogRotator 抽象跨平台日志轮转
type LogRotator interface {
	Rotate(ctx context.Context, path string, opts RotateOptions) error
	Compress(ctx context.Context, path string) error
	Watch(ctx context.Context, path string, opts WatchOptions) (<-chan FileEvent, error)
	Unwatch(path string) error
	ListWatched() []string
}

// RotateOptions 轮转选项
type RotateOptions struct {
	MaxSize     int64  `json:"max_size"`  // bytes
	MaxFiles    int    `json:"max_files"` // 保留份数
	Compress    bool   `json:"compress"`
	Mode        string `json:"mode"` // copytruncate, rename
	Owner       string `json:"owner"`
	Group       string `json:"group"`
	Permissions uint32 `json:"permissions"`
}

// WatchOptions 文件监控选项
type WatchOptions struct {
	Recursive bool `json:"recursive"`
}

// FileEvent 文件事件
type FileEvent struct {
	Path      string    `json:"path"`
	Operation string    `json:"operation"` // create, modify, delete, rename
	Timestamp time.Time `json:"timestamp"`
	Size      int64     `json:"size"`
}

// FileWatcher 抽象跨平台文件变更监控（inotify / ReadDirectoryChangesW）
type FileWatcher interface {
	Watch(ctx context.Context, path string, recursive bool) (<-chan FileEvent, error)
	Unwatch(path string) error
	ListWatched() []string
	Close() error
}

// FirewallManager 抽象跨平台防火墙（iptables/nftables / netsh）
type FirewallManager interface {
	BanIP(ctx context.Context, ip string, opts BanOptions) error
	UnbanIP(ctx context.Context, ip string) error
	IsBanned(ctx context.Context, ip string) (bool, error)
	ListBanned(ctx context.Context) ([]BanEntry, error)
	RateLimit(ctx context.Context, ip string, rate int, opts RateLimitOptions) error
	RemoveRateLimit(ctx context.Context, ip string) error
	ClearAll(ctx context.Context) error
}

// BanOptions 封禁选项
type BanOptions struct {
	Duration   time.Duration `json:"duration"` // 0 = permanent
	Port       int           `json:"port"`     // 0 = all ports
	Protocol   string        `json:"protocol"` // tcp, udp, any
	Reason     string        `json:"reason"`
	RulePrefix string        `json:"rule_prefix"` // 规则前缀，用于区分来源模块
}

// RateLimitOptions 限速选项
type RateLimitOptions struct {
	Burst    int    `json:"burst"`
	Port     int    `json:"port"`
	Protocol string `json:"protocol"`
}

// BanEntry 封禁记录
type BanEntry struct {
	IP        string    `json:"ip"`
	Port      int       `json:"port"`
	Protocol  string    `json:"protocol"`
	Reason    string    `json:"reason"`
	BannedAt  time.Time `json:"banned_at"`
	ExpiresAt time.Time `json:"expires_at"`
	Source    string    `json:"source"` // 来源模块
}

// NetworkManager 抽象跨平台网络管理
type NetworkManager interface {
	ListInterfaces(ctx context.Context) ([]NetInterface, error)
	RestartNetworking(ctx context.Context) error
	SetDNS(ctx context.Context, servers []string) error
	GetDNS(ctx context.Context) ([]string, error)
	Ping(ctx context.Context, host string, timeout time.Duration) (bool, time.Duration, error)
	TraceRoute(ctx context.Context, host string, maxHops int) ([]string, error)
	ListeningPorts(ctx context.Context) ([]PortInfo, error)
}

// NetInterface 网络接口
type NetInterface struct {
	Name       string   `json:"name"`
	IPs        []string `json:"ips"`
	MAC        string   `json:"mac"`
	MTU        int      `json:"mtu"`
	Up         bool     `json:"up"`
	IsLoopback bool     `json:"is_loopback"`
}

// PortInfo 端口信息
type PortInfo struct {
	Port      int32  `json:"port"`
	Protocol  string `json:"protocol"`
	Process   string `json:"process"`
	PID       int32  `json:"pid"`
	LocalAddr string `json:"local_addr"`
	State     string `json:"state"`
}

// PlatformDeps 平台依赖集合
type PlatformDeps struct {
	ServiceMgr  ServiceManager
	ProcessColl ProcessCollector
	LogRotator  LogRotator
	FileWatcher FileWatcher
	FirewallMgr FirewallManager
	NetworkMgr  NetworkManager
}

// NewPlatformDeps 根据运行时操作系统创建平台依赖集合
func NewPlatformDeps() *PlatformDeps {
	return newPlatformDepsImpl()
}
