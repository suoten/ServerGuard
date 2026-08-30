package config

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// Duration 是一个自定义时间类型，支持 YAML 中 "30s"、"5m"、"1h" 等字符串格式，
// 也支持纯整数（视为秒）。
// 解决 time.Duration 底层为 int64 纳秒，yaml.v3 无法解析 "30s" 字符串的问题。
type Duration time.Duration

// UnmarshalYAML 实现 yaml.Unmarshaler 接口。
// 支持以下格式：
//   - "30s", "5m", "1h" 等带单位的字符串
//   - 纯整数 5（视为 5 秒）
//   - 纯浮点数 1.5（视为 1.5 秒）
//   - 带引号的字符串 "30s"
func (d *Duration) UnmarshalYAML(value *yaml.Node) error {
	// 先尝试作为字符串解析
	var s string
	if err := value.Decode(&s); err == nil {
		// 尝试 time.ParseDuration（处理 "30s", "5m", "1h" 等）
		parsed, err := time.ParseDuration(s)
		if err == nil {
			*d = Duration(parsed)
			return nil
		}
		// ParseDuration 失败时，尝试将字符串作为数字解析（如 "5" -> 5 秒）
		if i, err2 := strconv.Atoi(s); err2 == nil {
			*d = Duration(time.Duration(i) * time.Second)
			return nil
		}
		if f, err2 := strconv.ParseFloat(s, 64); err2 == nil {
			*d = Duration(time.Duration(f) * time.Second)
			return nil
		}
		return fmt.Errorf("invalid duration '%s': %w", s, err)
	}
	// 尝试作为整数解析（视为秒）
	var i int
	if err := value.Decode(&i); err == nil {
		*d = Duration(time.Duration(i) * time.Second)
		return nil
	}
	// 尝试作为浮点数解析（视为秒）
	var f float64
	if err := value.Decode(&f); err == nil {
		*d = Duration(time.Duration(f) * time.Second)
		return nil
	}
	return fmt.Errorf("cannot parse duration from %v", value.Value)
}

// MarshalYAML 实现 yaml.Marshaler 接口，输出为字符串格式。
func (d Duration) MarshalYAML() (interface{}, error) {
	return time.Duration(d).String(), nil
}

// Duration 返回标准的 time.Duration 类型。
func (d Duration) Duration() time.Duration {
	return time.Duration(d)
}

// Config represents the main ServerGuard configuration.
type Config struct {
	SchemaVersion int             `yaml:"schema_version"`
	Agent         AgentConfig     `yaml:"agent"`
	Storage       StorageConfig   `yaml:"storage"`
	Collectors    CollectorConfig `yaml:"collectors"`
	Rules         RulesConfig     `yaml:"rules"`
	Safety        SafetyConfig    `yaml:"safety"`
	Notify        NotifyConfig    `yaml:"notify"`
	Web           WebConfig       `yaml:"web"`
	Hub           HubConfig       `yaml:"hub"`
	Cert          CertConfig      `yaml:"cert"`
	Log           LogGuardConfig  `yaml:"log"`
	Security      SecurityConfig  `yaml:"security"`
	Database      DatabaseConfig  `yaml:"database"`
	Docker        DockerConfig    `yaml:"docker"`
	System        SystemConfig    `yaml:"system"`
	Network       NetworkConfig   `yaml:"network"`
	Offline       OfflineConfig   `yaml:"offline"`
	Baota         BaotaConfig     `yaml:"baota"`
	Upgrade       UpgradeConfig   `yaml:"upgrade"`
	AI            AIConfig        `yaml:"ai"`
}

// AIConfig holds LLM enhancer settings.
type AIConfig struct {
	Enabled         bool   `yaml:"enabled" json:"enabled"`
	Provider        string `yaml:"provider" json:"provider"`
	APIKey          string `yaml:"api_key" json:"apiKey"`
	APIBase         string `yaml:"api_base" json:"apiBase"`
	Model           string `yaml:"model" json:"model"`
	HumanizeAlert   bool   `yaml:"humanize_alert" json:"humanizeAlert"`
	WeeklyReport    bool   `yaml:"weekly_report" json:"weeklyReport"`
	ExplainIncident bool   `yaml:"explain_incident" json:"explainIncident"`
}

// AgentConfig holds agent-level settings.
type AgentConfig struct {
	ID              string   `yaml:"id"`
	Name            string   `yaml:"name"`
	DataDir         string   `yaml:"data_dir"`
	LogLevel        string   `yaml:"log_level"` // debug, info, warn, error
	CollectInterval Duration `yaml:"collect_interval"`
	MaxMemoryMB     int      `yaml:"max_memory_mb"`
	MaxCPUPercent   int      `yaml:"max_cpu_percent"`
	LearnMode       bool     `yaml:"learn_mode"` // first week: only alert, no action
	LearnModeDays   int      `yaml:"learn_mode_days"`
	EmergencyStop   bool     `yaml:"emergency_stop"`
	// TrustAutoConfirm 信任演化：近 7 天确认执行 ≥8 次且成功率 100% 的规则
	// 自动跳过人工确认（任一失败立即恢复确认）。关闭后所有确认类规则永远等待用户。
	TrustAutoConfirm bool `yaml:"trust_auto_confirm"`
}

// StorageConfig holds database settings.
type StorageConfig struct {
	Path                  string   `yaml:"path"`
	EncryptionKey         string   `yaml:"encryption_key"`
	MaxSizeMB             int      `yaml:"max_size_mb"`
	VacuumInterval        Duration `yaml:"vacuum_interval"`
	WalCheckpointInterval Duration `yaml:"wal_checkpoint_interval"`
	BackupCount           int      `yaml:"backup_count"`
}

// CollectorConfig holds data collection settings.
type CollectorConfig struct {
	EnableProcesses   bool `yaml:"enable_processes"`
	EnableDisks       bool `yaml:"enable_disks"`
	EnableNetwork     bool `yaml:"enable_network"`
	EnableGPU         bool `yaml:"enable_gpu"`
	EnableTemperature bool `yaml:"enable_temperature"`
	EnableFD          bool `yaml:"enable_fd"`
	ProcessMaxCount   int  `yaml:"process_max_count"`
	InotifyMaxWatches int  `yaml:"inotify_max_watches"`
}

// RulesConfig holds rule engine settings.
type RulesConfig struct {
	ConfigPath      string   `yaml:"config_path"`
	MatchTimeout    Duration `yaml:"match_timeout"`
	MaxRules        int      `yaml:"max_rules"`
	DefaultCooldown Duration `yaml:"default_cooldown"`
}

// SafetyConfig holds safety mechanism settings.
type SafetyConfig struct {
	KillBudgetHourly            int      `yaml:"kill_budget_hourly"`
	KillBudgetDaily             int      `yaml:"kill_budget_daily"`
	KillMinInterval             Duration `yaml:"kill_min_interval"`
	CircuitBreakerThreshold     int      `yaml:"circuit_breaker_threshold"`
	CircuitBreakerResetDuration Duration `yaml:"circuit_breaker_reset_duration"`
	MinAvailableMemoryMB        int      `yaml:"min_available_memory_mb"`
	MaxLoadFactor               float64  `yaml:"max_load_factor"` // cores * this = max load
	MaxDiskIOWaitPercent        float64  `yaml:"max_disk_io_wait_percent"`
	MinDiskAvailableMB          int      `yaml:"min_disk_available_mb"`
	ObservationWindow           Duration `yaml:"observation_window"`
	CascadeSuppression          bool     `yaml:"cascade_suppression"`
	WhitelistPath               string   `yaml:"whitelist_path"`
	TrashDir                    string   `yaml:"trash_dir"`
	TrashRetentionDays          int      `yaml:"trash_retention_days"`
}

// NotifyConfig holds notification channel settings.
type NotifyConfig struct {
	Channels []ChannelConfig `yaml:"channels"`
	Silence  SilenceConfig   `yaml:"silence"`
	// Simplified fields for easy setup
	WxPusherAppToken string `yaml:"wxpusher_app_token"` // WxPusher appToken, get from wxpusher.zjiecode.com
	WxPusherUID      string `yaml:"wxpusher_uid"`       // WxPusher UID, get by scanning app QR code
	SMTPHost         string `yaml:"smtp_host"`          // e.g. smtp.gmail.com
	SMTPPort         string `yaml:"smtp_port"`          // e.g. 587
	SMTPUser         string `yaml:"smtp_user"`          // sender email
	SMTPPassword     string `yaml:"smtp_password"`      // sender password/app password
	EmailTo          string `yaml:"email_to"`           // recipient email(s), comma separated
	DigestEnabled    bool   `yaml:"digest_enabled"`     // daily digest
	DigestHour       int    `yaml:"digest_hour"`        // 8 = 8:00 AM
}

type ChannelConfig struct {
	Name    string                 `yaml:"name"`
	Type    string                 `yaml:"type"` // email, webhook, wechat, dingtalk, feishu, slack, telegram, sms
	Enabled bool                   `yaml:"enabled"`
	Config  map[string]interface{} `yaml:"config"`
}

type SilenceConfig struct {
	Enabled        bool            `yaml:"enabled"`
	SilencePeriods []SilencePeriod `yaml:"silence_periods"`
}

type SilencePeriod struct {
	StartHour int      `yaml:"start_hour"`
	EndHour   int      `yaml:"end_hour"`
	Levels    []string `yaml:"levels"` // silence only these levels
}

// WebConfig holds web panel settings.
type WebConfig struct {
	Enabled     bool     `yaml:"enabled"`
	Listen      string   `yaml:"listen"` // e.g., "127.0.0.1:8443"
	TLSCert     string   `yaml:"tls_cert"`
	TLSKey      string   `yaml:"tls_key"`
	AuthEnabled bool     `yaml:"auth_enabled"`
	Username    string   `yaml:"username"`
	Password    string   `yaml:"password"`
	JWTSecret   string   `yaml:"jwt_secret"`
	CORSOrigins []string `yaml:"cors_origins"`
}

// HubConfig holds Hub connection settings.
type HubConfig struct {
	Enabled           bool     `yaml:"enabled"`
	URL               string   `yaml:"url"`   // e.g., "wss://hub.serverguard.io"
	Token             string   `yaml:"token"` // registration token
	AgentID           string   `yaml:"agent_id"`
	HeartbeatInterval Duration `yaml:"heartbeat_interval"`
	ReconnectBackoff  Duration `yaml:"reconnect_backoff"`
	ReconnectMax      Duration `yaml:"reconnect_max"`
}

// CertConfig holds certificate guard settings.
type CertConfig struct {
	ScanInterval   Duration `yaml:"scan_interval"`
	ScanPorts      []int    `yaml:"scan_ports"`
	AlertDays      []int    `yaml:"alert_days"`      // 30, 14, 7, 3, 1
	AutoRenewDays  int      `yaml:"auto_renew_days"` // start trying N days before expiry
	RenewCooldown  Duration `yaml:"renew_cooldown"`
	ACMEDirectory  string   `yaml:"acme_directory"`
	ACMEEmail      string   `yaml:"acme_email"`
	BaoTaAutoRenew bool     `yaml:"baota_auto_renew"`
	PreferredCAs   []string `yaml:"preferred_cas"` // lets_encrypt, zerossl, trustasia, buypass
	NginxReloadCmd string   `yaml:"nginx_reload_cmd"`
	CertCacheDir   string   `yaml:"cert_cache_dir"`
}

// LogGuardConfig holds log guard settings.
type LogGuardConfig struct {
	MaxFileSize             int64    `yaml:"max_file_size"`      // bytes, default 500MB
	MaxDirSize              int64    `yaml:"max_dir_size"`       // bytes per directory
	MaxWriteRate            float64  `yaml:"max_write_rate"`     // MB/min
	CompressionFormat       string   `yaml:"compression_format"` // gzip
	RetentionDays           int      `yaml:"retention_days"`
	EmergencyCleanThreshold float64  `yaml:"emergency_clean_threshold"` // disk usage %
	ScanPaths               []string `yaml:"scan_paths"`
	ExcludePaths            []string `yaml:"exclude_paths"`
}

// SecurityConfig holds security guard settings.
type SecurityConfig struct {
	BruteForceThreshold int      `yaml:"brute_force_threshold"`
	BruteForceWindow    Duration `yaml:"brute_force_window"`
	BanDuration         Duration `yaml:"ban_duration"`
	BanProgression      bool     `yaml:"ban_progression"` // limit -> short -> long
	ExcludeIPs          []string `yaml:"exclude_ips"`
	MonitorPaths        []string `yaml:"monitor_paths"` // file tamper detection
	MonitorSSHLog       string   `yaml:"monitor_ssh_log"`
	MonitorAuthLog      string   `yaml:"monitor_auth_log"`
}

// DatabaseConfig holds database guard settings.
type DatabaseConfig struct {
	MySQL    MySQLGuardConfig    `yaml:"mysql"`
	Redis    RedisGuardConfig    `yaml:"redis"`
	InfluxDB InfluxDBGuardConfig `yaml:"influxdb"`
	MongoDB  MongoDBGuardConfig  `yaml:"mongodb"`
}

type MySQLGuardConfig struct {
	Enabled            bool     `yaml:"enabled"`
	DSN                string   `yaml:"dsn"`
	MaxConns           int      `yaml:"max_conns"`
	SlowQueryThreshold Duration `yaml:"slow_query_threshold"`
}

type RedisGuardConfig struct {
	Enabled  bool   `yaml:"enabled"`
	Addr     string `yaml:"addr"`
	Password string `yaml:"password"`
}

type InfluxDBGuardConfig struct {
	Enabled bool   `yaml:"enabled"`
	Addr    string `yaml:"addr"`
	Token   string `yaml:"token"`
	Org     string `yaml:"org"`
}

type MongoDBGuardConfig struct {
	Enabled bool   `yaml:"enabled"`
	URI     string `yaml:"uri"`
}

// DockerConfig holds Docker guard settings.
type DockerConfig struct {
	Enabled       bool     `yaml:"enabled"`
	Socket        string   `yaml:"socket"`
	MaxLogSize    string   `yaml:"max_log_size"`
	PruneInterval Duration `yaml:"prune_interval"`
}

// SystemConfig holds system guard settings.
type SystemConfig struct {
	TempFileCleanInterval Duration `yaml:"temp_file_clean_interval"`
	TempFileMaxAge        Duration `yaml:"temp_file_max_age"`
	TimeSyncCheckInterval Duration `yaml:"time_sync_check_interval"`
	MaxClockDrift         Duration `yaml:"max_clock_drift"`
	TempPaths             []string `yaml:"temp_paths"`
	CachePaths            []string `yaml:"cache_paths"`
}

// NetworkConfig holds network guard settings.
type NetworkConfig struct {
	CheckInterval Duration        `yaml:"check_interval"`
	Targets       []NetworkTarget `yaml:"targets"`
	DNSServers    []string        `yaml:"dns_servers"`
	ProbeTimeout  Duration        `yaml:"probe_timeout"`
}

type NetworkTarget struct {
	Name    string `yaml:"name"`
	Address string `yaml:"address"`
	Port    int    `yaml:"port"`
	Type    string `yaml:"type"` // tcp, http, icmp
}

// OfflineConfig holds offline mode settings.
type OfflineConfig struct {
	Enabled        bool   `yaml:"enabled"`
	PackageDir     string `yaml:"package_dir"`
	LocalRulesPath string `yaml:"local_rules_path"`
}

// BaotaConfig holds Baota panel compatibility settings.
// 包含宝塔环境检测模式、面板路径、确认超时时间、自动项开关和确认项策略。
type BaotaConfig struct {
	SafeMode              string            `yaml:"safe_mode"`                 // 环境检测模式: auto / true / false
	PanelPath             string            `yaml:"panel_path"`                // 宝塔面板路径（默认 /www/server/panel）
	UseBaotaServiceMgr    bool              `yaml:"use_baota_service_manager"` // 使用 /etc/init.d/xxx 管理服务
	CleanupScope          string            `yaml:"cleanup_scope"`             // disabled, var_log_only
	LogRotationScope      string            `yaml:"log_rotation_scope"`        // disabled, notify_only
	WebShellExclusions    []string          `yaml:"webshell_exclusions"`       // WebShell 扫描排除路径
	ConfirmTimeoutMinutes int               `yaml:"confirm_timeout_minutes"`   // 确认超时时间（分钟），默认 5，范围 1-60
	AutoActions           map[string]bool   `yaml:"auto_actions"`              // 🟢 自动项开关映射（action_type → bool）
	ConfirmActions        map[string]string `yaml:"confirm_actions"`           // 🟡 确认项策略映射（action_type → confirm/auto/alert）
}

// UpgradeConfig holds auto-upgrade settings.
// Agent 启动时定时检查官网 /api/v1/latest 接口，发现新版本后面板提示用户升级。
type UpgradeConfig struct {
	ServerURL     string   `yaml:"server_url"`     // 官网 API 地址，如 https://sg.jjtt.net/api/v1
	Channel       string   `yaml:"channel"`        // stable / beta / edge
	CheckInterval Duration `yaml:"check_interval"` // 检查间隔，默认 6 小时
	SigningKey    string   `yaml:"signing_key"`    // Ed25519 公钥（可选，用于签名验证）
	// AutoApplyInMaintenance 维护窗口内自动升级（默认关闭）。
	// 开启后：仅 stable 渠道 + 系统处于维护窗口期 + （配置了公钥时）签名校验通过，
	// 三个条件同时满足才自动执行升级——把"半夜手动升"变成"窗口内自动升"。
	AutoApplyInMaintenance bool `yaml:"auto_apply_in_maintenance"`
}

// DefaultConfig returns a configuration with sensible defaults.
func DefaultConfig() *Config {
	dataDir := defaultDataDir()

	return &Config{
		SchemaVersion: 1,
		Agent: AgentConfig{
			ID:              "",
			Name:            "serverguard-agent",
			DataDir:         dataDir,
			LogLevel:        "info",
			CollectInterval: Duration(10 * time.Second),
			// 内存软限制：作为 GOMEMLIMIT 后备值（systemd 环境优先用环境变量）。
			// 注意：不能低于实际常驻内存，否则 Go GC 会持续全速回收换内存（GC 抖动），
			// 在 1C 服务器上表现为 CPU 占用飙升。128MB 与 systemd 单元在 1G 内存服务器上的
			// GO_MEM_LIMIT=128MiB 一致。
			MaxMemoryMB:      128,
			MaxCPUPercent:    3,
			LearnMode:        true,
			LearnModeDays:    7,
			EmergencyStop:    false,
			TrustAutoConfirm: true,
		},
		Storage: StorageConfig{
			Path:                  filepath.Join(dataDir, "serverguard.db"),
			EncryptionKey:         "",
			MaxSizeMB:             200,
			VacuumInterval:        Duration(7 * 24 * time.Hour),
			WalCheckpointInterval: Duration(5 * time.Minute),
			BackupCount:           7,
		},
		Collectors: CollectorConfig{
			EnableProcesses:   true,
			EnableDisks:       true,
			EnableNetwork:     true,
			EnableGPU:         false,
			EnableTemperature: false,
			EnableFD:          true,
			ProcessMaxCount:   100,
			InotifyMaxWatches: 500,
		},
		Rules: RulesConfig{
			ConfigPath:      filepath.Join(dataDir, "rules.yaml"),
			MatchTimeout:    Duration(5 * time.Millisecond),
			MaxRules:        100,
			DefaultCooldown: Duration(300 * time.Second),
		},
		Safety: SafetyConfig{
			KillBudgetHourly:            5,
			KillBudgetDaily:             20,
			KillMinInterval:             Duration(30 * time.Second),
			CircuitBreakerThreshold:     3,
			CircuitBreakerResetDuration: Duration(30 * time.Minute),
			MinAvailableMemoryMB:        100,
			MaxLoadFactor:               2.0,
			MaxDiskIOWaitPercent:        50,
			MinDiskAvailableMB:          500,
			ObservationWindow:           Duration(60 * time.Second),
			CascadeSuppression:          true,
			WhitelistPath:               filepath.Join(dataDir, "whitelist.yaml"),
			TrashDir:                    filepath.Join(dataDir, ".trash"),
			TrashRetentionDays:          7,
		},
		Notify: NotifyConfig{
			Channels: []ChannelConfig{},
			Silence: SilenceConfig{
				Enabled: false,
			},
		},
		Web: WebConfig{
			Enabled:     true,
			Listen:      "127.0.0.1:8443",
			AuthEnabled: true,
			Username:    "admin",
			Password:    "",
			CORSOrigins: []string{"http://localhost:5173"},
		},
		Hub: HubConfig{
			Enabled:           false,
			HeartbeatInterval: Duration(30 * time.Second),
			ReconnectBackoff:  Duration(1 * time.Second),
			ReconnectMax:      Duration(300 * time.Second),
		},
		Cert: CertConfig{
			ScanInterval:   Duration(24 * time.Hour),
			ScanPorts:      []int{443, 8443, 8001, 8888},
			AlertDays:      []int{30, 14, 7, 3, 1},
			AutoRenewDays:  14,
			RenewCooldown:  Duration(1 * time.Hour),
			ACMEDirectory:  "https://acme-v02.api.letsencrypt.org/directory",
			ACMEEmail:      "",
			BaoTaAutoRenew: true,
			PreferredCAs:   []string{"lets_encrypt", "zerossl", "trustasia", "buypass"},
			NginxReloadCmd: "nginx -s reload",
			CertCacheDir:   filepath.Join(dataDir, "certs"),
		},
		Log: LogGuardConfig{
			MaxFileSize:             500 * 1024 * 1024,       // 500MB
			MaxDirSize:              10 * 1024 * 1024 * 1024, // 10GB
			MaxWriteRate:            10,                      // 10 MB/min
			CompressionFormat:       "gzip",
			RetentionDays:           30,
			EmergencyCleanThreshold: 0.95,
			ScanPaths:               []string{"/var/log", "/www/wwwlogs"},
			ExcludePaths:            []string{},
		},
		Security: SecurityConfig{
			BruteForceThreshold: 5,
			BruteForceWindow:    Duration(5 * time.Minute),
			BanDuration:         Duration(1 * time.Hour),
			BanProgression:      true,
			MonitorSSHLog:       "/var/log/auth.log",
			MonitorAuthLog:      "/var/log/auth.log",
		},
		Database: DatabaseConfig{
			MySQL: MySQLGuardConfig{
				Enabled:            false,
				MaxConns:           100,
				SlowQueryThreshold: Duration(5 * time.Second),
			},
		},
		Docker: DockerConfig{
			Enabled:       false,
			Socket:        "/var/run/docker.sock",
			MaxLogSize:    "100m",
			PruneInterval: Duration(24 * time.Hour),
		},
		System: SystemConfig{
			TempFileCleanInterval: Duration(24 * time.Hour),
			TempFileMaxAge:        Duration(7 * 24 * time.Hour),
			TimeSyncCheckInterval: Duration(1 * time.Hour),
			MaxClockDrift:         Duration(100 * time.Millisecond),
			TempPaths:             []string{"/tmp", "/var/tmp"},
			CachePaths:            []string{"~/.cache", "/var/cache"},
		},
		Network: NetworkConfig{
			CheckInterval: Duration(30 * time.Second),
			ProbeTimeout:  Duration(5 * time.Second),
			DNSServers:    []string{"8.8.8.8", "114.114.114.114"},
		},
		Offline: OfflineConfig{
			Enabled: false,
		},
		Baota: BaotaConfig{
			SafeMode:           "auto",
			PanelPath:          "/www/server/panel",
			UseBaotaServiceMgr: true,
			CleanupScope:       "disabled",
			LogRotationScope:   "disabled",
			WebShellExclusions: []string{
				"/www/server/panel",
				"/www/server/panel/plugin",
			},
			ConfirmTimeoutMinutes: 5,
			AutoActions:           make(map[string]bool),
			ConfirmActions:        make(map[string]string),
		},
		Upgrade: UpgradeConfig{
			ServerURL:     "https://sg.jjtt.net/api/v1",
			Channel:       "stable",
			CheckInterval: Duration(6 * time.Hour),
		},
	}
}

func defaultDataDir() string {
	if runtime.GOOS == "windows" {
		home, _ := os.UserHomeDir()
		return filepath.Join(home, ".serverguard")
	}
	return "/var/lib/serverguard"
}

// Load reads and parses the configuration file.
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file: %w", err)
	}

	cfg := DefaultConfig()
	if err := yaml.Unmarshal(data, cfg); err != nil {
		return nil, fmt.Errorf("failed to parse config: %w", err)
	}

	// Validate
	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("config validation failed: %w", err)
	}

	return cfg, nil
}

// Save writes the configuration to a file.
func (c *Config) Save(path string) error {
	data, err := yaml.Marshal(c)
	if err != nil {
		return fmt.Errorf("failed to marshal config: %w", err)
	}

	if err := os.WriteFile(path, data, 0600); err != nil {
		return fmt.Errorf("failed to write config: %w", err)
	}

	return nil
}

// Validate checks the configuration for errors.
func (c *Config) Validate() error {
	if c.Agent.CollectInterval.Duration() < 1*time.Second {
		return fmt.Errorf("collect_interval must be at least 1 second")
	}
	if c.Agent.MaxMemoryMB < 32 {
		return fmt.Errorf("max_memory_mb must be at least 32")
	}
	if c.Safety.KillBudgetHourly < 1 {
		return fmt.Errorf("kill_budget_hourly must be at least 1")
	}
	if c.Safety.KillBudgetDaily < c.Safety.KillBudgetHourly {
		return fmt.Errorf("kill_budget_daily must be >= kill_budget_hourly")
	}

	// 宝塔配置校验
	if err := c.validateBaotaConfig(); err != nil {
		return err
	}

	return nil
}

// validateBaotaConfig 校验宝塔配置节的合法性。
// 校验规则:
//   - 🟡 项值只能是 confirm / auto / alert 之一
//   - 🔴 禁止项出现在配置中即报错（安全红线不可配置）
//   - 超时时间不在 1-60 范围内则重置为 5
func (c *Config) validateBaotaConfig() error {
	bc := &c.Baota

	// 超时时间校验: 不在 1-60 范围内则重置为 5
	if bc.ConfirmTimeoutMinutes < 1 || bc.ConfirmTimeoutMinutes > 60 {
		bc.ConfirmTimeoutMinutes = 5
	}

	// 🔴 禁止项列表：这些动作不允许在配置中出现
	forbiddenActions := map[string]bool{
		"kill_bt_panel":       true,
		"kill_bt_task":        true,
		"restart_bt_panel":    true,
		"clean_baota_dir":     true,
		"systemctl_baota_svc": true,
		"chmod_baota_file":    true,
	}

	// 检查 🔴 禁止项是否出现在 auto_actions 中
	for action := range bc.AutoActions {
		if forbiddenActions[action] {
			return fmt.Errorf("action %s 为安全红线，不可在配置中修改", action)
		}
	}

	// 检查 🔴 禁止项是否出现在 confirm_actions 中
	for action := range bc.ConfirmActions {
		if forbiddenActions[action] {
			return fmt.Errorf("action %s 为安全红线，不可在配置中修改", action)
		}
	}

	// 🟡 项值校验: confirm_actions 中的值只能是 confirm / auto / alert
	validConfirmValues := map[string]bool{
		"confirm": true,
		"auto":    true,
		"alert":   true,
	}
	for action, val := range bc.ConfirmActions {
		valLower := strings.ToLower(strings.TrimSpace(val))
		if !validConfirmValues[valLower] {
			return fmt.Errorf("confirm_actions[%s] 值 %q 无效，只能是 confirm / auto / alert", action, val)
		}
		// 规范化写入
		bc.ConfirmActions[action] = valLower
	}

	return nil
}

// EnsureDataDir creates the data directory if it doesn't exist.
func (c *Config) EnsureDataDir() error {
	return os.MkdirAll(c.Agent.DataDir, 0750)
}
