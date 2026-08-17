package types

import (
	"time"
)

// MetricType represents the type of metric being collected.
type MetricType string

const (
	MetricCPU            MetricType = "cpu"
	MetricMemory         MetricType = "memory"
	MetricDisk           MetricType = "disk"
	MetricDiskIO         MetricType = "disk_io"
	MetricNetwork        MetricType = "network"
	MetricProcess        MetricType = "process"
	MetricGPU            MetricType = "gpu"
	MetricTemperature    MetricType = "temperature"
	MetricFileDescriptor MetricType = "fd"
)

// Metric represents a single metric data point.
type Metric struct {
	Type      MetricType        `json:"type"`
	Name      string            `json:"name"`  // e.g., "cpu_percent", "mem_used_bytes"
	Value     float64           `json:"value"` // numeric value
	Unit      string            `json:"unit"`  // e.g., "%", "bytes", "MB/s"
	Timestamp time.Time         `json:"timestamp"`
	Labels    map[string]string `json:"labels,omitempty"` // e.g., {"pid": "1234", "process": "nginx"}
}

// ProcessInfo represents information about a running process.
type ProcessInfo struct {
	PID            int32     `json:"pid"`
	PPID           int32     `json:"ppid"`
	Name           string    `json:"name"`
	Cmdline        string    `json:"cmdline"`
	CPUPercent     float64   `json:"cpu_percent"`
	MemPercent     float64   `json:"mem_percent"`
	RSS            uint64    `json:"rss"`    // resident set size in bytes
	VMS            uint64    `json:"vms"`    // virtual memory size in bytes
	Status         string    `json:"status"` // e.g., "R", "S", "Z"
	CreateTime     time.Time `json:"create_time"`
	NumThreads     int32     `json:"num_threads"`
	NumFDs         int32     `json:"num_fds"` // file descriptor count
	NumConnections int32     `json:"num_connections"`
	IsSystem       bool      `json:"is_system"`              // whether it's a system critical process
	Manager        string    `json:"manager"`                // "systemd", "docker", "supervisor", "bare"
	ContainerID    string    `json:"container_id,omitempty"` // if running in a container
}

// DiskInfo represents disk usage information.
type DiskInfo struct {
	Device      string  `json:"device"`
	MountPoint  string  `json:"mount_point"`
	FSType      string  `json:"fs_type"`
	Total       uint64  `json:"total"`
	Used        uint64  `json:"used"`
	Free        uint64  `json:"free"`
	UsedPercent float64 `json:"used_percent"`
	InodesTotal uint64  `json:"inodes_total"`
	InodesUsed  uint64  `json:"inodes_used"`
	InodesFree  uint64  `json:"inodes_free"`
}

// SystemInfo represents overall system resource information.
type SystemInfo struct {
	Hostname        string        `json:"hostname"`
	OS              string        `json:"os"`
	Platform        string        `json:"platform"`
	PlatformVersion string        `json:"platform_version"`
	KernelVersion   string        `json:"kernel_version"`
	BootTime        time.Time     `json:"boot_time"`
	Uptime          time.Duration `json:"uptime"`

	// CPU
	CPUPercent float64 `json:"cpu_percent"`
	CPUCores   int     `json:"cpu_cores"`
	LoadAvg1   float64 `json:"load_avg_1"`
	LoadAvg5   float64 `json:"load_avg_5"`
	LoadAvg15  float64 `json:"load_avg_15"`

	// Memory
	MemTotal     uint64  `json:"mem_total"`
	MemUsed      uint64  `json:"mem_used"`
	MemAvailable uint64  `json:"mem_available"`
	MemPercent   float64 `json:"mem_percent"`
	SwapTotal    uint64  `json:"swap_total"`
	SwapUsed     uint64  `json:"swap_used"`
	SwapPercent  float64 `json:"swap_percent"`

	// Disks
	Disks []DiskInfo `json:"disks"`

	// Network
	NetSent     uint64  `json:"net_sent"`      // bytes sent
	NetRecv     uint64  `json:"net_recv"`      // bytes received
	NetSentRate float64 `json:"net_sent_rate"` // bytes/s
	NetRecvRate float64 `json:"net_recv_rate"` // bytes/s

	// Process summary
	ProcessCount int `json:"process_count"`
	ZombieCount  int `json:"zombie_count"`
	TotalFDs     int `json:"total_fds"`

	// Timestamp
	Timestamp time.Time `json:"timestamp"`
}

// AlertLevel represents the severity level of an alert.
type AlertLevel string

const (
	AlertInfo     AlertLevel = "info"
	AlertWarning  AlertLevel = "warning"
	AlertError    AlertLevel = "error"
	AlertCritical AlertLevel = "critical"
	AlertFatal    AlertLevel = "fatal"
)

// Alert represents an alert event.
type Alert struct {
	ID           string            `json:"id"`
	Level        AlertLevel        `json:"level"`
	Title        string            `json:"title"`
	Message      string            `json:"message"`
	Source       string            `json:"source"`  // which guard module triggered it
	RuleID       string            `json:"rule_id"` // which rule triggered it
	Labels       map[string]string `json:"labels,omitempty"`
	Timestamp    time.Time         `json:"timestamp"`
	Resolved     bool              `json:"resolved"`
	ResolvedAt   *time.Time        `json:"resolved_at,omitempty"`
	Acknowledged bool              `json:"acknowledged"`
	AckedBy      string            `json:"acked_by,omitempty"`
}

// ActionType represents the type of action to execute.
type ActionType string

const (
	ActionKill        ActionType = "kill"
	ActionSigTerm     ActionType = "sigterm"
	ActionSigKill     ActionType = "sigkill"
	ActionNice        ActionType = "nice"
	ActionRestart     ActionType = "restart"
	ActionCleanLog    ActionType = "clean_log"
	ActionRotateLog   ActionType = "rotate_log"
	ActionBanIP       ActionType = "ban_ip"
	ActionUnbanIP     ActionType = "unban_ip"
	ActionRenewCert   ActionType = "renew_cert"
	ActionReloadNginx ActionType = "reload_nginx"
	ActionCleanDisk   ActionType = "clean_disk"
	ActionRunScript   ActionType = "run_script"
	ActionAlert       ActionType = "alert"
	ActionSnapshot    ActionType = "snapshot"
)

// Action represents an executable action.
type Action struct {
	Type    ActionType             `json:"type"`
	Timeout time.Duration          `json:"timeout"`
	OnFail  string                 `json:"on_fail"` // "continue", "abort", "alert"
	Params  map[string]interface{} `json:"params"`
}

// ActionResult represents the result of an executed action.
type ActionResult struct {
	Action    Action        `json:"action"`
	Success   bool          `json:"success"`
	Message   string        `json:"message"`
	Error     string        `json:"error,omitempty"`
	Duration  time.Duration `json:"duration"`
	Timestamp time.Time     `json:"timestamp"`
}

// ConditionOperator represents how to evaluate conditions.
type ConditionOperator string

const (
	OpAnd ConditionOperator = "AND"
	OpOr  ConditionOperator = "OR"
	OpNot ConditionOperator = "NOT"
)

// ComparisonOperator for condition evaluation.
type ComparisonOperator string

const (
	CmpGT       ComparisonOperator = ">"
	CmpGTE      ComparisonOperator = ">="
	CmpLT       ComparisonOperator = "<"
	CmpLTE      ComparisonOperator = "<="
	CmpEQ       ComparisonOperator = "=="
	CmpNE       ComparisonOperator = "!="
	CmpIn       ComparisonOperator = "in"
	CmpNotIn    ComparisonOperator = "not_in"
	CmpContains ComparisonOperator = "contains"
	CmpMatches  ComparisonOperator = "matches"
)

// Condition represents a trigger condition for a rule.
type Condition struct {
	Metric   string             `json:"metric"` // e.g., "process.cpu_percent"
	Op       ComparisonOperator `json:"op"`
	Value    interface{}        `json:"value"`    // threshold value
	Duration time.Duration      `json:"duration"` // sustained duration
}

// ConditionGroup represents a group of conditions with an operator.
type ConditionGroup struct {
	Operator   ConditionOperator `json:"operator"` // AND, OR
	Conditions []Condition       `json:"conditions"`
	Groups     []ConditionGroup  `json:"groups,omitempty"` // nested groups
}

// Rule represents a monitoring/self-healing rule.
type Rule struct {
	ID                string         `json:"id"`
	Name              string         `json:"name"`
	Description       string         `json:"description"`
	Enabled           bool           `json:"enabled"`
	Priority          int            `json:"priority"`
	Module            string         `json:"module"` // which guard module owns this rule
	Trigger           ConditionGroup `json:"trigger"`
	Actions           []Action       `json:"actions"`
	Cooldown          time.Duration  `json:"cooldown"`
	MaxTriggers       int            `json:"max_triggers"` // per hour
	AlertLevel        AlertLevel     `json:"alert_level"`
	AlertChannels     []string       `json:"alert_channels"`
	LearnMode         bool           `json:"learn_mode"`         // if true, only alert, don't execute
	NeedsConfirmation bool           `json:"needs_confirmation"` // W/X/Y 模块需要用户确认
	Tags              []string       `json:"tags,omitempty"`
}

// Event represents an event in the event bus.
type EventType string

const (
	EventAlert     EventType = "alert"
	EventAction    EventType = "action"
	EventMetric    EventType = "metric"
	EventSystem    EventType = "system"
	EventAudit     EventType = "audit"
	EventHeartbeat EventType = "heartbeat"
	EventCertScan  EventType = "cert_scan"
	EventLogRotate EventType = "log_rotate"
	EventSecurity  EventType = "security"
)

type Event struct {
	ID        string      `json:"id"`
	Type      EventType   `json:"type"`
	Source    string      `json:"source"` // module name
	Level     AlertLevel  `json:"level"`
	Title     string      `json:"title"`
	Message   string      `json:"message"`
	Data      interface{} `json:"data,omitempty"`
	Timestamp time.Time   `json:"timestamp"`
}

// GuardTarget represents a process/service being guarded.
type GuardTargetType string

const (
	TargetSystemd GuardTargetType = "systemd"
	TargetDocker  GuardTargetType = "docker"
	TargetWinSvc  GuardTargetType = "windows_service"
	TargetBare    GuardTargetType = "bare_process"
	TargetPort    GuardTargetType = "port"
	TargetHTTP    GuardTargetType = "http"
	TargetScript  GuardTargetType = "script"
)

type GuardTarget struct {
	ID            string          `json:"id"`
	Name          string          `json:"name"`
	Type          GuardTargetType `json:"type"`
	Command       string          `json:"command"` // start command
	StopCommand   string          `json:"stop_command,omitempty"`
	Port          int             `json:"port,omitempty"`
	HealthCheck   string          `json:"health_check,omitempty"` // HTTP URL or script path
	ProcessName   string          `json:"process_name,omitempty"`
	DependsOn     []string        `json:"depends_on,omitempty"` // IDs of targets this depends on
	RestartPolicy RestartPolicy   `json:"restart_policy"`
	Enabled       bool            `json:"enabled"`
	Tags          []string        `json:"tags,omitempty"`
}

// RestartPolicy defines how to handle restarts.
type RestartPolicy struct {
	MaxRetries        int           `json:"max_retries"`
	BackoffInitial    time.Duration `json:"backoff_initial"`
	BackoffMax        time.Duration `json:"backoff_max"`
	BackoffMultiplier float64       `json:"backoff_multiplier"`
	Cooldown          time.Duration `json:"cooldown"`
}

// DefaultRestartPolicy returns a sensible default restart policy.
func DefaultRestartPolicy() RestartPolicy {
	return RestartPolicy{
		MaxRetries:        5,
		BackoffInitial:    1 * time.Second,
		BackoffMax:        8 * time.Second,
		BackoffMultiplier: 2.0,
		Cooldown:          300 * time.Second,
	}
}

// CertInfo represents SSL certificate information.
type CertInfo struct {
	Domain             string    `json:"domain"`
	Port               int       `json:"port"`
	Issuer             string    `json:"issuer"`
	Subject            string    `json:"subject"`
	SANs               []string  `json:"sans"` // Subject Alternative Names
	NotBefore          time.Time `json:"not_before"`
	NotAfter           time.Time `json:"not_after"`
	KeyAlgorithm       string    `json:"key_algorithm"`
	SignatureAlgorithm string    `json:"signature_algorithm"`
	SerialNumber       string    `json:"serial_number"`
	CertPath           string    `json:"cert_path,omitempty"`
	ChainComplete      bool      `json:"chain_complete"`
	ManagedBy          string    `json:"managed_by,omitempty"` // "baota", "acme", "manual"
	DaysUntilExpiry    int       `json:"days_until_expiry"`
	StaggeredDeadline  time.Time `json:"staggered_deadline,omitempty"` // 错峰续期时间点
	CachedUntil        time.Time `json:"cached_until,omitempty"`       // 缓存有效期（跳过重复检查）
}

// AuditEntry represents an audit log entry.
type AuditEntry struct {
	ID        string    `json:"id"`
	Timestamp time.Time `json:"timestamp"`
	Actor     string    `json:"actor"`             // who performed the action ("system", "user:admin", "rule:cpu-protect")
	Action    string    `json:"action"`            // what was done
	Target    string    `json:"target"`            // what was affected
	Reason    string    `json:"reason"`            // why it was done
	Result    string    `json:"result"`            // "success", "failure", "blocked"
	Details   string    `json:"details,omitempty"` // additional details
	IPAddress string    `json:"ip_address,omitempty"`
}

// ServerStatus represents the status of a guarded server.
type ServerStatus struct {
	AgentID    string    `json:"agent_id"`
	Hostname   string    `json:"hostname"`
	IP         string    `json:"ip"`
	OS         string    `json:"os"`
	Version    string    `json:"version"`
	Status     string    `json:"status"` // "online", "offline", "degraded"
	Mode       string    `json:"mode"`   // "normal", "throttled", "minimal", "survival", "emergency"
	LastSeen   time.Time `json:"last_seen"`
	CPU        float64   `json:"cpu"`
	Memory     float64   `json:"memory"`
	Disk       float64   `json:"disk"`
	AlertCount int       `json:"alert_count"`
	GuardCount int       `json:"guard_count"`
	Tags       []string  `json:"tags,omitempty"`
}

// AgentMode represents the operational mode of the agent.
type AgentMode string

const (
	ModeNormal    AgentMode = "normal"
	ModeThrottled AgentMode = "throttled"
	ModeMinimal   AgentMode = "minimal"
	ModeSurvival  AgentMode = "survival"
	ModeEmergency AgentMode = "emergency"
)

// BaoTaInstance represents a detected BaoTa panel instance.
type BaoTaInstance struct {
	Detected     bool            `json:"detected"`
	InstallPath  string          `json:"install_path"`
	Version      string          `json:"version"`
	PanelType    string          `json:"panel_type"` // "baota_cn", "aapanel"
	PanelURL     string          `json:"panel_url"`
	Port         string          `json:"port"`
	AdminPath    string          `json:"admin_path"`
	APIEnabled   bool            `json:"api_enabled"`
	APIKey       string          `json:"-"` // never expose in JSON
	Capabilities map[string]bool `json:"capabilities"`
	Sites        []BaoTaSite     `json:"sites"`
}

// BaoTaSite represents a site managed by BaoTa.
type BaoTaSite struct {
	Name      string `json:"name"`
	Domain    string `json:"domain"`
	SSLExpire string `json:"ssl_expire,omitempty"`
	CertPath  string `json:"cert_path,omitempty"`
}

// LogFileInfo represents a log file being monitored.
type LogFileInfo struct {
	Path         string    `json:"path"`
	Size         int64     `json:"size"`
	LastModified time.Time `json:"last_modified"`
	WriteRate    float64   `json:"write_rate"`    // bytes/sec
	Managed      bool      `json:"managed"`       // is ServerGuard managing rotation
	App          string    `json:"app,omitempty"` // which app writes this log
}

// DependencyNode represents a node in the service dependency graph.
type DependencyNode struct {
	ID         string   `json:"id"`
	Name       string   `json:"name"`
	DependsOn  []string `json:"depends_on"`
	Dependents []string `json:"dependents"`
	Status     string   `json:"status"` // "healthy", "down", "isolated"
}

// Snapshot represents a pre-action snapshot for rollback.
type Snapshot struct {
	ID        string                 `json:"id"`
	Action    ActionType             `json:"action"`
	Target    string                 `json:"target"`
	Timestamp time.Time              `json:"timestamp"`
	Data      map[string]interface{} `json:"data"`
}

// RuleMatch represents a rule that matched against metrics.
type RuleMatch struct {
	RuleID      string      `json:"rule_id"`
	MetricName  string      `json:"metric_name"`
	Value       float64     `json:"value"`
	Threshold   interface{} `json:"threshold"`
	ProcessName string      `json:"process_name,omitempty"`
	Timestamp   time.Time   `json:"timestamp"`
}

// ActionSpec represents an action specification (for dry-run display).
type ActionSpec = Action

// NetworkTarget represents a network probe target.
type NetworkTarget struct {
	Name     string `json:"name"`
	Address  string `json:"address"`
	Port     int    `json:"port"`
	Protocol string `json:"protocol"` // tcp, udp
}

// Severity 严重级别
type Severity string

const (
	SeverityCritical Severity = "critical"
	SeverityHigh     Severity = "high"
	SeverityMedium   Severity = "medium"
	SeverityLow      Severity = "low"
	SeverityInfo     Severity = "info"
)

// FindingStatus 发现项状态
type FindingStatus string

const (
	FindingStatusOpen          FindingStatus = "open"
	FindingStatusConfirmed     FindingStatus = "confirmed"
	FindingStatusFixing        FindingStatus = "fixing"
	FindingStatusFixed         FindingStatus = "fixed"
	FindingStatusIgnored       FindingStatus = "ignored"
	FindingStatusFalsePositive FindingStatus = "false_positive"
)

// ScanTarget 扫描目标
type ScanTarget struct {
	Type string `json:"type"` // website, component, system, port, process, file
	Path string `json:"path"`
	Host string `json:"host"`
	Port int    `json:"port"`
}

// ScanReport 扫描报告
type ScanReport struct {
	Scanner   string        `json:"scanner"`
	Target    string        `json:"target"`
	ScannedAt time.Time     `json:"scanned_at"`
	Duration  time.Duration `json:"duration"`
	Findings  []ScanFinding `json:"findings"`
	Summary   ScanSummary   `json:"summary"`
}

// ScanFinding 扫描发现项
type ScanFinding struct {
	ID          string   `json:"id"`
	Scanner     string   `json:"scanner"`
	ScannerSub  string   `json:"scanner_sub"`
	Severity    Severity `json:"severity"`
	Title       string   `json:"title"`
	Description string   `json:"description"`
	Target      string   `json:"target"`
	Detail      string   `json:"detail"`
	Suggestion  string   `json:"suggestion"`
	Consequence string   `json:"consequence"`
	Snapshot    string   `json:"snapshot"`
}

// ScanSummary 扫描摘要
type ScanSummary struct {
	Total    int `json:"total"`
	Critical int `json:"critical"`
	High     int `json:"high"`
	Medium   int `json:"medium"`
	Low      int `json:"low"`
	Info     int `json:"info"`
}

// AttackEvent 攻击事件
type AttackEvent struct {
	ID          string    `json:"id"`
	EventType   string    `json:"event_type"`
	SourceIP    string    `json:"source_ip"`
	Target      string    `json:"target"`
	Severity    Severity  `json:"severity"`
	Detail      string    `json:"detail"`
	ActionTaken string    `json:"action_taken"`
	TraceID     string    `json:"trace_id"`
	CreatedAt   time.Time `json:"created_at"`
}

// AttackProfile 攻击画像
type AttackProfile struct {
	ID              string    `json:"id"`
	SourceIP        string    `json:"source_ip"`
	GeoLocation     string    `json:"geo_location"`
	AttackTypes     []string  `json:"attack_types"`
	FirstSeen       time.Time `json:"first_seen"`
	LastSeen        time.Time `json:"last_seen"`
	Duration        int64     `json:"duration"`
	AffectedModules []string  `json:"affected_modules"`
	Trend           string    `json:"trend"`
	Confidence      float64   `json:"confidence"`
	Detail          string    `json:"detail"`
}

// ReportFormat 报告格式
type ReportFormat string

const (
	ReportFormatJSON ReportFormat = "json"
	ReportFormatHTML ReportFormat = "html"
	ReportFormatPDF  ReportFormat = "pdf"
	ReportFormatText ReportFormat = "text"
)
