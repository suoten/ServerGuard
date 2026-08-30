package sitediscovery

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

// ────────────────────────────────────────────────
// V4.0 — 首跑引导向导
// 安装完成后面板自动走"检测到宝塔/Nginx/MySQL → 一键导入存量守护 → 学习模式 7 天倒计时"
// ────────────────────────────────────────────────

// OnboardingStep 引导向导步骤
type OnboardingStep struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Status      string `json:"status"` // "pending" / "running" / "done" / "skipped"
	Description string `json:"description"`
	Result      string `json:"result,omitempty"`
}

// OnboardingState 引导状态
type OnboardingState struct {
	Started          bool          `json:"started"`
	Completed        bool          `json:"completed"`
	StartedAt        time.Time     `json:"started_at"`
	CompletedAt      *time.Time    `json:"completed_at,omitempty"`
	CurrentStep      int           `json:"current_step"`
	Steps            []OnboardingStep `json:"steps"`
	LearnModeEndsAt  *time.Time    `json:"learn_mode_ends_at,omitempty"`  // 学习模式结束时间
	DetectedServices []DetectedService `json:"detected_services"`
}

// DetectedService 引导期间检测到的服务
type DetectedService struct {
	Name       string `json:"name"`        // nginx, mysql, redis, docker, baota
	Type       string `json:"type"`        // systemd, docker, baota, bare
	Available  bool   `json:"available"`
	ConfigPath string `json:"config_path"` // 配置文件路径（如有）
	Port       int    `json:"port"`        // 端口（如有）
	Importable bool   `json:"importable"`  // 是否可一键导入为守护目标
}

// OnboardingWizard 首跑引导向导
type OnboardingWizard struct {
	state OnboardingState
}

// NewOnboardingWizard 创建引导向导
func NewOnboardingWizard() *OnboardingWizard {
	return &OnboardingWizard{
		state: OnboardingState{
			Steps: []OnboardingStep{
				{
					ID:          "detect",
					Name:        "检测运行环境",
					Description: "扫描本机运行的服务（Nginx、MySQL、Redis、Docker、宝塔等）",
					Status:      "pending",
				},
				{
					ID:          "import",
					Name:        "导入守护目标",
					Description: "将检测到的服务一键导入为守护目标",
					Status:      "pending",
				},
				{
					ID:          "learn_mode",
					Name:        "启动学习模式",
					Description: "7天基线学习期，只观察不告警，积累正常指标基线",
					Status:      "pending",
				},
				{
					ID:          "first_report",
					Name:        "生成首份报告",
					Description: "学习期结束后自动生成首份巡检报告",
					Status:      "pending",
				},
			},
		},
	}
}

// GetState 获取当前引导状态
func (w *OnboardingWizard) GetState() OnboardingState {
	return w.state
}

// Start 开始引导
func (w *OnboardingWizard) Start() {
	w.state.Started = true
	w.state.StartedAt = time.Now()
	w.state.CurrentStep = 0
	w.state.Steps[0].Status = "running"
}

// DetectServices 执行环境检测（步骤 1）
func (w *OnboardingWizard) DetectServices() []DetectedService {
	services := DetectAllServices()
	w.state.DetectedServices = services
	w.state.Steps[0].Status = "done"
	w.state.Steps[0].Result = fmt.Sprintf("检测到 %d 个可导入的服务", len(services))
	if len(w.state.Steps) > 1 {
		w.state.CurrentStep = 1
		w.state.Steps[1].Status = "running"
	}
	return services
}

// CompleteImport 标记导入完成（步骤 2）
func (w *OnboardingWizard) CompleteImport(importedCount int) {
	w.state.Steps[1].Status = "done"
	w.state.Steps[1].Result = fmt.Sprintf("已导入 %d 个守护目标", importedCount)
	if len(w.state.Steps) > 2 {
		w.state.CurrentStep = 2
		w.state.Steps[2].Status = "running"
	}
}

// StartLearnMode 启动学习模式（步骤 3）
// learnDays: 学习天数（默认 7）
func (w *OnboardingWizard) StartLearnMode(learnDays int) {
	if learnDays <= 0 {
		learnDays = 7
	}
	endTime := time.Now().Add(time.Duration(learnDays) * 24 * time.Hour)
	w.state.LearnModeEndsAt = &endTime
	w.state.Steps[2].Status = "done"
	w.state.Steps[2].Result = fmt.Sprintf("学习模式已启动，将于 %s 结束", endTime.Format("2006-01-02 15:04"))
	if len(w.state.Steps) > 3 {
		w.state.CurrentStep = 3
		// 首份报告在学习模式结束后生成
		w.state.Steps[3].Status = "pending"
	}
}

// CompleteFirstReport 标记首份报告完成（步骤 4）
func (w *OnboardingWizard) CompleteFirstReport() {
	w.state.Steps[3].Status = "done"
	w.state.Steps[3].Result = "首份巡检报告已生成"
	w.state.Completed = true
	now := time.Now()
	w.state.CompletedAt = &now
}

// Skip 跳过引导
func (w *OnboardingWizard) Skip() {
	w.state.Completed = true
	now := time.Now()
	w.state.CompletedAt = &now
	for i := range w.state.Steps {
		if w.state.Steps[i].Status != "done" {
			w.state.Steps[i].Status = "skipped"
		}
	}
}

// IsLearnModeActive 检查学习模式是否活跃
func (w *OnboardingWizard) IsLearnModeActive() bool {
	if w.state.LearnModeEndsAt == nil {
		return false
	}
	return time.Now().Before(*w.state.LearnModeEndsAt)
}

// LearnModeRemainingDays 学习模式剩余天数
func (w *OnboardingWizard) LearnModeRemainingDays() int {
	if w.state.LearnModeEndsAt == nil {
		return 0
	}
	remaining := w.state.LearnModeEndsAt.Sub(time.Now())
	if remaining <= 0 {
		return 0
	}
	return int(remaining.Hours() / 24)
}

// ============================================================
// 环境检测逻辑
// ============================================================

// DetectAllServices 检测本机运行的所有常见服务
func DetectAllServices() []DetectedService {
	var services []DetectedService

	// Nginx
	if path := findExecutable("nginx"); path != "" || isProcessRunning("nginx") {
		services = append(services, DetectedService{
			Name:       "nginx",
			Type:       detectServiceType("nginx"),
			Available:  true,
			ConfigPath: findNginxConfig(),
			Port:       80,
			Importable: true,
		})
	}

	// MySQL / MariaDB
	if isProcessRunning("mysqld") || isProcessRunning("mariadbd") {
		services = append(services, DetectedService{
			Name:       "mysql",
			Type:       detectServiceType("mysql"),
			Available:  true,
			Port:       3306,
			Importable: true,
		})
	}

	// Redis
	if isProcessRunning("redis-server") || isProcessRunning("redis") {
		services = append(services, DetectedService{
			Name:       "redis",
			Type:       detectServiceType("redis"),
			Available:  true,
			Port:       6379,
			Importable: true,
		})
	}

	// Docker
	if path := findExecutable("docker"); path != "" {
		services = append(services, DetectedService{
			Name:       "docker",
			Type:       "docker",
			Available:  true,
			Importable: true,
		})
	}

	// 宝塔面板
	baotaPath := "/www/server/panel"
	if runtime.GOOS == "windows" {
		baotaPath = `C:\BtSoft\panel`
	}
	if _, err := os.Stat(baotaPath); err == nil {
		services = append(services, DetectedService{
			Name:       "baota",
			Type:       "baota",
			Available:  true,
			ConfigPath: baotaPath,
			Port:       8888,
			Importable: true,
		})
	}

	// Apache
	if isProcessRunning("apache2") || isProcessRunning("httpd") {
		services = append(services, DetectedService{
			Name:       "apache",
			Type:       detectServiceType("apache"),
			Available:  true,
			Port:       80,
			Importable: true,
		})
	}

	// PHP-FPM
	if isProcessRunning("php-fpm") || isProcessRunning("php7") || isProcessRunning("php8") {
		services = append(services, DetectedService{
			Name:       "php-fpm",
			Type:       detectServiceType("php-fpm"),
			Available:  true,
			Port:       9000,
			Importable: true,
		})
	}

	// SSH
	if isProcessRunning("sshd") {
		services = append(services, DetectedService{
			Name:       "ssh",
			Type:       detectServiceType("ssh"),
			Available:  true,
			Port:       22,
			Importable: false, // SSH 不建议作为守护目标（守护SSH有风险）
		})
	}

	return services
}

// findExecutable 在 PATH 中查找可执行文件
func findExecutable(name string) string {
	// 检查常见路径
	paths := []string{}
	if runtime.GOOS == "windows" {
		paths = []string{
			fmt.Sprintf("C:\\Program Files\\%s\\%s.exe", name, name),
			fmt.Sprintf("C:\\Program Files (x86)\\%s\\%s.exe", name, name),
			fmt.Sprintf("C:\\%s\\%s.exe", name, name),
		}
	} else {
		paths = []string{
			fmt.Sprintf("/usr/sbin/%s", name),
			fmt.Sprintf("/usr/bin/%s", name),
			fmt.Sprintf("/usr/local/sbin/%s", name),
			fmt.Sprintf("/usr/local/bin/%s", name),
			fmt.Sprintf("/www/server/%s/sbin/%s", name, name),
		}
	}

	for _, p := range paths {
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	return ""
}

// isProcessRunning 通过 /proc 或 tasklist 检查进程是否在运行
func isProcessRunning(name string) bool {
	if runtime.GOOS == "windows" {
		// Windows 上不做进程检测（避免依赖 tasklist）
		return false
	}

	// Linux: 检查 /proc/*/comm
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return false
	}
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		commPath := filepath.Join("/proc", entry.Name(), "comm")
		data, err := os.ReadFile(commPath)
		if err != nil {
			continue
		}
		comm := strings.TrimSpace(string(data))
		if comm == name || strings.HasPrefix(comm, name) {
			return true
		}
	}
	return false
}

// findNginxConfig 查找 Nginx 配置文件路径
func findNginxConfig() string {
	candidates := []string{
		"/etc/nginx/nginx.conf",
		"/usr/local/nginx/conf/nginx.conf",
		"/www/server/nginx/conf/nginx.conf",
		"/usr/local/etc/nginx/nginx.conf",
	}
	for _, p := range candidates {
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	return ""
}

// detectServiceType 检测服务管理方式
func detectServiceType(name string) string {
	if runtime.GOOS == "windows" {
		return "windows_service"
	}

	// 检查是否有 systemd 服务
	systemdPath := fmt.Sprintf("/etc/systemd/system/%s.service", name)
	if _, err := os.Stat(systemdPath); err == nil {
		return "systemd"
	}

	// 检查 sysvinit
	sysvPath := fmt.Sprintf("/etc/init.d/%s", name)
	if _, err := os.Stat(sysvPath); err == nil {
		return "systemd" // 兼容 sysvinit
	}

	return "bare_process"
}
