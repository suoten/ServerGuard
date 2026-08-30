package baota

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
)

// BaotaEnv 描述宝塔面板环境检测结果。
// 启动时自动判断当前主机是否为宝塔环境，并提取关键路径与配置。
type BaotaEnv struct {
	IsBaota   bool   `json:"is_baota"`           // 是否为宝塔环境
	PanelPath string `json:"panel_path"`         // 宝塔面板安装路径，通常是 /www/server/panel
	PanelPort int    `json:"panel_port"`         // 面板端口，从 /www/server/panel/data/port.pl 读取
	WebRoot   string `json:"web_root"`           // 网站根目录，通常是 /www/wwwroot
	Version   string `json:"version"`            // 宝塔版本，从 version.pl 或 class/common.py 读取
	PanelType string `json:"panel_type"`         // 面板类型: "baota_cn" 或 "aapanel"
	Signals   int    `json:"signals"`            // 命中的检测信号数量
	SignalHit []string `json:"signal_hit"`       // 命中的检测信号列表（用于调试/展示）
}

var (
	baotaEnvOnce     sync.Once
	baotaEnvInstance *BaotaEnv
)

// DetectBaotaEnvironment 检测当前主机是否为宝塔环境。
// 检测标志（满足 2 项即判定为宝塔环境）：
//  1. /www/server/panel 目录存在
//  2. /etc/init.d/bt 文件存在且可执行
//  3. /usr/local/bin/bt 或 /usr/bin/bt 存在
//  4. 进程列表中存在 bt-panel 相关进程
// 返回缓存的检测结果（首次调用后缓存，后续调用直接返回）。
func DetectBaotaEnvironment() *BaotaEnv {
	baotaEnvOnce.Do(func() {
		baotaEnvInstance = detectBaotaEnvironmentImpl()
	})
	return baotaEnvInstance
}

// ResetBaotaEnv 重置缓存的环境检测结果，强制下次调用重新检测。
// 用于宝塔重新探测场景。
func ResetBaotaEnv() {
	baotaEnvOnce = sync.Once{}
	baotaEnvInstance = nil
}

// detectBaotaEnvironmentImpl 执行实际的宝塔环境检测。
func detectBaotaEnvironmentImpl() *BaotaEnv {
	env := &BaotaEnv{
		PanelPath: "/www/server/panel",
		WebRoot:   "/www/wwwroot",
	}

	// 信号 1: /www/server/panel 目录存在
	if fi, err := os.Stat("/www/server/panel/"); err == nil && fi.IsDir() {
		env.Signals++
		env.SignalHit = append(env.SignalHit, "panel_dir_exists")
	}

	// 信号 2: /etc/init.d/bt 文件存在且可执行
	if fi, err := os.Stat("/etc/init.d/bt"); err == nil && !fi.IsDir() {
		// 检查可执行权限
		if fi.Mode()&0111 != 0 {
			env.Signals++
			env.SignalHit = append(env.SignalHit, "init_bt_executable")
		}
	}

	// 信号 3: /usr/local/bin/bt 或 /usr/bin/bt 存在
	if _, err := os.Stat("/usr/local/bin/bt"); err == nil {
		env.Signals++
		env.SignalHit = append(env.SignalHit, "usr_local_bin_bt")
	} else if _, err := os.Stat("/usr/bin/bt"); err == nil {
		env.Signals++
		env.SignalHit = append(env.SignalHit, "usr_bin_bt")
	} else if _, err := exec.LookPath("bt"); err == nil {
		env.Signals++
		env.SignalHit = append(env.SignalHit, "bt_in_path")
	}

	// 信号 4: 进程列表中存在 bt-panel 相关进程
	if hasBaotaProcess() {
		env.Signals++
		env.SignalHit = append(env.SignalHit, "bt_process_running")
	}

	// 判定：满足 2 项即为宝塔环境
	env.IsBaota = env.Signals >= 2

	// 如果是宝塔环境，读取详细配置
	if env.IsBaota {
		env.PanelPort = readBaotaPort(env.PanelPath)
		env.Version = readBaotaVersion(env.PanelPath)
		env.PanelType = detectBaotaPanelType(env.PanelPath)
		// 读取宝塔实际的站点根目录（可能安装在数据盘上，如 /data/wwwroot）
		env.WebRoot = readBaotaWebRoot(env.PanelPath)
	}

	return env
}

// readBaotaWebRoot 从宝塔配置中读取实际的站点根目录。
// 宝塔的站点根目录可能不在 /www/wwwroot（用户可能选了数据盘），
// 实际路径存储在以下位置：
//   - /www/server/panel/data/default_path.pl  （宝塔 6.x+）
//   - /www/server/panel/config/config.json     （宝塔 5.x）
//   - /www/server/panel/data/sitepath.pl       （旧版本）
// 如果都读不到，回退到 /www/wwwroot。
func readBaotaWebRoot(panelPath string) string {
	// 方式1: default_path.pl（宝塔 6.x+ 存储 wwwroot 路径）
	paths := []string{
		panelPath + "/data/default_path.pl",
		panelPath + "/data/sitepath.pl",
	}
	for _, p := range paths {
		if data, err := os.ReadFile(p); err == nil {
			path := strings.TrimSpace(string(data))
			if path != "" {
				// 验证路径确实存在
				if fi, err := os.Stat(path); err == nil && fi.IsDir() {
					return path
				}
			}
		}
	}

	// 方式2: 从 config/config.json 中提取 default_path
	configFile := panelPath + "/config/config.json"
	if data, err := os.ReadFile(configFile); err == nil {
		content := string(data)
		// 查找 "default_path": "/xxx/wwwroot" 格式
		if idx := strings.Index(content, "default_path"); idx >= 0 {
			rest := content[idx:]
			for _, quote := range []byte{'"', '\''} {
				quoteStr := string(quote)
				// 找到 : 后面的引号
				if colonIdx := strings.Index(rest, ":"); colonIdx >= 0 {
					afterColon := rest[colonIdx+1:]
					// 跳过空格
					for len(afterColon) > 0 && afterColon[0] == ' ' {
						afterColon = afterColon[1:]
					}
					if len(afterColon) > 0 && afterColon[0] == quote {
						pathStart := afterColon[1:]
						if end := strings.Index(pathStart, quoteStr); end > 0 {
							path := pathStart[:end]
							if path != "" {
								if fi, err := os.Stat(path); err == nil && fi.IsDir() {
									return path
								}
							}
						}
					}
				}
			}
		}
	}

	// 方式3: 从 Nginx 配置中提取 root 路径
	// 宝塔的 Nginx vhost 配置文件中 root 指令指向实际站点路径
	vhostDir := "/www/server/panel/vhost/nginx/"
	if entries, err := os.ReadDir(vhostDir); err == nil {
		for _, entry := range entries {
			if entry.IsDir() {
				continue
			}
			ext := strings.ToLower(filepath.Ext(entry.Name()))
			if ext != ".conf" && ext != ".vhost" {
				continue
			}
			data, err := os.ReadFile(filepath.Join(vhostDir, entry.Name()))
			if err != nil {
				continue
			}
			content := string(data)
			// 查找 root /xxx/wwwroot/yyy; 格式
			lines := strings.Split(content, "\n")
			for _, line := range lines {
				line = strings.TrimSpace(line)
				if strings.HasPrefix(line, "root ") || strings.HasPrefix(line, "root\t") {
					// 提取路径
					pathPart := strings.TrimPrefix(line, "root")
					pathPart = strings.TrimPrefix(pathPart, "\t")
					pathPart = strings.TrimSpace(pathPart)
					pathPart = strings.TrimSuffix(pathPart, ";")
					pathPart = strings.Trim(pathPart, "\"'")
					// 取上级目录（root 指向 /xxx/wwwroot/site，上级 /xxx/wwwroot 就是根目录）
					if pathPart != "" && pathPart != "/" {
						parentDir := filepath.Dir(pathPart)
						if fi, err := os.Stat(parentDir); err == nil && fi.IsDir() {
							return parentDir
						}
					}
				}
			}
		}
	}

	// 回退到默认路径
	return "/www/wwwroot"
}

// readBaotaPort 从 /www/server/panel/data/port.pl 读取面板端口。
func readBaotaPort(panelPath string) int {
	data, err := os.ReadFile(panelPath + "/data/port.pl")
	if err != nil {
		return 0
	}
	portStr := strings.TrimSpace(string(data))
	port, err := strconv.Atoi(portStr)
	if err != nil {
		return 0
	}
	return port
}

// readBaotaVersion 从 version.pl 或 class/common.py 读取宝塔版本。
func readBaotaVersion(panelPath string) string {
	// 优先读 version.pl
	if data, err := os.ReadFile(panelPath + "/version.pl"); err == nil {
		v := strings.TrimSpace(string(data))
		if v != "" {
			return v
		}
	}

	// 回退到 class/common.py 中的版本字符串
	if data, err := os.ReadFile(panelPath + "/class/common.py"); err == nil {
		content := string(data)
		// 查找 version = 'x.x.x' 格式
		if idx := strings.Index(content, "version"); idx >= 0 {
			rest := content[idx:]
			for _, quote := range []byte{'\'', '"'} {
				quoteStr := string(quote)
				if start := strings.Index(rest, quoteStr); start >= 0 {
					afterQuote := rest[start+1:]
					if end := strings.Index(afterQuote, quoteStr); end >= 0 {
						v := afterQuote[:end]
						if isValidVersion(v) {
							return v
						}
					}
				}
			}
		}
	}

	// 不再使用 bt 14 命令获取版本 — 该命令在宝塔 Python 环境中启动新进程，
	// 会与正在运行的面板进程争抢 SQLite 数据库锁和 Python 模块，导致面板崩溃。
	// version.pl 和 common.py 已经足够获取版本号。

	return "unknown"
}

// isValidVersion 检查字符串是否像一个版本号（包含至少一个数字和点号）。
func isValidVersion(s string) bool {
	if len(s) == 0 || len(s) > 30 {
		return false
	}
	hasDigit := false
	hasDot := false
	for _, c := range s {
		if c >= '0' && c <= '9' {
			hasDigit = true
		}
		if c == '.' {
			hasDot = true
		}
	}
	return hasDigit && hasDot
}

// detectBaotaPanelType 检测面板类型（宝塔国内版 vs aaPanel 国际版）。
func detectBaotaPanelType(panelPath string) string {
	// 检查 aaPanel 标识
	if data, err := os.ReadFile(panelPath + "/config/config.json"); err == nil {
		content := string(data)
		if strings.Contains(strings.ToLower(content), "aapanel") {
			return "aapanel"
		}
	}

	// 检查语言文件目录
	if fi, err := os.Stat(panelPath + "/language/English/"); err == nil && fi.IsDir() {
		return "aapanel"
	}

	return "baota_cn"
}

// hasBaotaProcess 检查进程列表中是否存在 bt-panel 相关进程。
func hasBaotaProcess() bool {
	// 使用 pgrep 检测宝塔相关进程
	patterns := []string{
		"bt-panel",
		"BT-Panel",
		"Bt-Panel",
		"btpanel",
		"panelSite.py",
	}

	for _, pattern := range patterns {
		cmd := exec.Command("pgrep", "-f", pattern)
		if output, err := cmd.Output(); err == nil && len(output) > 0 {
			return true
		}
	}

	// pgrep 可能不存在，尝试读 /proc
	if processes, err := os.ReadDir("/proc"); err == nil {
		for _, entry := range processes {
			if !entry.IsDir() {
				continue
			}
			pid := entry.Name()
			if !isNumeric(pid) {
				continue
			}
			// 读取 cmdline
			if data, err := os.ReadFile("/proc/" + pid + "/cmdline"); err == nil {
				cmdline := strings.ReplaceAll(string(data), "\x00", " ")
				for _, pattern := range patterns {
					if strings.Contains(cmdline, pattern) {
						return true
					}
				}
			}
		}
	}

	return false
}

// isNumeric 检查字符串是否全为数字。
func isNumeric(s string) bool {
	if len(s) == 0 {
		return false
	}
	for _, c := range s {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}

// String 返回 BaotaEnv 的可读描述。
func (e *BaotaEnv) String() string {
	if !e.IsBaota {
		return "BaotaEnv(not baota environment)"
	}
	return fmt.Sprintf("BaotaEnv(detected=%v, path=%s, port=%d, version=%s, type=%s, signals=%d)",
		e.IsBaota, e.PanelPath, e.PanelPort, e.Version, e.PanelType, e.Signals)
}
