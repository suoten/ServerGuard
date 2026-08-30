package sitediscovery

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"sync"
)

// DiscoveredSite represents a website found by auto-discovery.
type DiscoveredSite struct {
	Name      string `json:"name"`
	URL       string `json:"url"`
	Domain    string `json:"domain"`
	Source    string `json:"source"`    // "nginx", "apache", "iis", "baota"
	Port      int    `json:"port"`
	SSL       bool   `json:"ssl"`
	ConfigFile string `json:"config_file,omitempty"`
	WebRoot   string `json:"web_root,omitempty"` // 网站文件根目录（从 Nginx root / Apache DocumentRoot 提取）
}

// Discovery scans the system for configured websites.
type Discovery struct {
	mu     sync.RWMutex
	sites  []DiscoveredSite
}

// New creates a new Discovery.
func New() *Discovery {
	return &Discovery{}
}

// Discover scans all sources and returns found websites.
// 优化：每个配置目录扫描完立即去重，避免 117+ 站点时一次性分配大 slice。
// 去重用 map，最终只在返回前转为 slice，中间过程内存占用极小。
func (d *Discovery) Discover() []DiscoveredSite {
	d.mu.Lock()
	defer d.mu.Unlock()

	// 用 map 做去重，避免先收集全部再过滤（减少峰值内存）
	seen := make(map[string]DiscoveredSite)

	if runtime.GOOS == "windows" {
		d.discoverIISStream(seen)
	} else {
		// 逐个目录扫描，每扫完一个目录后 seen map 已去重
		// 不再像原来那样把全部原始结果 append 到 d.sites 再去重
		d.discoverNginxStream(seen)
		d.discoverApacheStream(seen)
		d.discoverBaoTaStream(seen)
	}

	// 从 map 提取为 slice（此时已经是去重后的，比原来先收集再去重省内存）
	result := make([]DiscoveredSite, 0, len(seen))
	for _, s := range seen {
		// 过滤本地回环地址和无意义的站点
		key := s.Domain
		if key == "127.0.0.1" || key == "localhost" || key == "::1" || key == "0.0.0.0" {
			continue
		}
		result = append(result, s)
	}

	sort.Slice(result, func(i, j int) bool {
		return result[i].Name < result[j].Name
	})

	d.sites = result
	return result
}

// GetSites returns the last discovery result.
func (d *Discovery) GetSites() []DiscoveredSite {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return d.sites
}

// addSite adds a site to the seen map with deduplication.
func addSite(seen map[string]DiscoveredSite, site DiscoveredSite) {
	key := site.Domain
	if key == "" {
		key = site.URL
	}
	if _, exists := seen[key]; !exists {
		seen[key] = site
	}
}

// --- IIS Discovery (Windows) ---

func (d *Discovery) discoverIISStream(seen map[string]DiscoveredSite) {
	appcmd := `C:\Windows\System32\inetsrv\appcmd.exe`
	if _, err := os.Stat(appcmd); err != nil {
		return
	}

	output, err := exec.Command(appcmd, "list", "site", "/text:name").Output()
	if err != nil {
		return
	}

	siteNames := strings.Split(strings.TrimSpace(string(output)), "\n")
	for _, name := range siteNames {
		name = strings.TrimSpace(name)
		if name == "" {
			continue
		}

		bindingsOutput, err := exec.Command(appcmd, "list", "site", name, "/text:bindings").Output()
		if err != nil {
			continue
		}
		bindings := strings.TrimSpace(string(bindingsOutput))
		parseIISBindingsStream(seen, name, bindings)
	}
}

func parseIISBindingsStream(seen map[string]DiscoveredSite, siteName, bindings string) {
	for _, binding := range strings.Split(bindings, ",") {
		binding = strings.TrimSpace(binding)
		if binding == "" {
			continue
		}

		parts := strings.Split(binding, ":")
		if len(parts) < 2 {
			continue
		}

		protocol := parts[0]
		ssl := protocol == "https"

		port := 80
		host := ""
		if len(parts) >= 3 {
			fmt.Sscanf(parts[len(parts)-2], "%d", &port)
			host = parts[len(parts)-1]
		} else {
			fmt.Sscanf(parts[1], "%d", &port)
		}

		scheme := "http"
		if ssl {
			scheme = "https"
		}

		if ssl && port == 80 {
			port = 443
		}

		url := fmt.Sprintf("%s://%s", scheme, host)
		if host == "" {
			url = fmt.Sprintf("%s://localhost:%d", scheme, port)
		} else if (!ssl && port != 80) || (ssl && port != 443) {
			url = fmt.Sprintf("%s://%s:%d", scheme, host, port)
		}

		if host == "" {
			host = siteName
		}

		addSite(seen, DiscoveredSite{
			Name:   siteName,
			URL:    url,
			Domain: host,
			Source: "iis",
			Port:   port,
			SSL:    ssl,
		})
	}
}

// --- Nginx Discovery (Linux) ---

var (
	nginxServerNameRe = regexp.MustCompile(`server_name\s+(.+?);`)
	nginxListenRe     = regexp.MustCompile(`listen\s+(\d+)`)
	nginxListenSSLRe  = regexp.MustCompile(`listen\s+(\d+)\s+ssl`)
	nginxSSLRe        = regexp.MustCompile(`ssl\s+on|listen\s+\d+\s+ssl`)
	// Nginx root 指令：root /www/wwwroot/example.com;
	// 兼容带引号和不带引号的路径，兼容 root $variable; （跳过变量）
	nginxRootRe = regexp.MustCompile(`(?m)^\s*root\s+([^;\s$]+)\s*;`)
)

func (d *Discovery) discoverNginxStream(seen map[string]DiscoveredSite) {
	configDirs := []string{
		"/etc/nginx/conf.d/",
		"/etc/nginx/sites-enabled/",
		"/www/server/panel/vhost/nginx/",
		"/usr/local/nginx/conf/vhost/",
	}

	for _, dir := range configDirs {
		entries, err := os.ReadDir(dir)
		if err != nil {
			continue
		}
		for _, entry := range entries {
			if entry.IsDir() || !isConfigFile(entry.Name()) {
				continue
			}
			path := filepath.Join(dir, entry.Name())
			parseNginxConfigStream(seen, path)
		}
	}
}

func parseNginxConfigStream(seen map[string]DiscoveredSite, path string) {
	data, err := os.ReadFile(path)
	if err != nil {
		return
	}
	content := string(data)

	serverNameMatches := nginxServerNameRe.FindStringSubmatch(content)
	if len(serverNameMatches) < 2 {
		return
	}
	serverNames := strings.Split(strings.TrimSpace(serverNameMatches[1]), " ")

	port := 80
	if sslListenMatches := nginxListenSSLRe.FindStringSubmatch(content); len(sslListenMatches) >= 2 {
		fmt.Sscanf(sslListenMatches[1], "%d", &port)
	} else if listenMatches := nginxListenRe.FindStringSubmatch(content); len(listenMatches) >= 2 {
		fmt.Sscanf(listenMatches[1], "%d", &port)
	}

	ssl := nginxSSLRe.MatchString(content) || port == 443

	// 提取 root 指令（网站文件根目录）
	webRoot := ""
	if rootMatches := nginxRootRe.FindStringSubmatch(content); len(rootMatches) >= 2 {
		rootPath := strings.TrimSpace(rootMatches[1])
		// 跳过 Nginx 变量（如 $root_path）
		if !strings.HasPrefix(rootPath, "$") && rootPath != "/" {
			// 验证路径是否存在
			if _, statErr := os.Stat(rootPath); statErr == nil {
				webRoot = rootPath
			}
		}
	}

	for _, name := range serverNames {
		name = strings.TrimSuffix(strings.TrimSpace(name), ";")
		if name == "" || name == "_" || name == "*" {
			continue
		}

		scheme := "http"
		if ssl {
			scheme = "https"
		}

		if ssl && port == 80 {
			port = 443
		}

		url := fmt.Sprintf("%s://%s", scheme, name)
		if (!ssl && port != 80) || (ssl && port != 443) {
			url = fmt.Sprintf("%s://%s:%d", scheme, name, port)
		}

		addSite(seen, DiscoveredSite{
			Name:       name,
			URL:        url,
			Domain:     name,
			Source:     "nginx",
			Port:       port,
			SSL:        ssl,
			ConfigFile: path,
			WebRoot:    webRoot,
		})
	}
}

// isApacheRunning checks if Apache (httpd or apache2) is actually running.
func isApacheRunning() bool {
	for _, pattern := range []string{"httpd", "apache2"} {
		cmd := exec.Command("pgrep", "-x", pattern)
		if output, err := cmd.Output(); err == nil && len(output) > 0 {
			return true
		}
	}
	return false
}

// --- Apache Discovery (Linux) ---

var (
	apacheServerNameRe   = regexp.MustCompile(`ServerName\s+(\S+)`)
	apacheVhostPortRe    = regexp.MustCompile(`VirtualHost\s+\*:(\d+)`)
	apacheDocumentRootRe = regexp.MustCompile(`(?i)DocumentRoot\s+"?([^"\s]+)"?`)
)

func (d *Discovery) discoverApacheStream(seen map[string]DiscoveredSite) {
	if !isApacheRunning() {
		return
	}

	configDirs := []string{
		"/etc/apache2/sites-enabled/",
		"/etc/httpd/conf.d/",
		"/www/server/panel/vhost/apache/",
	}

	for _, dir := range configDirs {
		entries, err := os.ReadDir(dir)
		if err != nil {
			continue
		}
		for _, entry := range entries {
			if entry.IsDir() || !isConfigFile(entry.Name()) {
				continue
			}
			path := filepath.Join(dir, entry.Name())
			parseApacheConfigStream(seen, path)
		}
	}
}

func parseApacheConfigStream(seen map[string]DiscoveredSite, path string) {
	data, err := os.ReadFile(path)
	if err != nil {
		return
	}
	content := string(data)

	port := 80
	portMatches := apacheVhostPortRe.FindStringSubmatch(content)
	if len(portMatches) >= 2 {
		fmt.Sscanf(portMatches[1], "%d", &port)
	}

	nameMatches := apacheServerNameRe.FindStringSubmatch(content)
	if len(nameMatches) < 2 {
		return
	}
	name := strings.TrimSpace(nameMatches[1])

	ssl := port == 443 || strings.Contains(content, "SSLEngine on")

	// 提取 DocumentRoot（网站文件根目录）
	webRoot := ""
	if rootMatches := apacheDocumentRootRe.FindStringSubmatch(content); len(rootMatches) >= 2 {
		rootPath := strings.TrimSpace(rootMatches[1])
		if rootPath != "/" {
			if _, statErr := os.Stat(rootPath); statErr == nil {
				webRoot = rootPath
			}
		}
	}

	scheme := "http"
	if ssl {
		scheme = "https"
	}

	if ssl && port == 80 {
		port = 443
	}

	url := fmt.Sprintf("%s://%s", scheme, name)
	if (!ssl && port != 80) || (ssl && port != 443) {
		url = fmt.Sprintf("%s://%s:%d", scheme, name, port)
	}

	addSite(seen, DiscoveredSite{
		Name:       name,
		URL:        url,
		Domain:     name,
		Source:     "apache",
		Port:       port,
		SSL:        ssl,
		ConfigFile: path,
		WebRoot:    webRoot,
	})
}

// --- BaoTa Discovery (Linux) ---

func (d *Discovery) discoverBaoTaStream(seen map[string]DiscoveredSite) {
	vhostDir := "/www/server/panel/vhost/nginx/"
	entries, err := os.ReadDir(vhostDir)
	if err != nil {
		return
	}

	for _, entry := range entries {
		if entry.IsDir() || !isConfigFile(entry.Name()) {
			continue
		}
		path := filepath.Join(vhostDir, entry.Name())
		data, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		content := string(data)

		serverNameMatches := nginxServerNameRe.FindStringSubmatch(content)
		if len(serverNameMatches) < 2 {
			continue
		}
		serverNames := strings.Split(strings.TrimSpace(serverNameMatches[1]), " ")

		port := 80
		if sslListenMatches := nginxListenSSLRe.FindStringSubmatch(content); len(sslListenMatches) >= 2 {
			fmt.Sscanf(sslListenMatches[1], "%d", &port)
		} else if listenMatches := nginxListenRe.FindStringSubmatch(content); len(listenMatches) >= 2 {
			fmt.Sscanf(listenMatches[1], "%d", &port)
		}

	ssl := nginxSSLRe.MatchString(content) || port == 443

	// 提取 root 指令（宝塔 Nginx 配置中的 root 指向站点根目录）
	webRoot := ""
	if rootMatches := nginxRootRe.FindStringSubmatch(content); len(rootMatches) >= 2 {
		rootPath := strings.TrimSpace(rootMatches[1])
		if !strings.HasPrefix(rootPath, "$") && rootPath != "/" {
			if _, statErr := os.Stat(rootPath); statErr == nil {
				webRoot = rootPath
			}
		}
	}

	for _, name := range serverNames {
		name = strings.TrimSuffix(strings.TrimSpace(name), ";")
		if name == "" || name == "_" {
			continue
		}

		scheme := "http"
		if ssl {
			scheme = "https"
		}

		if ssl && port == 80 {
			port = 443
		}

		url := fmt.Sprintf("%s://%s", scheme, name)
		if (!ssl && port != 80) || (ssl && port != 443) {
			url = fmt.Sprintf("%s://%s:%d", scheme, name, port)
		}

		addSite(seen, DiscoveredSite{
			Name:       name,
			URL:        url,
			Domain:     name,
			Source:     "baota",
			Port:       port,
			SSL:        ssl,
			ConfigFile: path,
			WebRoot:    webRoot,
		})
	}
	}
}

func isConfigFile(name string) bool {
	ext := strings.ToLower(filepath.Ext(name))
	return ext == ".conf" || ext == ".vhost" || ext == "" || ext == ".cfg"
}
