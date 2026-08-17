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
func (d *Discovery) Discover() []DiscoveredSite {
	d.mu.Lock()
	defer d.mu.Unlock()

	d.sites = d.sites[:0]

	if runtime.GOOS == "windows" {
		d.discoverIIS()
	} else {
		d.discoverNginx()
		d.discoverApache()
		d.discoverBaoTa()
	}

	// Deduplicate by domain
	seen := make(map[string]bool)
	unique := make([]DiscoveredSite, 0, len(d.sites))
	for _, s := range d.sites {
		key := s.Domain
		if key == "" {
			key = s.URL
		}
		// 过滤本地回环地址和无意义的站点
		if key == "127.0.0.1" || key == "localhost" || key == "::1" || key == "0.0.0.0" {
			continue
		}
		if !seen[key] {
			seen[key] = true
			unique = append(unique, s)
		}
	}

	sort.Slice(unique, func(i, j int) bool {
		return unique[i].Name < unique[j].Name
	})

	d.sites = unique
	return unique
}

// GetSites returns the last discovery result.
func (d *Discovery) GetSites() []DiscoveredSite {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return d.sites
}

// --- IIS Discovery (Windows) ---

func (d *Discovery) discoverIIS() {
	// Use appcmd to list sites
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

		// Get bindings for this site
		bindingsOutput, err := exec.Command(appcmd, "list", "site", name, "/text:bindings").Output()
		if err != nil {
			continue
		}
		bindings := strings.TrimSpace(string(bindingsOutput))

		// Parse bindings like "http/*:80:example.com,https/*:443:example.com"
		d.parseIISBindings(name, bindings)
	}
}

func (d *Discovery) parseIISBindings(siteName, bindings string) {
	for _, binding := range strings.Split(bindings, ",") {
		binding = strings.TrimSpace(binding)
		if binding == "" {
			continue
		}

		// Format: protocol/ip:port:hostheader or protocol/port
		parts := strings.Split(binding, ":")
		if len(parts) < 2 {
			continue
		}

		protocol := parts[0]
		ssl := protocol == "https"

		// Extract port and host
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

		// If SSL is detected but port is 80, the actual SSL port is 443
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

		d.sites = append(d.sites, DiscoveredSite{
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
)

func (d *Discovery) discoverNginx() {
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
			d.parseNginxConfig(path)
		}
	}
}

func (d *Discovery) parseNginxConfig(path string) {
	data, err := os.ReadFile(path)
	if err != nil {
		return
	}
	content := string(data)

	// Extract server names
	serverNameMatches := nginxServerNameRe.FindStringSubmatch(content)
	if len(serverNameMatches) < 2 {
		return
	}
	serverNames := strings.Split(strings.TrimSpace(serverNameMatches[1]), " ")

	// Extract listen port — prefer SSL listen port if present (BaoTa configs have both listen 80 and listen 443 ssl)
	port := 80
	if sslListenMatches := nginxListenSSLRe.FindStringSubmatch(content); len(sslListenMatches) >= 2 {
		fmt.Sscanf(sslListenMatches[1], "%d", &port)
	} else if listenMatches := nginxListenRe.FindStringSubmatch(content); len(listenMatches) >= 2 {
		fmt.Sscanf(listenMatches[1], "%d", &port)
	}

	// Check SSL
	ssl := nginxSSLRe.MatchString(content) || port == 443

	for _, name := range serverNames {
		name = strings.TrimSuffix(strings.TrimSpace(name), ";")
		if name == "" || name == "_" || name == "*" {
			continue
		}

		scheme := "http"
		if ssl {
			scheme = "https"
		}

		// If SSL is detected but port is 80 (common in BaoTa combined configs),
		// the actual SSL port is 443
		if ssl && port == 80 {
			port = 443
		}

		url := fmt.Sprintf("%s://%s", scheme, name)
		if (!ssl && port != 80) || (ssl && port != 443) {
			url = fmt.Sprintf("%s://%s:%d", scheme, name, port)
		}

		d.sites = append(d.sites, DiscoveredSite{
			Name:       name,
			URL:        url,
			Domain:     name,
			Source:     "nginx",
			Port:       port,
			SSL:        ssl,
			ConfigFile: path,
		})
	}
}

// isApacheRunning checks if Apache (httpd or apache2) is actually running.
// 宝塔会为每个站点生成 Apache vhost 文件，即使没装 Apache 也会有。
// 只在 Apache 实际运行时才扫描其配置。
func isApacheRunning() bool {
	// 检查 httpd 或 apache2 进程是否存在
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
	apacheServerNameRe = regexp.MustCompile(`ServerName\s+(\S+)`)
	apacheVhostPortRe  = regexp.MustCompile(`VirtualHost\s+\*:(\d+)`)
)

func (d *Discovery) discoverApache() {
	// 先检查 Apache 是否在运行 — 宝塔创建站点时会同时生成 Apache vhost 文件，
	// 即使没装 Apache 也会生成。只扫描实际运行的 Apache 配置。
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
			d.parseApacheConfig(path)
		}
	}
}

func (d *Discovery) parseApacheConfig(path string) {
	data, err := os.ReadFile(path)
	if err != nil {
		return
	}
	content := string(data)

	// Extract port from VirtualHost
	port := 80
	portMatches := apacheVhostPortRe.FindStringSubmatch(content)
	if len(portMatches) >= 2 {
		fmt.Sscanf(portMatches[1], "%d", &port)
	}

	// Extract ServerName
	nameMatches := apacheServerNameRe.FindStringSubmatch(content)
	if len(nameMatches) < 2 {
		return
	}
	name := strings.TrimSpace(nameMatches[1])

	ssl := port == 443 || strings.Contains(content, "SSLEngine on")

	scheme := "http"
	if ssl {
		scheme = "https"
	}

	// If SSL is detected but port is 80 (common in combined configs),
	// the actual SSL port is 443
	if ssl && port == 80 {
		port = 443
	}

	url := fmt.Sprintf("%s://%s", scheme, name)
	if (!ssl && port != 80) || (ssl && port != 443) {
		url = fmt.Sprintf("%s://%s:%d", scheme, name, port)
	}

	d.sites = append(d.sites, DiscoveredSite{
		Name:       name,
		URL:        url,
		Domain:     name,
		Source:     "apache",
		Port:       port,
		SSL:        ssl,
		ConfigFile: path,
	})
}

// --- BaoTa Discovery (Linux) ---

func (d *Discovery) discoverBaoTa() {
	// BaoTa nginx vhost directory
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

		for _, name := range serverNames {
			name = strings.TrimSuffix(strings.TrimSpace(name), ";")
			if name == "" || name == "_" {
				continue
			}

			scheme := "http"
			if ssl {
				scheme = "https"
			}

		// If SSL is detected but port is 80 (common in BaoTa combined configs),
		// the actual SSL port is 443
		if ssl && port == 80 {
			port = 443
		}

		url := fmt.Sprintf("%s://%s", scheme, name)
		if (!ssl && port != 80) || (ssl && port != 443) {
			url = fmt.Sprintf("%s://%s:%d", scheme, name, port)
		}

		d.sites = append(d.sites, DiscoveredSite{
			Name:       name,
			URL:        url,
			Domain:     name,
			Source:     "baota",
				Port:       port,
				SSL:        ssl,
				ConfigFile: path,
			})
		}
	}
}

func isConfigFile(name string) bool {
	ext := strings.ToLower(filepath.Ext(name))
	return ext == ".conf" || ext == ".vhost" || ext == "" || ext == ".cfg"
}
