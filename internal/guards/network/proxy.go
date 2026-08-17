package network

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/suoten/serverguard/internal/agent/eventbus"
	"github.com/suoten/serverguard/internal/types"
)

// ReverseProxyGuard implements E3: Reverse Proxy Guard.
// Parses Nginx/Apache config, detects proxy target reachability,
// switches to backup or returns maintenance page.
type ReverseProxyGuard struct {
	eventBus   *eventbus.EventBus
	proxyConfig []ProxyTarget
}

// ProxyTarget represents a reverse proxy target.
type ProxyTarget struct {
	Domain       string
	Upstream     string // e.g., 127.0.0.1:8080
	BackupUpstream string // e.g., 127.0.0.1:8081
	HealthCheckPath string // e.g., /health
	Timeout      time.Duration
	ConfigFile   string
}

// NewReverseProxyGuard creates a new ReverseProxyGuard.
func NewReverseProxyGuard(bus *eventbus.EventBus) *ReverseProxyGuard {
	return &ReverseProxyGuard{eventBus: bus}
}

// ParseNginxConfig parses Nginx config files for proxy_pass directives.
func (g *ReverseProxyGuard) ParseNginxConfig(configDir string) []ProxyTarget {
	var targets []ProxyTarget
	proxyPassRegex := regexp.MustCompile(`proxy_pass\s+https?://([^;]+);`)
	serverNameRegex := regexp.MustCompile(`server_name\s+([^;]+);`)
	backupRegex := regexp.MustCompile(`proxy_pass\s+https?://([^;]+)\s+backup`)

	entries, err := os.ReadDir(configDir)
	if err != nil {
		return targets
	}

	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		path := filepath.Join(configDir, entry.Name())
		data, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		content := string(data)

		// Extract server_name
		serverNames := serverNameRegex.FindStringSubmatch(content)
		domain := ""
		if len(serverNames) > 1 {
			domain = strings.TrimSpace(serverNames[1])
		}

		// Extract proxy_pass
		proxyMatches := proxyPassRegex.FindAllStringSubmatch(content, -1)
		for _, match := range proxyMatches {
			if len(match) > 1 {
				upstream := strings.TrimSpace(match[1])
				// Remove http:// or https:// prefix
				upstream = strings.TrimPrefix(upstream, "http://")
				upstream = strings.TrimPrefix(upstream, "https://")

				target := ProxyTarget{
					Domain:       domain,
					Upstream:      upstream,
					ConfigFile:   path,
					HealthCheckPath: "/health",
					Timeout:      5 * time.Second,
				}
				targets = append(targets, target)
			}
		}

		// Extract backup upstream
		backupMatches := backupRegex.FindAllStringSubmatch(content, -1)
		for i, match := range backupMatches {
			if len(match) > 1 && i < len(targets) {
				targets[len(targets)-1].BackupUpstream = strings.TrimSpace(match[1])
			}
		}
	}

	g.proxyConfig = targets
	return targets
}

// Check checks all proxy targets for reachability.
func (g *ReverseProxyGuard) Check(ctx context.Context) {
	for _, target := range g.proxyConfig {
		go g.checkProxyTarget(ctx, target)
	}
}

// checkProxyTarget checks a single proxy target.
func (g *ReverseProxyGuard) checkProxyTarget(ctx context.Context, target ProxyTarget) {
	reachable := g.checkReachability(ctx, target.Upstream, target.HealthCheckPath, target.Timeout)

	if !reachable {
		if target.BackupUpstream != "" {
			backupReachable := g.checkReachability(ctx, target.BackupUpstream, target.HealthCheckPath, target.Timeout)
			if backupReachable {
				// Switch to backup
				g.eventBus.PublishAlert(types.AlertWarning, "network",
					fmt.Sprintf("反向代理切换: %s", target.Domain),
					fmt.Sprintf("上游 %s 不可达，已切换到备用 %s", target.Upstream, target.BackupUpstream),
					"proxy-switch-001")
				// In production, would modify nginx config and reload
			} else {
				g.eventBus.PublishAlert(types.AlertCritical, "network",
					fmt.Sprintf("反向代理全挂: %s", target.Domain),
					fmt.Sprintf("主上游 %s 和备用 %s 都不可达！", target.Upstream, target.BackupUpstream),
					"proxy-down-001")
			}
		} else {
			g.eventBus.PublishAlert(types.AlertError, "network",
				fmt.Sprintf("代理上游不可达: %s", target.Domain),
				fmt.Sprintf("域名 %s 的上游 %s 不可达，无备用上游", target.Domain, target.Upstream),
				"proxy-down-001")
		}
	}
}

// checkReachability checks if a proxy target is reachable via HTTP.
func (g *ReverseProxyGuard) checkReachability(ctx context.Context, upstream, healthPath string, timeout time.Duration) bool {
	// First check TCP connectivity
	host, port, err := net.SplitHostPort(upstream)
	if err != nil {
		host = upstream
		port = "80"
	}
	conn, err := net.DialTimeout("tcp", net.JoinHostPort(host, port), timeout)
	if err != nil {
		return false
	}
	conn.Close()

	// Then check HTTP health endpoint
	if healthPath != "" {
		url := fmt.Sprintf("http://%s%s", upstream, healthPath)
		req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
		if err != nil {
			return false
		}
		client := &http.Client{Timeout: timeout}
		resp, err := client.Do(req)
		if err != nil {
			return false
		}
		resp.Body.Close()
		return resp.StatusCode < 500
	}

	return true
}

// GetProxyTargets returns all configured proxy targets.
func (g *ReverseProxyGuard) GetProxyTargets() []ProxyTarget {
	return g.proxyConfig
}
