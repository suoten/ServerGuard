package scannercommon

import (
	"bytes"
	"fmt"
	"os/exec"
	"strings"
)

// ExternalScanner 外部扫描器接口
type ExternalScanner interface {
	Scan(target string, options map[string]string) ([]ExternalScanResult, error)
	IsAvailable() bool
	Version() string
}

// ExternalScanResult 外部扫描器结果
type ExternalScanResult struct {
	Scanner  string `json:"scanner"`
	Target   string `json:"target"`
	Detail   string `json:"detail"`
	Severity string `json:"severity"`
}

// baseScanner 基础扫描器实现
type baseScanner struct {
	name    string
	binary  string
	version string
}

// IsAvailable 检查扫描器是否可用
func (s *baseScanner) IsAvailable() bool {
	_, err := exec.LookPath(s.binary)
	return err == nil
}

// Version 返回扫描器版本
func (s *baseScanner) Version() string {
	if !s.IsAvailable() {
		return ""
	}
	cmd := exec.Command(s.binary, "--version")
	out, err := cmd.Output()
	if err != nil {
		return s.version
	}
	return strings.TrimSpace(string(out))
}

// run 执行扫描命令
func (s *baseScanner) run(args ...string) (string, error) {
	if !s.IsAvailable() {
		return "", fmt.Errorf("%s not available", s.name)
	}
	cmd := exec.Command(s.binary, args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("%s failed: %w, stderr: %s", s.name, err, stderr.String())
	}
	return stdout.String(), nil
}

// TrivyScanner trivy 漏洞扫描器
type TrivyScanner struct {
	baseScanner
}

// NewTrivyScanner 创建 trivy 扫描器
func NewTrivyScanner() *TrivyScanner {
	return &TrivyScanner{
		baseScanner: baseScanner{name: "trivy", binary: "trivy"},
	}
}

// Scan 扫描 Docker 镜像或文件系统漏洞
func (t *TrivyScanner) Scan(target string, options map[string]string) ([]ExternalScanResult, error) {
	format := options["format"]
	if format == "" {
		format = "json"
	}
	output, err := t.run("image", "--format", format, target)
	if err != nil {
		return nil, err
	}
	_ = output
	return []ExternalScanResult{
		{Scanner: "trivy", Target: target, Severity: "info"},
	}, nil
}

// GrypeScanner grype 漏洞扫描器
type GrypeScanner struct {
	baseScanner
}

// NewGrypeScanner 创建 grype 扫描器
func NewGrypeScanner() *GrypeScanner {
	return &GrypeScanner{
		baseScanner: baseScanner{name: "grype", binary: "grype"},
	}
}

// Scan 扫描漏洞
func (g *GrypeScanner) Scan(target string, options map[string]string) ([]ExternalScanResult, error) {
	output, err := g.run(target)
	if err != nil {
		return nil, err
	}
	_ = output
	return []ExternalScanResult{
		{Scanner: "grype", Target: target, Severity: "info"},
	}, nil
}

// RkhunterScanner rkhunter rootkit 检测器
type RkhunterScanner struct {
	baseScanner
}

// NewRkhunterScanner 创建 rkhunter 扫描器
func NewRkhunterScanner() *RkhunterScanner {
	return &RkhunterScanner{
		baseScanner: baseScanner{name: "rkhunter", binary: "rkhunter"},
	}
}

// Scan 执行 rootkit 检测
func (r *RkhunterScanner) Scan(target string, options map[string]string) ([]ExternalScanResult, error) {
	output, err := r.run("--check", "--sk", "--report-warnings-only")
	if err != nil {
		return nil, err
	}
	_ = output
	return []ExternalScanResult{
		{Scanner: "rkhunter", Target: target, Severity: "warning"},
	}, nil
}

// ChkrootkitScanner chkrootkit rootkit 检测器
type ChkrootkitScanner struct {
	baseScanner
}

// NewChkrootkitScanner 创建 chkrootkit 扫描器
func NewChkrootkitScanner() *ChkrootkitScanner {
	return &ChkrootkitScanner{
		baseScanner: baseScanner{name: "chkrootkit", binary: "chkrootkit"},
	}
}

// Scan 执行 rootkit 检测
func (c *ChkrootkitScanner) Scan(target string, options map[string]string) ([]ExternalScanResult, error) {
	output, err := c.run("-q")
	if err != nil {
		return nil, err
	}
	_ = output
	return []ExternalScanResult{
		{Scanner: "chkrootkit", Target: target, Severity: "warning"},
	}, nil
}

// NmapScanner nmap 端口扫描器
type NmapScanner struct {
	baseScanner
}

// NewNmapScanner 创建 nmap 扫描器
func NewNmapScanner() *NmapScanner {
	return &NmapScanner{
		baseScanner: baseScanner{name: "nmap", binary: "nmap"},
	}
}

// Scan 执行端口扫描
func (n *NmapScanner) Scan(target string, options map[string]string) ([]ExternalScanResult, error) {
	ports := options["ports"]
	if ports == "" {
		ports = "1-65535"
	}
	output, err := n.run("-sS", "-p", ports, "--open", target)
	if err != nil {
		return nil, err
	}
	_ = output
	return []ExternalScanResult{
		{Scanner: "nmap", Target: target, Severity: "info"},
	}, nil
}
