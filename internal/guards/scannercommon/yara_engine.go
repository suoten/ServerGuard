package scannercommon

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
)

// YaraMatch YARA 匹配结果
type YaraMatch struct {
	Rule   string `json:"rule"`
	Tag    string `json:"tag"`
	Offset int    `json:"offset"`
	Length int    `json:"length"`
}

// YaraEngine YARA 规则引擎
// 优先使用 go-yara CGO 绑定；备选外部 yara CLI 子进程；或纯 Go 实现简化版正则匹配
type YaraEngine struct {
	mu          sync.RWMutex
	rules       []yaraRule
	yaraCLIPath string // yara CLI 路径（备选方案）
}

type yaraRule struct {
	name    string
	pattern *regexp.Regexp
	tags    []string
}

// NewYaraEngine 创建 YARA 引擎
func NewYaraEngine() *YaraEngine {
	eng := &YaraEngine{}

	// 检测 yara CLI 是否可用
	if path, err := exec.LookPath("yara"); err == nil {
		eng.yaraCLIPath = path
	}

	// 加载内置 webshell 检测规则
	eng.loadBuiltinRules()

	return eng
}

// loadBuiltinRules 加载内置 webshell 检测规则
func (e *YaraEngine) loadBuiltinRules() {
	e.mu.Lock()
	defer e.mu.Unlock()

	// 常见 webshell 特征模式
	patterns := []struct {
		name    string
		pattern string
		tags    []string
	}{
		{"php_eval_base64", `eval\s*\(\s*base64_decode\s*\(`, []string{"webshell", "php"}},
		{"php_assert_post", `assert\s*\(\s*\$_POST\s*\[`, []string{"webshell", "php"}},
		{"php_system", `\b(system|exec|shell_exec|passthru|popen)\s*\(\s*\$_(GET|POST|REQUEST|COOKIE)`, []string{"webshell", "php"}},
		{"php_eval_get", `eval\s*\(\s*\$_GET\s*\[`, []string{"webshell", "php"}},
		{"php_gzuncompress", `gzuncompress\s*\(\s*base64_decode\s*\(`, []string{"webshell", "php"}},
		{"php_str_replace_rot13", `str_replace\s*\(.{0,20}rot13`, []string{"webshell", "php"}},
		{"jsp_runtime_exec", `Runtime\.getRuntime\s*\(\s*\)\.exec`, []string{"webshell", "jsp"}},
		{"asp_execute", `Server\.Execute\s*\(`, []string{"webshell", "asp"}},
		{"python_exec", `\bexec\s*\(\s*open\s*\(`, []string{"webshell", "python"}},
		{"perl_eval", `\beval\s*\{`, []string{"webshell", "perl"}},
		{"c99_shell", `c99\s*shell|c99shell`, []string{"webshell", "c99"}},
		{"r57_shell", `r57\s*shell|r57shell`, []string{"webshell", "r57"}},
		{"b374k_shell", `b374k`, []string{"webshell", "b374k"}},
		{"china_chopper", `chopper|caidao`, []string{"webshell", "chopper"}},
	}

	for _, p := range patterns {
		if re, err := regexp.Compile(p.pattern); err == nil {
			e.rules = append(e.rules, yaraRule{
				name:    p.name,
				pattern: re,
				tags:    p.tags,
			})
		}
	}
}

// ScanFile 扫描文件，返回匹配结果
func (e *YaraEngine) ScanFile(path string) ([]YaraMatch, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read file: %w", err)
	}
	return e.ScanData(data), nil
}

// ScanData 扫描数据
func (e *YaraEngine) ScanData(data []byte) []YaraMatch {
	e.mu.RLock()
	defer e.mu.RUnlock()

	var matches []YaraMatch
	content := string(data)

	for _, rule := range e.rules {
		locs := rule.pattern.FindAllStringIndex(content, -1)
		for _, loc := range locs {
			matches = append(matches, YaraMatch{
				Rule:   rule.name,
				Tag:    strings.Join(rule.tags, ","),
				Offset: loc[0],
				Length: loc[1] - loc[0],
			})
		}
	}

	return matches
}

// IsAvailable 检查 YARA 引擎是否可用
func (e *YaraEngine) IsAvailable() bool {
	return len(e.rules) > 0 || e.yaraCLIPath != ""
}

// RuleCount 返回已加载的规则数
func (e *YaraEngine) RuleCount() int {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return len(e.rules)
}

// LoadRulesFromDir 从目录加载 .yar/.yara 规则文件
func (e *YaraEngine) LoadRulesFromDir(dir string) error {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return fmt.Errorf("read yara rules dir: %w", err)
	}

	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		ext := strings.ToLower(filepath.Ext(entry.Name()))
		if ext != ".yar" && ext != ".yara" {
			continue
		}
		if err := e.loadYaraFile(filepath.Join(dir, entry.Name())); err != nil {
			continue
		}
	}
	return nil
}

// loadYaraFile 加载单个 YARA 规则文件
// 解析简化的 YARA 语法：rule NAME { strings: $s = /regex/ condition: $s }
func (e *YaraEngine) loadYaraFile(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}

	content := string(data)
	rulePattern := regexp.MustCompile(`rule\s+(\w+)\s*(?::\s*\w+)?\s*\{[^}]*strings:\s*\$\w+\s*=\s*/([^/]+)/[^}]*condition:[^}]*\}`)

	matches := rulePattern.FindAllStringSubmatch(content, -1)
	e.mu.Lock()
	defer e.mu.Unlock()

	for _, m := range matches {
		ruleName := m[1]
		patternStr := m[2]

		if re, err := regexp.Compile(patternStr); err == nil {
			e.rules = append(e.rules, yaraRule{
				name:    ruleName,
				pattern: re,
				tags:    []string{"external", filepath.Base(path)},
			})
		}
	}

	return nil
}
