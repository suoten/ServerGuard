package platform

import (
	"net"
	"regexp"
	"strconv"
	"strings"
)

// banExpireRe 从规则注释中提取到期时间戳（exp=<unix>；无该字段=旧格式/永久）
var banExpireRe = regexp.MustCompile(`\bexp=(\d+)\b`)

// parseBanRuleLine 解析 `iptables -L INPUT -n --line-numbers` 输出中的规则行。
// 行格式: <行号> <target> <prot> -- <source> <destination> [/* 注释 */]
// 返回 行号（用于 -D INPUT <num> 删除）、源IP、到期Unix时间戳
// （0 = 永久/无 exp 字段的旧格式，永不过期以保证兼容）。
// 非本工具添加的规则返回 ok=false。
// 纯字符串逻辑，与平台无关——独立成文件以便在任意平台单测。
func parseBanRuleLine(line string) (lineNum, sourceIP string, expireUnix int64, ok bool) {
	if !strings.Contains(line, "serverguard") {
		return "", "", 0, false
	}
	fields := strings.Fields(line)
	if len(fields) < 5 || !isAllDigits(fields[0]) {
		return "", "", 0, false
	}
	// fields: [num, target, prot, "--", source, ...]
	if fields[3] != "--" {
		return "", "", 0, false
	}
	source := fields[4]
	if idx := strings.Index(source, "/"); idx > 0 {
		source = source[:idx]
	}
	if net.ParseIP(source) == nil {
		return "", "", 0, false
	}
	var expire int64
	if m := banExpireRe.FindStringSubmatch(line); len(m) == 2 {
		if v, err := strconv.ParseInt(m[1], 10, 64); err == nil {
			expire = v
		}
	}
	return fields[0], source, expire, true
}

func isAllDigits(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}
