// Package forecast 磁盘增长热点定位。
//
// 磁盘写满预测回答"什么时候满"，热点定位回答"哪里在涨"——
// 两者一起给出，用户看完告警就知道该清哪里，不用自己登服务器翻目录。
// 扫描策略保守：仅浅层（一级子目录）、限定候选目录、单目录 10s 超时，
// 只在预测告警发出时执行（每挂载点每天最多一次），绝不拖累系统。
package forecast

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"
)

// dirSize 单目录大小项（MB）。
type dirSize struct {
	path   string
	sizeMB int
}

// collectHotspots 浅层扫描候选目录，返回 TOP3 空间占用子目录的描述文本。
// mount 为预测告警的挂载点；仅 Linux 生效，失败/超时静默返回空串。
func collectHotspots(mount string) string {
	if runtime.GOOS == "windows" {
		return ""
	}

	// 候选目录：根挂载扫常见增长目录；其他挂载点扫自身
	candidates := []string{mount}
	if mount == "/" {
		candidates = []string{"/var/log", "/www", "/home", "/opt", "/tmp"}
	}

	var all []dirSize
	for _, dir := range candidates {
		if !dirExists(dir) {
			continue
		}
		all = append(all, duShallow(dir)...)
	}
	if len(all) == 0 {
		return ""
	}

	// 去重（挂载点与候选目录可能重叠）后按大小降序取 TOP3
	seen := make(map[string]bool)
	uniq := all[:0]
	for _, d := range all {
		if seen[d.path] {
			continue
		}
		seen[d.path] = true
		uniq = append(uniq, d)
	}
	sort.Slice(uniq, func(i, j int) bool { return uniq[i].sizeMB > uniq[j].sizeMB })
	if len(uniq) > 3 {
		uniq = uniq[:3]
	}

	var parts []string
	for _, d := range uniq {
		if d.sizeMB >= 1024 {
			parts = append(parts, fmt.Sprintf("%s %.1fG", d.path, float64(d.sizeMB)/1024))
		} else {
			parts = append(parts, fmt.Sprintf("%s %dM", d.path, d.sizeMB))
		}
	}
	return "\n📂 空间占用热点（浅层扫描）：" + strings.Join(parts, " · ")
}

// duShallow 对单目录做一级子目录大小统计（du -x -d 1 -m），10 秒超时。
func duShallow(dir string) []dirSize {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	out, err := exec.CommandContext(ctx, "du", "-x", "-d", "1", "-m", dir).Output()
	cancel()
	if err != nil {
		return nil
	}

	var result []dirSize
	for _, line := range strings.Split(string(out), "\n") {
		fields := strings.SplitN(line, "\t", 2)
		if len(fields) != 2 {
			continue
		}
		size, err := strconv.Atoi(strings.TrimSpace(fields[0]))
		if err != nil {
			continue
		}
		path := strings.TrimSpace(fields[1])
		if path == dir {
			continue // 排除目录自身的汇总行
		}
		result = append(result, dirSize{path: path, sizeMB: size})
	}
	return result
}

// dirExists 判断目录存在且可读。
func dirExists(path string) bool {
	info, err := os.Stat(path)
	return err == nil && info.IsDir()
}
