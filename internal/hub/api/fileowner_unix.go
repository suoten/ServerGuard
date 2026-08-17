//go:build !windows

package api

import (
	"os"
	"strconv"
	"syscall"
)

// getFileOwner 使用 syscall 获取文件所有者（比 exec.Command 快 100 倍）
func getFileOwner(info os.FileInfo, cache map[uint32]string) string {
	if stat, ok := info.Sys().(*syscall.Stat_t); ok {
		uid := stat.Uid
		if name, ok := cache[uid]; ok {
			return name
		}
		name := strconv.Itoa(int(uid))
		cache[uid] = name
		return name
	}
	return ""
}
