//go:build windows

package api

import "os"

// getFileOwner on Windows returns empty string (owner info not available via syscall)
func getFileOwner(info os.FileInfo, cache map[uint32]string) string {
	return ""
}
