//go:build windows

package executor

import (
	"os/exec"
)

// setSysProcAttr is a no-op on Windows.
func setSysProcAttr(cmd *exec.Cmd) {
	// Windows doesn't support Setsid
}

// reapZombie is a no-op on Windows (no zombie processes).
func reapZombie(ppid int32) error {
	// Windows doesn't have zombie processes
	return nil
}
