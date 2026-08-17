//go:build !windows

package executor

import (
	"os/exec"
	"syscall"

	"github.com/shirou/gopsutil/v3/process"
)

// setSysProcAttr sets Unix-specific process attributes (Setsid).
func setSysProcAttr(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
}

// reapZombie sends SIGCHLD to a zombie's parent process.
func reapZombie(ppid int32) error {
	parent, err := process.NewProcess(ppid)
	if err == nil {
		return parent.SendSignal(syscall.SIGCHLD)
	}
	return err
}
