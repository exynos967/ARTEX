//go:build !windows

package server

import (
	"os/exec"
	"syscall"
	"time"
)

// configurePythonCmd places the Python subprocess in its own process group so
// cancellation kills the entire process tree instead of leaving orphan children
// holding stdout/stderr pipes open.
func configurePythonCmd(cmd *exec.Cmd) {
	if cmd.SysProcAttr == nil {
		cmd.SysProcAttr = &syscall.SysProcAttr{}
	}
	cmd.SysProcAttr.Setpgid = true
	cmd.Cancel = func() error {
		if cmd.Process == nil {
			return nil
		}
		if err := syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL); err != nil {
			return cmd.Process.Kill()
		}
		return nil
	}
	cmd.WaitDelay = 3 * time.Second
}
