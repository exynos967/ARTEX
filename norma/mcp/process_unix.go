//go:build !windows

package mcp

import (
	"errors"
	"os"
	"os/exec"
	"syscall"
	"time"
)

const (
	stdioTermGraceTimeout = 1500 * time.Millisecond
	stdioTermPollInterval = 20 * time.Millisecond
)

func configureStdioProcess(cmd *exec.Cmd) {
	configureStdioProcessWithDone(cmd, nil)
}

func configureStdioProcessWithDone(cmd *exec.Cmd, done <-chan struct{}) {
	if cmd.SysProcAttr == nil {
		cmd.SysProcAttr = &syscall.SysProcAttr{}
	}
	cmd.SysProcAttr.Setpgid = true
	cmd.WaitDelay = 3 * time.Second
	cmd.Cancel = func() error { return killStdioProcess(cmd, done) }
}

// killStdioProcess gracefully shuts down the subprocess's entire process group:
// sends SIGTERM to -pgid first so Node/Playwright MCP servers have time to close
// Chromium child trees cleanly, polling until the entire group exits before
// escalating to SIGKILL. Never signals -pgid if done was already closed before
// entry (reaped leader / potentially recycled PID).
func killStdioProcess(cmd *exec.Cmd, done <-chan struct{}) error {
	if cmd == nil || cmd.Process == nil {
		return nil
	}
	if done != nil {
		select {
		case <-done:
			return os.ErrProcessDone
		default:
		}
	}
	return signalStdioProcessGroup(cmd.Process.Pid)
}

// killStdioAfterEOF tears down the subprocess's process group after stdin EOF.
// Even if the leader already exited and was reaped on EOF, POSIX/Linux keeps
// the PGID reserved as long as any descendant remains in the group, so
// signalling -pgid cleans up orphaned children (or returns ESRCH immediately if
// the group is already empty).
func killStdioAfterEOF(cmd *exec.Cmd, _ <-chan struct{}, _ bool) error {
	if cmd == nil || cmd.Process == nil {
		return nil
	}
	return signalStdioProcessGroup(cmd.Process.Pid)
}

func signalStdioProcessGroup(pid int) error {
	if pid <= 0 {
		return nil
	}
	if err := syscall.Kill(-pid, syscall.SIGTERM); err != nil {
		if errors.Is(err, syscall.ESRCH) {
			return nil
		}
		return err
	}
	deadline := time.NewTimer(stdioTermGraceTimeout)
	defer deadline.Stop()
	ticker := time.NewTicker(stdioTermPollInterval)
	defer ticker.Stop()
	for {
		if err := syscall.Kill(-pid, 0); errors.Is(err, syscall.ESRCH) {
			return nil
		}
		select {
		case <-deadline.C:
			err := syscall.Kill(-pid, syscall.SIGKILL)
			if errors.Is(err, syscall.ESRCH) {
				return nil
			}
			return err
		case <-ticker.C:
		}
	}
}
