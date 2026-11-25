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
	stdioTermGraceTimeout = 2 * time.Second
	stdioTermPollInterval = 50 * time.Millisecond
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
// Chromium child trees cleanly, watching done and polling up to 2s before
// escalating to SIGKILL. Never signals -pgid once done has closed (pid reaped).
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
	pid := cmd.Process.Pid
	if pid <= 0 {
		return nil
	}
	if err := syscall.Kill(-pid, syscall.SIGTERM); err != nil {
		if errors.Is(err, syscall.ESRCH) {
			return os.ErrProcessDone
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
		case <-done:
			// Leader has been reaped by cmd.Wait(); do NOT signal -pid after reap
			// to prevent any PID-reuse kill hazard.
			return nil
		case <-deadline.C:
			if done != nil {
				select {
				case <-done:
					return nil
				default:
				}
			}
			err := syscall.Kill(-pid, syscall.SIGKILL)
			if errors.Is(err, syscall.ESRCH) {
				return nil
			}
			return err
		case <-ticker.C:
		}
	}
}
