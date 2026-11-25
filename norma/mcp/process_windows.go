//go:build windows

package mcp

import (
	"context"
	"os"
	"os/exec"
	"strconv"
	"syscall"
	"time"
)

const createNewProcessGroup = 0x00000200 // CREATE_NEW_PROCESS_GROUP

func configureStdioProcess(cmd *exec.Cmd) {
	configureStdioProcessWithDone(cmd, nil)
}

func configureStdioProcessWithDone(cmd *exec.Cmd, done <-chan struct{}) {
	if cmd.SysProcAttr == nil {
		cmd.SysProcAttr = &syscall.SysProcAttr{}
	}
	cmd.SysProcAttr.CreationFlags |= createNewProcessGroup
	cmd.WaitDelay = 3 * time.Second
	cmd.Cancel = func() error { return killStdioProcess(cmd, done) }
}

// killStdioProcess terminates the subprocess and its child tree on Windows via
// taskkill /T /F, falling back to Process.Kill when taskkill fails. Never runs
// after done closes (pid already reaped).
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
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := exec.CommandContext(ctx, "taskkill", "/T", "/F", "/PID", strconv.Itoa(pid)).Run(); err != nil {
		if done != nil {
			select {
			case <-done:
				return os.ErrProcessDone
			default:
			}
		}
		return cmd.Process.Kill()
	}
	return nil
}
