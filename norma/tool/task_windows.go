//go:build windows

package tool

import (
	"context"
	"os"
	"os/exec"
	"strconv"
	"syscall"
	"time"
)

// createNewProcessGroup isolates the child from our console so it survives the
// per-turn context.
const (
	createNewProcessGroup = 0x00000200 // CREATE_NEW_PROCESS_GROUP
	cmdWaitDelay          = 3 * time.Second
)

func setDetached(cmd *exec.Cmd) {
	setDetachedWithCgroup(cmd, nil)
}

func setDetachedWithCgroup(cmd *exec.Cmd, _ *cmdCgroup) {
	if cmd.SysProcAttr == nil {
		cmd.SysProcAttr = &syscall.SysProcAttr{}
	}
	cmd.SysProcAttr.CreationFlags |= createNewProcessGroup
	cmd.WaitDelay = cmdWaitDelay
	cmd.Cancel = func() error {
		if cmd.Process == nil {
			return nil
		}
		treeKill(cmd.Process)
		return nil
	}
}

// treeKill terminates the process and its descendants via taskkill, falling
// back to Process.Kill when taskkill fails.
func treeKill(p *os.Process) {
	if p == nil || p.Pid <= 0 {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := exec.CommandContext(ctx, "taskkill", "/T", "/F", "/PID", strconv.Itoa(p.Pid)).Run(); err != nil {
		_ = p.Kill()
	}
}

func treeKillWithDone(p *os.Process, _ <-chan struct{}, _ *cmdCgroup) {
	treeKill(p)
}

func forceKillProcessGroup(p *os.Process) {
	treeKill(p)
}
