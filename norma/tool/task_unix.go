//go:build !windows

package tool

import (
	"errors"
	"os"
	"os/exec"
	"syscall"
	"time"
)

const (
	cmdWaitDelay     = 3 * time.Second
	gracefulKillWait = 2 * time.Second
)

// setDetached puts the child in its own process group so it survives the
// per-turn context and can be killed as a whole tree, and bounds pipe drain
// with WaitDelay so escaped grandchildren cannot hang Wait().
func setDetached(cmd *exec.Cmd) {
	setDetachedWithCgroup(cmd, nil)
}

func setDetachedWithCgroup(cmd *exec.Cmd, cg *cmdCgroup) {
	if cmd.SysProcAttr == nil {
		cmd.SysProcAttr = &syscall.SysProcAttr{}
	}
	cmd.SysProcAttr.Setpgid = true
	cmd.WaitDelay = cmdWaitDelay
	cmd.Cancel = func() error {
		if cmd.Process == nil {
			return nil
		}
		treeKillWithDone(cmd.Process, nil, cg)
		return nil
	}
}

// treeKill terminates the process group gracefully (SIGTERM -> SIGKILL),
// falling back to the lone process.
func treeKill(p *os.Process) {
	treeKillWithDone(p, nil, nil)
}

// forceKillProcessGroup sends SIGKILL directly to -p.Pid (falling back to
// p.Kill) without a graceful-shutdown delay. Used when rejecting a freshly
// spawned PTY process that hit the active-session cap before readLoop starts.
func forceKillProcessGroup(p *os.Process) {
	if p == nil || p.Pid <= 0 {
		return
	}
	if err := syscall.Kill(-p.Pid, syscall.SIGKILL); err != nil && !errors.Is(err, syscall.ESRCH) {
		_ = p.Kill()
	}
}

// treeKillWithDone sends SIGTERM to the process group first, waits briefly for
// graceful shutdown (or until done closes / the pgid disappears), then forces
// cgroup.kill (when active on Linux) and SIGKILL on the process group.
func treeKillWithDone(p *os.Process, done <-chan struct{}, cg *cmdCgroup) {
	if p == nil || p.Pid <= 0 {
		if cg != nil {
			_ = cg.kill()
		}
		return
	}

	if err := syscall.Kill(-p.Pid, syscall.SIGTERM); errors.Is(err, syscall.ESRCH) {
		// Process group is already gone; still reap any setsid()-escaped cgroup members.
		if cg != nil {
			_ = cg.kill()
		}
		return
	} else if err != nil {
		_ = p.Signal(syscall.SIGTERM)
	}

	exited := false
	deadline := time.NewTimer(gracefulKillWait)
	defer deadline.Stop()
	ticker := time.NewTicker(25 * time.Millisecond)
	defer ticker.Stop()

waitLoop:
	for {
		select {
		case <-done:
			exited = true
			break waitLoop
		case <-deadline.C:
			break waitLoop
		case <-ticker.C:
			if errors.Is(syscall.Kill(-p.Pid, 0), syscall.ESRCH) {
				exited = true
				break waitLoop
			}
		}
	}

	if cg != nil {
		_ = cg.kill()
	}
	if !exited {
		if err := syscall.Kill(-p.Pid, syscall.SIGKILL); err != nil && !errors.Is(err, syscall.ESRCH) {
			_ = p.Kill()
		}
		return
	}
	// If the leader exited (done closed), still reap any remaining pgid members.
	if !errors.Is(syscall.Kill(-p.Pid, 0), syscall.ESRCH) {
		_ = syscall.Kill(-p.Pid, syscall.SIGKILL)
	}
}
