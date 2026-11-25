//go:build linux

package tool

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Linux cgroup v2 per-command process containment.
//
// When the process runs inside a writable cgroup v2 subtree with cgroup.kill
// support (Linux >= 5.14), each command gets a dedicated child cgroup
// (artex-cmd-<pid>-<seq>). Attaching the child PID via cgroup.procs keeps every
// descendant — including grandchildren that call setsid() such as Chromium —
// inside the cgroup so writing "1" to cgroup.kill reaps the entire tree.
// Writing cgroup.procs post-Start avoids clone3(CLONE_INTO_CGROUP) seccomp
// rejections in restricted container runtimes.

var (
	cgroupV2Once sync.Once
	cgroupV2Root string
	cgroupSeq    atomic.Int64
)

// parseCgroupV2Path extracts the unified cgroup v2 mount path from
// /proc/self/cgroup content (the "0::<relpath>" entry).
func parseCgroupV2Path(procSelfCgroup string) (string, bool) {
	for _, line := range strings.Split(procSelfCgroup, "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "0::") {
			continue
		}
		rel := strings.TrimPrefix(line, "0::")
		rel = strings.TrimPrefix(strings.TrimSpace(rel), "/")
		return filepath.Join("/sys/fs/cgroup", rel), true
	}
	return "", false
}

// probeCgroupV2Root checks whether base is a writable cgroup v2 directory whose
// child cgroups expose both cgroup.procs and cgroup.kill.
func probeCgroupV2Root(base string) bool {
	if base == "" {
		return false
	}
	probe := filepath.Join(base, fmt.Sprintf("artex-probe-%d-%d", os.Getpid(), time.Now().UnixNano()))
	if err := os.Mkdir(probe, 0o755); err != nil {
		return false
	}
	defer os.Remove(probe)
	if _, err := os.Stat(filepath.Join(probe, "cgroup.procs")); err != nil {
		return false
	}
	if _, err := os.Stat(filepath.Join(probe, "cgroup.kill")); err != nil {
		return false
	}
	return true
}

func detectCgroupV2Root() string {
	cgroupV2Once.Do(func() {
		raw, err := os.ReadFile("/proc/self/cgroup")
		if err != nil {
			return
		}
		base, ok := parseCgroupV2Path(string(raw))
		if !ok {
			return
		}
		if probeCgroupV2Root(base) {
			cgroupV2Root = base
		}
	})
	return cgroupV2Root
}

// cmdCgroup owns one ephemeral child cgroup directory for a spawned command.
type cmdCgroup struct {
	mu       sync.Mutex
	dir      string
	attached bool
	killed   bool
	cleaning bool
	closed   bool
}

// newCmdCgroup creates a per-command child cgroup directory when cgroup v2 is
// available and writable; otherwise returns nil so callers fall back to
// process-group termination.
func newCmdCgroup() *cmdCgroup {
	return newCmdCgroupIn(detectCgroupV2Root())
}

func newCmdCgroupIn(base string) *cmdCgroup {
	if base == "" {
		return nil
	}
	dir := filepath.Join(base, fmt.Sprintf("artex-cmd-%d-%d", os.Getpid(), cgroupSeq.Add(1)))
	if err := os.Mkdir(dir, 0o755); err != nil {
		return nil
	}
	return &cmdCgroup{dir: dir}
}

// attach moves pid into this command's cgroup via cgroup.procs. If kill was
// already requested before attach completed, cgroup.kill is triggered
// immediately. On failure the empty cgroup directory is cleaned up.
func (c *cmdCgroup) attach(pid int) bool {
	if c == nil || pid <= 0 {
		return false
	}
	c.mu.Lock()
	if c.closed || c.cleaning {
		c.mu.Unlock()
		return false
	}
	err := os.WriteFile(filepath.Join(c.dir, "cgroup.procs"), []byte(strconv.Itoa(pid)), 0o644)
	if err != nil {
		c.mu.Unlock()
		c.cleanup()
		return false
	}
	c.attached = true
	if c.killed {
		_ = os.WriteFile(filepath.Join(c.dir, "cgroup.kill"), []byte("1"), 0o644)
	}
	c.mu.Unlock()
	return true
}

// kill writes "1" to cgroup.kill, forcibly terminating every process inside the
// cgroup including setsid()-escaped grandchildren.
func (c *cmdCgroup) kill() error {
	if c == nil {
		return nil
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.killed = true
	if c.closed || !c.attached {
		return nil
	}
	return os.WriteFile(filepath.Join(c.dir, "cgroup.kill"), []byte("1"), 0o644)
}

// cleanup terminates any remaining descendants inside the cgroup (including
// setsid()-escaped grandchildren such as headless Chromium) via cgroup.kill
// before removing the ephemeral cgroup directory. c.kill() stays usable until
// directory removal succeeds. Brief retries tolerate transient EBUSY while the
// kernel finishes reaping exiting descendants.
func (c *cmdCgroup) cleanup() {
	if c == nil {
		return
	}
	c.mu.Lock()
	if c.closed || c.cleaning {
		c.mu.Unlock()
		return
	}
	c.cleaning = true
	dir := c.dir
	if c.attached {
		c.killed = true
		_ = os.WriteFile(filepath.Join(dir, "cgroup.kill"), []byte("1"), 0o644)
	}
	c.mu.Unlock()

	removed := false
	for range 5 {
		err := os.Remove(dir)
		if err == nil || os.IsNotExist(err) {
			removed = true
			break
		}
		// Re-issue cgroup.kill if any late-forked descendant kept the directory busy.
		c.mu.Lock()
		if c.attached && !c.closed {
			_ = os.WriteFile(filepath.Join(dir, "cgroup.kill"), []byte("1"), 0o644)
		}
		c.mu.Unlock()
		time.Sleep(20 * time.Millisecond)
	}

	c.mu.Lock()
	c.cleaning = false
	if removed {
		c.closed = true
	}
	c.mu.Unlock()
}
