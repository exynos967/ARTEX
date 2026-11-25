//go:build linux

package tool

import (
	"os"
	"path/filepath"
	"testing"
)

func TestParseCgroupV2Path(t *testing.T) {
	cases := []struct {
		name   string
		in     string
		want   string
		wantOK bool
	}{
		{"unified root", "0::/\n", "/sys/fs/cgroup", true},
		{"nested container slice", "0::/system.slice/docker-abc.scope\n", "/sys/fs/cgroup/system.slice/docker-abc.scope", true},
		{"hybrid v1+v2", "12:memory:/docker/1\n0::/kubepods/pod1\n", "/sys/fs/cgroup/kubepods/pod1", true},
		{"v1 only", "1:name=systemd:/user.slice\n", "", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := parseCgroupV2Path(tc.in)
			if ok != tc.wantOK || got != tc.want {
				t.Fatalf("parseCgroupV2Path(%q) = (%q, %v), want (%q, %v)", tc.in, got, ok, tc.want, tc.wantOK)
			}
		})
	}
}

func TestCmdCgroupCleanupWritesCgroupKillAndKeepsKillUsableOnBusyDir(t *testing.T) {
	base := t.TempDir()
	cg := newCmdCgroupIn(base)
	if cg == nil {
		t.Fatal("newCmdCgroupIn returned nil")
	}
	if !cg.attach(12345) {
		t.Fatal("attach returned false")
	}
	procs, err := os.ReadFile(filepath.Join(cg.dir, "cgroup.procs"))
	if err != nil || string(procs) != "12345" {
		t.Fatalf("cgroup.procs = %q err=%v, want 12345", procs, err)
	}

	// cleanup must write "1" to cgroup.kill BEFORE attempting os.Remove(dir).
	// On a regular tmpfs directory, cgroup.procs / cgroup.kill files make
	// os.Remove fail with ENOTEMPTY — which also verifies c.closed stays false
	// so c.kill() remains usable until removal succeeds.
	cg.cleanup()

	killed, err := os.ReadFile(filepath.Join(cg.dir, "cgroup.kill"))
	if err != nil || string(killed) != "1" {
		t.Fatalf("cgroup.kill = %q err=%v, want \"1\"", killed, err)
	}
	if cg.closed {
		t.Fatal("cg.closed must stay false while directory removal has not succeeded")
	}

	// c.kill() remains usable while the cgroup still exists.
	if err := os.WriteFile(filepath.Join(cg.dir, "cgroup.kill"), []byte("0"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := cg.kill(); err != nil {
		t.Fatalf("cg.kill after busy cleanup failed: %v", err)
	}
	killed, _ = os.ReadFile(filepath.Join(cg.dir, "cgroup.kill"))
	if string(killed) != "1" {
		t.Fatalf("cg.kill did not rewrite cgroup.kill: %q", killed)
	}

	// Unattached cgroup removes empty directory cleanly and marks closed=true.
	cg2 := newCmdCgroupIn(base)
	if cg2 == nil {
		t.Fatal("newCmdCgroupIn(2) returned nil")
	}
	cg2.cleanup()
	if !cg2.closed {
		t.Fatal("empty cgroup cleanup should mark closed=true")
	}
	if _, err := os.Stat(cg2.dir); !os.IsNotExist(err) {
		t.Fatalf("empty cgroup dir still exists: %v", err)
	}
}
