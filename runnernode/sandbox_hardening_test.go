package runnernode

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/RC-CHN/ARTEX/runnerfiles"
)

var tmpfsSizePattern = regexp.MustCompile(`^([^:]+):.*size=(\d+)m`)

func parseDockerTmpfsSizes(t *testing.T, args []string) map[string]int64 {
	t.Helper()
	got := map[string]int64{}
	for i := 0; i < len(args)-1; i++ {
		if args[i] != "--tmpfs" {
			continue
		}
		m := tmpfsSizePattern.FindStringSubmatch(args[i+1])
		if len(m) != 3 {
			t.Fatalf("unexpected --tmpfs spec %q", args[i+1])
		}
		sz, err := strconv.ParseInt(m[2], 10, 64)
		if err != nil {
			t.Fatalf("parse tmpfs size %q: %v", m[2], err)
		}
		got[m[1]] = sz
	}
	return got
}

func TestSandboxHardeningDockerArgsAndTmpfsBudget(t *testing.T) {
	cases := []struct {
		name             string
		memoryMiB        int64
		effectiveMemMiB  int64
		wantShmMiB       int64
		mountWorkspace   bool
		wantWorkspaceTmp bool
	}{
		{name: "default-1g-with-workspace-tmpfs", memoryMiB: 0, effectiveMemMiB: 1024, wantShmMiB: 128, mountWorkspace: false, wantWorkspaceTmp: true},
		{name: "default-1g-with-mounted-workspace", memoryMiB: 0, effectiveMemMiB: 1024, wantShmMiB: 128, mountWorkspace: true, wantWorkspaceTmp: false},
		{name: "small-512m-with-workspace-tmpfs", memoryMiB: 512, effectiveMemMiB: 512, wantShmMiB: 64, mountWorkspace: false, wantWorkspaceTmp: true},
		{name: "small-256m-with-mounted-workspace", memoryMiB: 256, effectiveMemMiB: 256, wantShmMiB: 32, mountWorkspace: true, wantWorkspaceTmp: false},
		{name: "tiny-64m-clamps-shm-floor", memoryMiB: 64, effectiveMemMiB: 64, wantShmMiB: 16, mountWorkspace: true, wantWorkspaceTmp: false},
		{name: "large-4g-with-workspace-tmpfs", memoryMiB: 4096, effectiveMemMiB: 4096, wantShmMiB: 128, mountWorkspace: false, wantWorkspaceTmp: true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			d := &DockerExecutor{NodeID: "node-hardening"}
			spec := baseSpec("/workspace")
			spec.Resources.MemoryMiB = tc.memoryMiB
			plan := runnerfiles.Plan{}
			roots := map[string]string{}
			if tc.mountWorkspace {
				plan.Mounts = []runnerfiles.Mount{{Name: "ws", Target: "/workspace", Writable: []string{"."}}}
				roots["ws"] = t.TempDir()
			}
			args, err := d.DockerArgs("sess", spec, plan, roots, nil)
			if err != nil {
				t.Fatalf("DockerArgs: %v", err)
			}
			joined := strings.Join(args, " ")
			wantShm := fmt.Sprintf("--shm-size=%dm", tc.wantShmMiB)
			wantFsize := fmt.Sprintf("--ulimit=fsize=%d:%d", int64(2048)<<20, int64(2048)<<20)
			for _, flag := range []string{"--init", wantShm, "--ulimit=nofile=8192:8192", wantFsize} {
				if !strings.Contains(joined, flag) {
					t.Errorf("missing expected docker flag %q in %s", flag, joined)
				}
			}

			sizes := parseDockerTmpfsSizes(t, args)
			tmpSize, ok := sizes["/tmp"]
			if !ok || tmpSize <= 0 || tmpSize > 128 {
				t.Fatalf("/tmp size = %d (present=%v), want 1..128", tmpSize, ok)
			}
			homeSize, ok := sizes["/home/runner"]
			if !ok || homeSize <= 0 || homeSize > 64 {
				t.Fatalf("/home/runner size = %d (present=%v), want 1..64", homeSize, ok)
			}
			wsSize, hasWS := sizes["/workspace"]
			if hasWS != tc.wantWorkspaceTmp {
				t.Fatalf("/workspace tmpfs present=%v, want %v", hasWS, tc.wantWorkspaceTmp)
			}
			if hasWS && (wsSize <= 0 || wsSize > 128) {
				t.Fatalf("/workspace size = %d, want 1..128", wsSize)
			}

			total := tmpSize + homeSize + wsSize
			budget := tc.effectiveMemMiB / 4
			if total > budget {
				t.Fatalf("total tmpfs %dm exceeds 25%% budget %dm (memory=%dm, breakdown=%v)", total, budget, tc.effectiveMemMiB, sizes)
			}
		})
	}
}

func TestSandboxHardeningDockerUserMapping(t *testing.T) {
	cases := []struct {
		name      string
		uid, gid  int
		hasMounts bool
		wantUID   string
		wantGID   string
	}{
		{name: "root-without-mounts-maps-to-10001", uid: 0, gid: 0, hasMounts: false, wantUID: "10001", wantGID: "10001"},
		{name: "root-with-mounts-preserves-owner-access", uid: 0, gid: 0, hasMounts: true, wantUID: "0", wantGID: "0"},
		{name: "non-root-without-mounts", uid: 1000, gid: 1000, hasMounts: false, wantUID: "1000", wantGID: "1000"},
		{name: "non-root-with-mounts", uid: 1000, gid: 1000, hasMounts: true, wantUID: "1000", wantGID: "1000"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			gotUID, gotGID := dockerSandboxUser(tc.uid, tc.gid, tc.hasMounts)
			if gotUID != tc.wantUID || gotGID != tc.wantGID {
				t.Fatalf("dockerSandboxUser(%d,%d,%v) = (%s,%s), want (%s,%s)",
					tc.uid, tc.gid, tc.hasMounts, gotUID, gotGID, tc.wantUID, tc.wantGID)
			}
		})
	}
}

func TestSandboxHardeningKubernetesPodVolumesAndPIDReaping(t *testing.T) {
	cases := []struct {
		memoryMiB int64
		wantShm   string
	}{
		{memoryMiB: 0, wantShm: "128Mi"},
		{memoryMiB: 64, wantShm: "16Mi"},
		{memoryMiB: 256, wantShm: "32Mi"},
		{memoryMiB: 512, wantShm: "64Mi"},
		{memoryMiB: 4096, wantShm: "128Mi"},
	}
	for _, tc := range cases {
		t.Run(fmt.Sprintf("mem-%d", tc.memoryMiB), func(t *testing.T) {
			c := KubernetesConfig{
				Namespace:        "runner-test",
				WorkspacePVC:     "workspace",
				WorkspaceSubPath: "sessions",
			}
			if err := c.validate(); err != nil {
				t.Fatal(err)
			}
			wsDir := t.TempDir()
			root := filepath.Join(wsDir, "s", "mounts", "task")
			k := &KubernetesExecutor{Config: c, WorkspaceDir: wsDir, NodeID: "node-k8s", MaxPods: 2}
			spec := baseSpec("/workspace")
			spec.Resources.MemoryMiB = tc.memoryMiB
			pod, err := k.Pod("sess", spec, runnerfiles.Plan{}, map[string]string{"task": root})
			if err != nil {
				t.Fatalf("Pod: %v", err)
			}

			ps, ok := pod["spec"].(map[string]any)
			if !ok {
				t.Fatalf("missing pod.spec: %#v", pod)
			}
			if share, _ := ps["shareProcessNamespace"].(bool); !share {
				t.Fatalf("shareProcessNamespace = %v, want true for pause PID 1 zombie reaping", ps["shareProcessNamespace"])
			}

			volumesByName := map[string]map[string]any{}
			for _, raw := range ps["volumes"].([]any) {
				v := raw.(map[string]any)
				volumesByName[v["name"].(string)] = v
			}

			tmpVol, ok := volumesByName["tmp"]
			if !ok {
				t.Fatal("missing tmp volume")
			}
			tmpEmpty := tmpVol["emptyDir"].(map[string]any)
			if tmpEmpty["medium"] != nil {
				t.Fatalf("tmp emptyDir must be disk-backed, got medium=%v", tmpEmpty["medium"])
			}
			if tmpEmpty["sizeLimit"] != "512Mi" {
				t.Fatalf("tmp sizeLimit = %v, want 512Mi", tmpEmpty["sizeLimit"])
			}

			homeVol, ok := volumesByName["home"]
			if !ok {
				t.Fatal("missing home volume")
			}
			homeEmpty := homeVol["emptyDir"].(map[string]any)
			if homeEmpty["medium"] != nil {
				t.Fatalf("home emptyDir must be disk-backed, got medium=%v", homeEmpty["medium"])
			}
			if homeEmpty["sizeLimit"] != "256Mi" {
				t.Fatalf("home sizeLimit = %v, want 256Mi", homeEmpty["sizeLimit"])
			}

			shmVol, ok := volumesByName["shm"]
			if !ok {
				t.Fatal("missing shm volume")
			}
			shmEmpty := shmVol["emptyDir"].(map[string]any)
			if shmEmpty["medium"] != "Memory" || shmEmpty["sizeLimit"] != tc.wantShm {
				t.Fatalf("shm emptyDir = %#v, want medium=Memory sizeLimit=%s", shmEmpty, tc.wantShm)
			}

			containers := ps["containers"].([]any)
			sandbox := containers[0].(map[string]any)
			mountsByName := map[string]string{}
			for _, raw := range sandbox["volumeMounts"].([]any) {
				m := raw.(map[string]any)
				mountsByName[m["name"].(string)] = m["mountPath"].(string)
			}
			if mountsByName["tmp"] != "/tmp" || mountsByName["home"] != "/home/runner" || mountsByName["shm"] != "/dev/shm" {
				t.Fatalf("unexpected volumeMounts: %#v", mountsByName)
			}
		})
	}
}

func TestSandboxInvalidJSONHelper(t *testing.T) {
	if os.Getenv("ARTEX_INVALID_JSON_HELPER") != "1" {
		return
	}
	_, _ = fmt.Fprintln(os.Stdout, "not-valid-json")
	time.Sleep(30 * time.Second)
	os.Exit(0)
}

func TestSandboxHardeningInvalidJSONReapsChild(t *testing.T) {
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.CommandContext(t.Context(), exe, "-test.run=^TestSandboxInvalidJSONHelper$")
	cmd.Env = append(os.Environ(), "ARTEX_INVALID_JSON_HELPER=1")
	configureProcess(cmd)

	sb, err := startRPC(cmd, func() error { return killProcess(cmd) }, io.Discard)
	if err != nil {
		t.Fatalf("startRPC: %v", err)
	}
	defer func() { _ = sb.Stop() }()

	select {
	case <-sb.done:
	case <-time.After(5 * time.Second):
		t.Fatal("startRPC did not finish after invalid JSON")
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if _, err := sb.Request(ctx, SandboxRequest{Method: "heartbeat"}); err == nil || !strings.Contains(err.Error(), "invalid JSON") {
		t.Fatalf("Request err = %v, want invalid JSON error", err)
	}
	if cmd.ProcessState == nil {
		t.Fatal("child process was not reaped by cmd.Wait() on invalid JSON")
	}
}

func TestSandboxHardeningDockerFsizeUlimitOverrides(t *testing.T) {
	t.Setenv("NORMA_BASH_MAX_FILE_MB", "")
	d := &DockerExecutor{NodeID: "node-fsize"}

	// Custom override via spec.Env (512 MiB).
	spec := baseSpec("/workspace")
	spec.Env = map[string]string{"NORMA_BASH_MAX_FILE_MB": "512"}
	args, err := d.DockerArgs("sess-custom", spec, runnerfiles.Plan{}, map[string]string{}, nil)
	if err != nil {
		t.Fatalf("DockerArgs custom: %v", err)
	}
	wantCustom := fmt.Sprintf("--ulimit=fsize=%d:%d", int64(512)<<20, int64(512)<<20)
	if !strings.Contains(strings.Join(args, " "), wantCustom) {
		t.Fatalf("missing custom fsize flag %q in %v", wantCustom, args)
	}

	// Explicit disable via spec.Env ("0") omits --ulimit=fsize.
	specOff := baseSpec("/workspace")
	specOff.Env = map[string]string{"NORMA_BASH_MAX_FILE_MB": "0"}
	argsOff, err := d.DockerArgs("sess-off", specOff, runnerfiles.Plan{}, map[string]string{}, nil)
	if err != nil {
		t.Fatalf("DockerArgs disabled: %v", err)
	}
	if strings.Contains(strings.Join(argsOff, " "), "--ulimit=fsize=") {
		t.Fatalf("expected --ulimit=fsize omitted when NORMA_BASH_MAX_FILE_MB=0, got %v", argsOff)
	}
}
