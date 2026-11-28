package tool

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
	"unicode/utf8"
)

func TestBoundedTaskOutputCapsDiskWithoutKillingProcess(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("shell loop fixture uses Unix shell")
	}
	dir := t.TempDir()
	m := newTestManager(t)
	m.maxOutput = 4096 // 4 KiB cap for fast deterministic test

	// Generate ~200 KiB on stdout, then write a side-effect artifact file and exit 0.
	// The process MUST NOT be killed when output crosses 4 KiB, and its disk
	// output file MUST remain bounded while preserving both head and tail.
	artifact := filepath.Join(dir, "scan-result.txt")
	cmd := fmt.Sprintf(
		`echo "HEAD_MARKER"; i=0; while [ "$i" -lt 4000 ]; do printf "0123456789abcdef0123456789abcdef0123456789abcdef\n"; i=$((i+1)); done; echo "TAIL_MARKER"; printf "finding-ok" > %q`,
		artifact,
	)
	task, err := m.Spawn(SpawnSpec{Command: cmd, WorkingDir: dir})
	if err != nil {
		t.Fatalf("Spawn: %v", err)
	}
	m.Background(task.ID)

	info, ok := m.Wait(context.Background(), task.ID, 15*time.Second)
	if !ok {
		t.Fatalf("task did not finish in time: %+v", info)
	}
	if info.Status != TaskCompleted || info.ExitCode != 0 {
		t.Fatalf("process was killed or failed: status=%s exit=%d", info.Status, info.ExitCode)
	}
	gotArtifact, err := os.ReadFile(artifact)
	if err != nil || string(gotArtifact) != "finding-ok" {
		t.Fatalf("side-effect artifact missing: got=%q err=%v", gotArtifact, err)
	}

	fi, err := os.Stat(task.OutputPath)
	if err != nil {
		t.Fatalf("stat output: %v", err)
	}
	// On-disk size must be strictly bounded (cap + rolling tail <= 2 KiB + header).
	if fi.Size() > 4096+2048+512 {
		t.Fatalf("output file grew past bounded cap: size=%d", fi.Size())
	}
	raw, err := os.ReadFile(task.OutputPath)
	if err != nil {
		t.Fatalf("read output: %v", err)
	}
	text := string(raw)
	if !strings.Contains(text, "HEAD_MARKER") {
		t.Fatal("bounded output lost HEAD_MARKER")
	}
	if !strings.Contains(text, "task output capped") {
		t.Fatalf("bounded output missing truncation marker: %q", text)
	}
	if !strings.Contains(text, "TAIL_MARKER") {
		t.Fatal("bounded output lost TAIL_MARKER")
	}
	if !utf8.ValidString(text) {
		t.Fatal("bounded output produced invalid UTF-8")
	}
	out, err := m.Output(task.ID, 4096)
	if err != nil || !strings.Contains(out, "TAIL_MARKER") {
		t.Fatalf("Manager.Output missing TAIL_MARKER: out=%q err=%v", out, err)
	}
}

func TestBashMaxFileBytesParsing(t *testing.T) {
	t.Setenv(BashMaxFileEnv, "")
	if got := bashMaxFileBytes(nil); got != DefaultBashMaxFileMiB<<20 {
		t.Fatalf("default = %d, want %d", got, DefaultBashMaxFileMiB<<20)
	}
	if got := bashMaxFileBytes([]string{BashMaxFileEnv + "=0"}); got != 0 {
		t.Fatalf("disabled = %d, want 0", got)
	}
	if got := bashMaxFileBytes([]string{BashMaxFileEnv + "=512"}); got != 512<<20 {
		t.Fatalf("512 MiB = %d, want %d", got, 512<<20)
	}
	if got := bashMaxFileBytes([]string{BashMaxFileEnv + "=-10"}); got != DefaultBashMaxFileMiB<<20 {
		t.Fatalf("negative fallback = %d, want default", got)
	}
	if got := bashMaxFileBytes([]string{BashMaxFileEnv + "=invalid"}); got != DefaultBashMaxFileMiB<<20 {
		t.Fatalf("invalid fallback = %d, want default", got)
	}
	// Last entry in extraEnv wins over earlier entry and process env.
	t.Setenv(BashMaxFileEnv, "1024")
	if got := bashMaxFileBytes([]string{BashMaxFileEnv + "=128", BashMaxFileEnv + "=256"}); got != 256<<20 {
		t.Fatalf("override = %d, want %d", got, 256<<20)
	}
}

func TestBashFsizeLimitEnforcedOnUnix(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("RLIMIT_FSIZE ulimit -f is Unix-only")
	}
	dir := t.TempDir()
	m := newTestManager(t)

	// 1. With NORMA_BASH_MAX_FILE_MB=1, writing a 2 MiB file must be stopped at ~1 MiB.
	tcLimited := &ToolContext{
		WorkingDir: dir,
		Tasks:      m,
		Env:        []string{BashMaxFileEnv + "=1"},
	}
	bigFile := filepath.Join(dir, "runaway.log")
	raw, _ := json.Marshal(map[string]any{
		"command": fmt.Sprintf("dd if=/dev/zero of=%q bs=65536 count=40 2>&1", bigFile),
	})
	res, err := NewBash().Call(context.Background(), raw, tcLimited)
	if err != nil {
		t.Fatalf("Bash.Call: %v", err)
	}
	if !res.IsError {
		t.Fatalf("expected non-zero exit when exceeding 1 MiB fsize limit, got success: %s", res.Flatten())
	}
	fi, err := os.Stat(bigFile)
	if err != nil {
		t.Fatalf("stat runaway.log: %v", err)
	}
	if fi.Size() > (1<<20)+65536 {
		t.Fatalf("file grew far past 1 MiB limit: size=%d", fi.Size())
	}

	// 2. Small file under limit succeeds cleanly (including leading comment + set -e).
	smallFile := filepath.Join(dir, "small.txt")
	rawSmall, _ := json.Marshal(map[string]any{
		"command": fmt.Sprintf("# leading comment\nset -e\ndd if=/dev/zero of=%q bs=1024 count=64 2>/dev/null\necho SMALL_OK", smallFile),
	})
	resSmall, err := NewBash().Call(context.Background(), rawSmall, tcLimited)
	if err != nil || resSmall.IsError || !strings.Contains(resSmall.Flatten(), "SMALL_OK") {
		t.Fatalf("small write under limit failed: err=%v isErr=%v out=%q", err, resSmall.IsError, resSmall.Flatten())
	}

	// 3. With NORMA_BASH_MAX_FILE_MB=0 (disabled), a 2 MiB file succeeds cleanly.
	tcDisabled := &ToolContext{
		WorkingDir: dir,
		Tasks:      m,
		Env:        []string{BashMaxFileEnv + "=0"},
	}
	okFile := filepath.Join(dir, "allowed2m.bin")
	rawAllowed, _ := json.Marshal(map[string]any{
		"command": fmt.Sprintf("dd if=/dev/zero of=%q bs=65536 count=32 2>/dev/null && echo UNLIMITED_OK", okFile),
	})
	resAllowed, err := NewBash().Call(context.Background(), rawAllowed, tcDisabled)
	if err != nil || resAllowed.IsError || !strings.Contains(resAllowed.Flatten(), "UNLIMITED_OK") {
		t.Fatalf("disabled fsize limit failed: err=%v isErr=%v out=%q", err, resAllowed.IsError, resAllowed.Flatten())
	}
}
