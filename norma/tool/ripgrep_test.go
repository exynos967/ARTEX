package tool

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestRipgrepPathDisabled(t *testing.T) {
	t.Setenv("NORMA_DISABLE_RIPGREP", "1")
	if RipgrepPath() != "" {
		t.Fatal("NORMA_DISABLE_RIPGREP should force the Go implementation")
	}
}

func TestGrepViaRipgrepIfAvailable(t *testing.T) {
	if _, err := exec.LookPath("rg"); err != nil {
		t.Skip("rg not installed — skipping the ripgrep-backed path")
	}
	// Use the existing rg; never auto-install during tests.
	t.Setenv("NORMA_RIPGREP_NO_INSTALL", "1")
	os.Unsetenv("NORMA_DISABLE_RIPGREP")

	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "x.go"), []byte("package main\nfunc Zed(){}\n"), 0o644)
	os.WriteFile(filepath.Join(dir, "y.txt"), []byte("nothing here\n"), 0o644)

	res := run(t, NewGrep(), dir, map[string]any{"pattern": "Zed", "output_mode": "files_with_matches"})
	if !strings.Contains(res.Flatten(), "x.go") || strings.Contains(res.Flatten(), "y.txt") {
		t.Fatalf("ripgrep-backed grep: %q", res.Flatten())
	}
}

func TestLinePagerEarlyStopTriggersCallback(t *testing.T) {
	stopped := 0
	p := newLinePager(2, 0)
	p.maxDrain = 3
	p.onStop = func() { stopped++ }

	for i := range 20 {
		_, _ = p.Write([]byte("line\n"))
		if i == 10 && stopped == 0 {
			t.Fatal("expected early stop callback to trigger once drain cap was reached")
		}
	}
	if stopped != 1 {
		t.Fatalf("onStop called %d times, want 1", stopped)
	}
	if !p.stoppedEarly {
		t.Fatal("expected p.stoppedEarly to be true")
	}
	kept, more := p.finish()
	if len(kept) != 2 || more <= 0 {
		t.Fatalf("finish = (%d kept, %d more), want 2 kept and more > 0", len(kept), more)
	}
}

func TestGrepHandlesUnreadableSubdirWithoutHanging(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root ignores chmod 0000 permissions")
	}
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "ok.txt"), []byte("needle-here\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	locked := filepath.Join(dir, "locked")
	if err := os.Mkdir(locked, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(locked, "hidden.txt"), []byte("needle-hidden\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(locked, 0o000); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(locked, 0o755) })

	for _, disableRG := range []string{"1", ""} {
		if disableRG == "" {
			if _, err := exec.LookPath("rg"); err != nil {
				continue
			}
			t.Setenv("NORMA_RIPGREP_NO_INSTALL", "1")
		}
		t.Setenv("NORMA_DISABLE_RIPGREP", disableRG)
		res := run(t, NewGrep(), dir, map[string]any{"pattern": "needle-here", "output_mode": "files_with_matches"})
		if !strings.Contains(res.Flatten(), "ok.txt") {
			t.Fatalf("disableRG=%q: expected ok.txt in results, got %q", disableRG, res.Flatten())
		}
	}
}

func TestSearchTimeoutEnvOverride(t *testing.T) {
	t.Setenv("NORMA_GREP_TIMEOUT_MS", "")
	if got := searchTimeout(); got != defaultSearchTimeout {
		t.Fatalf("default searchTimeout = %v, want %v", got, defaultSearchTimeout)
	}
	t.Setenv("NORMA_GREP_TIMEOUT_MS", "250")
	if got := searchTimeout(); got != 250*time.Millisecond {
		t.Fatalf("override searchTimeout = %v, want 250ms", got)
	}
	t.Setenv("NORMA_GREP_TIMEOUT_MS", "invalid")
	if got := searchTimeout(); got != defaultSearchTimeout {
		t.Fatalf("invalid searchTimeout = %v, want %v", got, defaultSearchTimeout)
	}
}

func TestGrepLargeMatchSetStopsEarly(t *testing.T) {
	dir := t.TempDir()
	chunk := strings.Repeat("match-target-line\n", 150)
	for i := range 30 {
		p := filepath.Join(dir, fmt.Sprintf("f%02d.txt", i))
		if err := os.WriteFile(p, []byte(chunk), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	for _, disableRG := range []string{"1", ""} {
		if disableRG == "" {
			if _, err := exec.LookPath("rg"); err != nil {
				continue
			}
			t.Setenv("NORMA_RIPGREP_NO_INSTALL", "1")
		}
		t.Setenv("NORMA_DISABLE_RIPGREP", disableRG)
		res := run(t, NewGrep(), dir, map[string]any{
			"pattern":     "match-target-line",
			"output_mode": "content",
			"head_limit":  5,
		})
		out := res.Flatten()
		if !strings.Contains(out, "match-target-line") {
			t.Fatalf("disableRG=%q: expected matches, got %q", disableRG, out)
		}
		if !strings.Contains(out, "stopped early") || !strings.Contains(out, "offset=5") {
			t.Fatalf("disableRG=%q: expected early-stop pagination notice, got %q", disableRG, out)
		}
	}
}
