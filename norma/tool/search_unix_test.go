//go:build !windows

package tool

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

// TestGrepSkipsFIFOWithoutHanging verifies that a named pipe (FIFO) in the
// searched directory or passed directly never blocks Grep indefinitely.
func TestGrepSkipsFIFOWithoutHanging(t *testing.T) {
	dir := t.TempDir()
	fifo := filepath.Join(dir, "hang.pipe")
	if err := syscall.Mkfifo(fifo, 0o600); err != nil {
		t.Fatalf("mkfifo: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "good.txt"), []byte("find-me-safely\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	for _, disableRG := range []string{"1", ""} {
		if disableRG == "" {
			if _, err := exec.LookPath("rg"); err != nil {
				continue
			}
			t.Setenv("NORMA_RIPGREP_NO_INSTALL", "1")
		}
		t.Setenv("NORMA_DISABLE_RIPGREP", disableRG)
		t.Setenv("NORMA_GREP_TIMEOUT_MS", "2000")

		start := time.Now()
		res := run(t, NewGrep(), dir, map[string]any{"pattern": "find-me-safely"})
		if time.Since(start) > time.Second {
			t.Fatalf("disableRG=%q: grep over dir containing FIFO took %v", disableRG, time.Since(start))
		}
		if !strings.Contains(res.Flatten(), "good.txt") {
			t.Fatalf("disableRG=%q: expected good.txt, got %q", disableRG, res.Flatten())
		}

		// Explicitly targeting the FIFO path directly must also return immediately.
		start = time.Now()
		resDirect := run(t, NewGrep(), dir, map[string]any{"pattern": "anything", "path": fifo})
		if time.Since(start) > time.Second {
			t.Fatalf("disableRG=%q: grep targeting FIFO directly took %v", disableRG, time.Since(start))
		}
		if !strings.Contains(resDirect.Flatten(), "No matches found") {
			t.Fatalf("disableRG=%q: direct FIFO grep = %q, want No matches found", disableRG, resDirect.Flatten())
		}
	}
}
