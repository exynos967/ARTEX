package mcp

import (
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

type errWriter struct{ err error }

func (w errWriter) Write(p []byte) (int, error) { return 0, w.err }

func pendingCount(c *conn) int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.pending)
}

func TestConnCallCleansPendingOnContextDone(t *testing.T) {
	cReader, sWriter := io.Pipe()
	defer cReader.Close()
	defer sWriter.Close()

	// Drain client writes so call() reaches the select without blocking on write.
	sReader, cWriter := io.Pipe()
	defer sReader.Close()
	defer cWriter.Close()
	go func() { _, _ = io.Copy(io.Discard, sReader) }()

	c := newConn(cReader, cWriter)

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if _, err := c.call(ctx, "slow/method", map[string]any{}); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("expected DeadlineExceeded, got %v", err)
	}
	if got := pendingCount(c); got != 0 {
		t.Fatalf("pending leaked after ctx.Done(): %d", got)
	}
}

func TestConnCallCleansPendingOnWriteError(t *testing.T) {
	cReader, sWriter := io.Pipe()
	defer cReader.Close()
	defer sWriter.Close()

	boom := errors.New("broken write pipe")
	c := newConn(cReader, errWriter{err: boom})

	if _, err := c.call(context.Background(), "tools/list", nil); !errors.Is(err, boom) {
		t.Fatalf("expected write error %v, got %v", boom, err)
	}
	if got := pendingCount(c); got != 0 {
		t.Fatalf("pending leaked after write error: %d", got)
	}
}

func TestConnCallAndReadLoopCleanPendingOnClose(t *testing.T) {
	cReader, sWriter := io.Pipe()
	sReader, cWriter := io.Pipe()
	defer sReader.Close()
	defer cWriter.Close()
	go func() { _, _ = io.Copy(io.Discard, sReader) }()

	c := newConn(cReader, cWriter)

	errCh := make(chan error, 1)
	go func() {
		_, err := c.call(context.Background(), "blocked/call", nil)
		errCh <- err
	}()

	// Wait until the pending call is registered before closing the server stream.
	deadline := time.Now().Add(2 * time.Second)
	for pendingCount(c) == 0 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if pendingCount(c) != 1 {
		t.Fatalf("expected 1 in-flight pending call, got %d", pendingCount(c))
	}

	_ = sWriter.Close()

	select {
	case err := <-errCh:
		if err == nil {
			t.Fatal("expected error when connection closes")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("call did not unblock on closeCh")
	}

	<-c.closeCh
	if got := pendingCount(c); got != 0 {
		t.Fatalf("pending leaked after readLoop exit: %d", got)
	}

	// Subsequent calls on a closed connection must fail fast without leaking pending entries.
	if _, err := c.call(context.Background(), "after/close", nil); err == nil {
		t.Fatal("expected error on closed connection")
	}
	if got := pendingCount(c); got != 0 {
		t.Fatalf("pending leaked after post-close call: %d", got)
	}
}

// TestStdioStubHelper is invoked as a subprocess by TestStdioCloserTerminatesStubAndIsIdempotent.
func TestStdioStubHelper(t *testing.T) {
	mode := os.Getenv("ARTEX_MCP_STUB_MODE")
	if mode == "" {
		return
	}
	switch mode {
	case "eof":
		_, _ = io.Copy(io.Discard, os.Stdin)
		os.Exit(0)
	case "ignore-eof":
		time.Sleep(30 * time.Second)
		os.Exit(0)
	case "exit-fast":
		os.Exit(0)
	case "spawn-child-ignore-eof":
		child := exec.Command(os.Args[0], "-test.run=^TestStdioStubHelper$")
		child.Env = append(os.Environ(), "ARTEX_MCP_STUB_MODE=ignore-eof")
		if err := child.Start(); err != nil {
			os.Exit(2)
		}
		if marker := os.Getenv("ARTEX_MCP_CHILD_PID_FILE"); marker != "" {
			_ = os.WriteFile(marker, []byte(strconv.Itoa(child.Process.Pid)), 0o600)
		}
		time.Sleep(30 * time.Second)
		os.Exit(0)
	}
}

func TestStdioCloserTerminatesStubAndIsIdempotent(t *testing.T) {
	for _, mode := range []string{"eof", "ignore-eof"} {
		t.Run(mode, func(t *testing.T) {
			cmd := exec.CommandContext(context.Background(), os.Args[0], "-test.run=^TestStdioStubHelper$")
			cmd.Env = append(os.Environ(), "ARTEX_MCP_STUB_MODE="+mode)
			cmd.WaitDelay = 3 * time.Second
			configureStdioProcess(cmd)

			stdinR, stdinW, err := os.Pipe()
			if err != nil {
				t.Fatal(err)
			}
			stdoutR, stdoutW, err := os.Pipe()
			if err != nil {
				t.Fatal(err)
			}
			cmd.Stdin = stdinR
			cmd.Stdout = stdoutW
			if err := cmd.Start(); err != nil {
				t.Fatal(err)
			}
			_ = stdinR.Close()
			_ = stdoutW.Close()

			done := make(chan struct{})
			go func() {
				_ = cmd.Wait()
				close(done)
			}()

			closer := &stdioCloser{
				cmd:    cmd,
				stdin:  stdinW,
				stdout: stdoutR,
				done:   done,
			}

			// Concurrent and repeated Close calls must be idempotent and never race with Wait().
			var wg sync.WaitGroup
			for range 4 {
				wg.Add(1)
				go func() {
					defer wg.Done()
					if err := closer.Close(); err != nil {
						t.Errorf("Close returned error: %v", err)
					}
				}()
			}
			wg.Wait()
			if err := closer.Close(); err != nil {
				t.Fatalf("second Close returned error: %v", err)
			}

			select {
			case <-done:
			case <-time.After(3 * time.Second):
				t.Fatalf("stub subprocess (%s) did not terminate after Close()", mode)
			}
		})
	}
}

// TestStdioCloserAlreadyExitedSkipsSignaling verifies that once cmd.Wait() has
// already reaped the child (done closed), neither killStdioProcess nor Close()
// signals the recycled PID.
func TestStdioCloserAlreadyExitedSkipsSignaling(t *testing.T) {
	cmd := exec.CommandContext(context.Background(), os.Args[0], "-test.run=^TestStdioStubHelper$")
	cmd.Env = append(os.Environ(), "ARTEX_MCP_STUB_MODE=exit-fast")
	done := make(chan struct{})
	configureStdioProcessWithDone(cmd, done)

	stdinR, stdinW, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	stdoutR, stdoutW, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	cmd.Stdin = stdinR
	cmd.Stdout = stdoutW
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	_ = stdinR.Close()
	_ = stdoutW.Close()

	go func() {
		_ = cmd.Wait()
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("exit-fast stub did not exit")
	}

	// Point cmd.Process at our own PID after reap to prove done-gating skips
	// signaling completely rather than signalling a recycled PID!
	origProc := cmd.Process
	cmd.Process = &os.Process{Pid: os.Getpid()}
	defer func() { cmd.Process = origProc }()

	if err := killStdioProcess(cmd, done); !errors.Is(err, os.ErrProcessDone) {
		t.Fatalf("killStdioProcess after done = %v, want os.ErrProcessDone", err)
	}

	closer := &stdioCloser{cmd: cmd, stdin: stdinW, stdout: stdoutR, done: done}
	start := time.Now()
	if err := closer.Close(); err != nil {
		t.Fatalf("Close after exit returned error: %v", err)
	}
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Fatalf("Close after already-exited child stalled for %v", elapsed)
	}
}

// TestStdioCloserKillsChildTree verifies that closing an MCP subprocess that
// ignores EOF terminates both the leader and its spawned child process across
// Unix process groups and Windows taskkill /T /F.
func TestStdioCloserKillsChildTree(t *testing.T) {
	pidFile := filepath.Join(t.TempDir(), "child.pid")
	cmd := exec.CommandContext(context.Background(), os.Args[0], "-test.run=^TestStdioStubHelper$")
	cmd.Env = append(os.Environ(), "ARTEX_MCP_STUB_MODE=spawn-child-ignore-eof", "ARTEX_MCP_CHILD_PID_FILE="+pidFile)
	done := make(chan struct{})
	configureStdioProcessWithDone(cmd, done)

	stdinR, stdinW, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	stdoutR, stdoutW, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	cmd.Stdin = stdinR
	cmd.Stdout = stdoutW
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	_ = stdinR.Close()
	_ = stdoutW.Close()

	go func() {
		_ = cmd.Wait()
		close(done)
	}()

	// Wait for the child to write its PID so we know the tree is live before Close.
	deadline := time.Now().Add(5 * time.Second)
	var childPID int
	for time.Now().Before(deadline) {
		if b, rerr := os.ReadFile(pidFile); rerr == nil {
			if pid, perr := strconv.Atoi(strings.TrimSpace(string(b))); perr == nil && pid > 0 {
				childPID = pid
				break
			}
		}
		time.Sleep(20 * time.Millisecond)
	}
	if childPID == 0 {
		_ = (&stdioCloser{cmd: cmd, stdin: stdinW, stdout: stdoutR, done: done}).Close()
		t.Fatal("spawned child did not report PID")
	}

	closer := &stdioCloser{cmd: cmd, stdin: stdinW, stdout: stdoutR, done: done}
	if err := closer.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("leader did not exit after Close")
	}
}
