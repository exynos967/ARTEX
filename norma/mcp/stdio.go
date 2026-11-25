package mcp

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"
)

const (
	stdioEOFGraceTimeout  = 200 * time.Millisecond
	stdioWaitCloseTimeout = 3 * time.Second
)

// stdioCloser shuts down a spawned MCP server process and its pipes.
// A single owner goroutine calls cmd.Wait() and closes done so Close() never
// races with Wait() and remains idempotent across concurrent or repeated calls.
type stdioCloser struct {
	cmd    *exec.Cmd
	stdin  io.Closer
	stdout io.Closer
	done   <-chan struct{}
	once   sync.Once
}

func (s *stdioCloser) Close() error {
	s.once.Do(func() {
		// Check whether cmd.Wait() had ALREADY reaped the process BEFORE Close()
		// was invoked so a long-dead recycled PID is never signalled.
		exitedBeforeClose := false
		if s.done != nil {
			select {
			case <-s.done:
				exitedBeforeClose = true
			default:
			}
		}
		// 1. Close stdin first so well-behaved stdio MCP servers receive EOF and exit cleanly.
		if s.stdin != nil {
			_ = s.stdin.Close()
		}
		// 2. Briefly wait for a clean EOF-driven leader exit before signalling.
		leaderExited := exitedBeforeClose
		if !exitedBeforeClose && s.done != nil {
			timer := time.NewTimer(stdioEOFGraceTimeout)
			select {
			case <-s.done:
				leaderExited = true
			case <-timer.C:
			}
			timer.Stop()
		}
		// 3. Even when the leader exits promptly on stdin EOF, spawned descendants
		// can still be alive inside the process group (-pgid on Unix). As long as
		// the child was live at Close() entry, tear down the remaining group/tree.
		if !exitedBeforeClose && s.cmd != nil && s.cmd.Process != nil {
			_ = killStdioAfterEOF(s.cmd, s.done, leaderExited)
		}
		// 4. Wait up to 3s for the single Wait() owner goroutine to reap the process.
		if !leaderExited && s.done != nil {
			timer := time.NewTimer(stdioWaitCloseTimeout)
			select {
			case <-s.done:
			case <-timer.C:
			}
			timer.Stop()
		}
		if s.stdout != nil {
			_ = s.stdout.Close()
		}
	})
	return nil
}

// NewStdioClient spawns an MCP server as a subprocess, performs the handshake,
// and returns a connected Client (FR-10.1). Call Close to terminate it.
//
// env holds extra environment variables (e.g. API tokens an MCP server needs)
// applied on top of the parent process environment; pass nil for none.
func NewStdioClient(ctx context.Context, server, command string, env map[string]string, args ...string) (*Client, error) {
	opts := StdioOptions{InheritEnv: true}
	for k, v := range env {
		opts.Env = append(opts.Env, k+"="+v)
	}
	return NewStdioClientWithOptions(ctx, server, command, opts, args...)
}

// StdioOptions makes the MCP process's filesystem and environment explicit.
// The zero value inherits no environment; callers must supply any required PATH.
type StdioOptions struct {
	WorkingDir string
	Env        []string
	InheritEnv bool
}

// NewStdioClientWithOptions binds the process lifetime to ctx and terminates its
// process group / child tree cleanly across Unix and Windows. The compatibility
// constructor retains inherited env.
func NewStdioClientWithOptions(ctx context.Context, server, command string, opts StdioOptions, args ...string) (*Client, error) {
	env := make([]string, 0, len(opts.Env))
	if opts.InheritEnv {
		env = os.Environ()
	}
	env = append(env, opts.Env...)
	resolved, err := resolveStdioCommand(command, opts.WorkingDir, env)
	if err != nil {
		return nil, err
	}
	cmd := exec.CommandContext(ctx, resolved, args...)
	cmd.Dir = opts.WorkingDir
	cmd.Env = env
	cmd.WaitDelay = 3 * time.Second
	done := make(chan struct{})
	configureStdioProcessWithDone(cmd, done)

	// Manage stdio pipes directly instead of StdinPipe/StdoutPipe so the single
	// cmd.Wait() owner goroutine can start immediately after cmd.Start() without
	// racing with conn.readLoop or conn.writeLocked on pipe close.
	stdinR, stdinW, err := os.Pipe()
	if err != nil {
		return nil, err
	}
	stdoutR, stdoutW, err := os.Pipe()
	if err != nil {
		_ = stdinR.Close()
		_ = stdinW.Close()
		return nil, err
	}
	cmd.Stdin = stdinR
	cmd.Stdout = stdoutW
	if err := cmd.Start(); err != nil {
		_ = stdinR.Close()
		_ = stdinW.Close()
		_ = stdoutR.Close()
		_ = stdoutW.Close()
		return nil, err
	}
	_ = stdinR.Close()
	_ = stdoutW.Close()

	go func() {
		_ = cmd.Wait()
		close(done)
	}()

	c := &Client{
		server: server,
		conn:   newConn(stdoutR, stdinW),
		closer: &stdioCloser{cmd: cmd, stdin: stdinW, stdout: stdoutR, done: done},
	}
	if err := c.initialize(ctx); err != nil {
		c.Close()
		return nil, err
	}
	return c, nil
}

func resolveStdioCommand(command, cwd string, env []string) (string, error) {
	if strings.ContainsAny(command, `/\`) {
		return command, nil
	}
	pathEnv := ""
	extensions := []string{""}
	if runtime.GOOS == "windows" {
		extensions = []string{"", ".com", ".exe", ".bat", ".cmd"}
	}
	for _, pair := range env {
		if k, v, ok := strings.Cut(pair, "="); ok && (k == "PATH" || runtime.GOOS == "windows" && strings.EqualFold(k, "PATH")) {
			pathEnv = v
		}
	}
	if cwd == "" {
		cwd, _ = os.Getwd()
	}
	for _, dir := range filepath.SplitList(pathEnv) {
		if !filepath.IsAbs(dir) {
			dir = filepath.Join(cwd, dir)
		}
		for _, ext := range extensions {
			candidate := filepath.Join(dir, command+ext)
			if st, err := os.Stat(candidate); err == nil && !st.IsDir() && (runtime.GOOS == "windows" || st.Mode()&0111 != 0) {
				return candidate, nil
			}
		}
	}
	return "", fmt.Errorf("MCP executable %q not found in its configured PATH", command)
}

// newClientWithConn builds a Client over an arbitrary transport (used by tests).
func newClientWithConn(ctx context.Context, server string, r io.Reader, w io.Writer, closer io.Closer) (*Client, error) {
	c := &Client{server: server, conn: newConn(r, w), closer: closer}
	if err := c.initialize(ctx); err != nil {
		c.Close()
		return nil, err
	}
	return c, nil
}
