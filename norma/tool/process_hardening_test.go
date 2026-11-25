package tool

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"
	"unicode/utf8"
)

func sleepShellCmd(seconds int) string {
	if runtime.GOOS == "windows" {
		return fmt.Sprintf("Start-Sleep -Seconds %d", seconds)
	}
	return fmt.Sprintf("sleep %d", seconds)
}

func loopShellCmd() string {
	if runtime.GOOS == "windows" {
		return "for ($i = 0; $i -lt 300; $i++) { Start-Sleep -Milliseconds 100 }"
	}
	return "while true; do sleep 0.1; done"
}

func TestProcessHardeningDetachedAndSyncTimeout(t *testing.T) {
	cmd := exec.Command("echo", "ok")
	setDetached(cmd)
	if cmd.WaitDelay != 3*time.Second {
		t.Fatalf("WaitDelay = %v, want 3s", cmd.WaitDelay)
	}
	if cmd.Cancel == nil {
		t.Fatal("setDetached must install cmd.Cancel")
	}
	if cmd.SysProcAttr == nil {
		t.Fatal("setDetached must configure SysProcAttr")
	}
	if err := cmd.Cancel(); err != nil {
		t.Fatalf("Cancel before Start returned error: %v", err)
	}

	// Synchronous Bash path (tc.Tasks == nil) must honor timeout promptly and not hang.
	start := time.Now()
	raw, _ := json.Marshal(map[string]any{
		"command":    sleepShellCmd(30),
		"timeout_ms": 300,
	})
	res, err := NewBash().Call(context.Background(), raw, &ToolContext{WorkingDir: t.TempDir()})
	elapsed := time.Since(start)
	if err != nil {
		t.Fatalf("Bash.Call: %v", err)
	}
	if !res.IsError || !strings.Contains(res.Flatten(), "timed out") {
		t.Fatalf("expected timeout error, got err=%v out=%q", res.IsError, res.Flatten())
	}
	if elapsed > 6*time.Second {
		t.Fatalf("sync bash timeout hung for %v", elapsed)
	}
}

func TestBashBackgroundBoundsAndDenylist(t *testing.T) {
	denied := []string{
		"sleep 10",
		"/usr/bin/katana -u https://example.com",
		"HTTP_PROXY=http://127.0.0.1:8080 nuclei -u https://example.com",
		"httpx -l hosts.txt",
		"ffuf -u https://example.com/FUZZ",
		"naabu -host 127.0.0.1",
		"sqlmap -u https://example.com",
		"nmap -sV 127.0.0.1",
		"masscan 10.0.0.0/8",
		"gobuster dir -u https://example.com",
		"feroxbuster -u https://example.com",
		"dirsearch -u https://example.com",
		"subfinder -d example.com",
		"amass enum -d example.com",
		"chromium --headless",
		"google-chrome --headless",
		"playwright test",
		"curl https://example.com",
		"wget https://example.com",
		"python script.py",
		`C:\Python311\Python3.exe script.py`,
		"node runtime_harvest.js",
		// Chained & wrapped bypass attempts:
		"cd /tmp && nuclei -u https://example.com",
		"echo start || curl https://example.com",
		"echo start; sleep 30",
		"cat hosts.txt | httpx -silent",
		"echo a\npython3 exploit.py",
		"env FOO=1 BAR=2 nuclei -u https://example.com",
		"env -i -u HOME /usr/bin/katana -u https://example.com",
		"timeout 60 nuclei -u https://example.com",
		"timeout -s KILL --foreground 30s nmap -sV 127.0.0.1",
		"nohup python3 server.py",
		"nice -n 10 ffuf -u https://example.com/FUZZ",
		"sudo -u root -E sqlmap -u https://example.com",
		"(cd /tmp && (sleep 10))",
	}
	for _, cmd := range denied {
		if autoBackgroundAllowed(cmd) {
			t.Errorf("autoBackgroundAllowed(%q) = true, want false", cmd)
		}
	}
	allowed := []string{
		"while true; do echo tick; done",
		"for ($i=0; $i -lt 10; $i++) { echo $i }",
		"make build",
		"go test ./...",
		`echo "sleep 10; nuclei -u x"`,
		"make build 2>&1 | tee build.log",
	}
	for _, cmd := range allowed {
		if !autoBackgroundAllowed(cmd) {
			t.Errorf("autoBackgroundAllowed(%q) = false, want true", cmd)
		}
	}

	// Enforce per-session max running background tasks on both explicit BG and auto-BG.
	// Allocate workDir before newTestManager so LIFO t.Cleanup kills tasks before removing workDir.
	workDir := t.TempDir()
	m := newTestManager(t)
	m.SetLimits(2, 15*time.Minute)
	tc := &ToolContext{Tasks: m, WorkingDir: workDir}

	for i := range 2 {
		res := runTC(t, NewBash(), tc, map[string]any{
			"command":           sleepShellCmd(30),
			"run_in_background": true,
		})
		if res.IsError {
			t.Fatalf("bg launch %d failed: %s", i+1, res.Flatten())
		}
	}
	if got := m.RunningBackgroundCount(); got != 2 {
		t.Fatalf("RunningBackgroundCount = %d, want 2", got)
	}

	// 3rd explicit background launch must be refused.
	res := runTC(t, NewBash(), tc, map[string]any{
		"command":           sleepShellCmd(30),
		"run_in_background": true,
	})
	if !res.IsError || !strings.Contains(res.Flatten(), "background task limit reached") {
		t.Fatalf("expected background limit error, got err=%v out=%q", res.IsError, res.Flatten())
	}

	// Foreground timeout must NOT auto-background when background slots are full.
	res = runTC(t, NewBash(), tc, map[string]any{
		"command":    loopShellCmd(),
		"timeout_ms": 250,
	})
	if !res.IsError || !strings.Contains(res.Flatten(), "timed out") {
		t.Fatalf("expected timeout error when BG slots full, got err=%v out=%q", res.IsError, res.Flatten())
	}
	if got := m.RunningBackgroundCount(); got != 2 {
		t.Fatalf("RunningBackgroundCount after refused auto-bg = %d, want 2", got)
	}

	// Monitor must also respect MaxBackgroundTasks limit.
	monRes := runTC(t, NewMonitor(), tc, map[string]any{
		"command":     sleepShellCmd(30),
		"description": "over-limit-monitor",
	})
	if !monRes.IsError || !strings.Contains(monRes.Flatten(), "background task limit reached") {
		t.Fatalf("expected Monitor to enforce background limit, got err=%v out=%q", monRes.IsError, monRes.Flatten())
	}

	// Monitor must forward tc.Env to spawned subprocesses.
	mEnv := newTestManager(t)
	envCmd := "echo $ARTEX_MONITOR_TEST_VAR"
	if runtime.GOOS == "windows" {
		envCmd = "Write-Output $env:ARTEX_MONITOR_TEST_VAR"
	}
	tcEnv := &ToolContext{Tasks: mEnv, WorkingDir: workDir, Env: []string{"ARTEX_MONITOR_TEST_VAR=monitor_env_ok"}}
	monEnvRes := runTC(t, NewMonitor(), tcEnv, map[string]any{
		"command":     envCmd,
		"description": "env-check",
	})
	if monEnvRes.IsError {
		t.Fatalf("Monitor with Env failed: %s", monEnvRes.Flatten())
	}
	tasks := mEnv.List()
	if len(tasks) != 1 {
		t.Fatalf("expected 1 monitor task, got %d", len(tasks))
	}
	waitTerminal(t, mEnv, tasks[0].ID)
	out, err := mEnv.Output(tasks[0].ID, 0)
	if err != nil || !strings.Contains(out, "monitor_env_ok") {
		t.Fatalf("Monitor did not forward tc.Env: out=%q err=%v", out, err)
	}
}

func TestTaskTTLWatchdogAndCleanup(t *testing.T) {
	m, err := NewManager("test-ttl-" + fmt.Sprintf("%d", time.Now().UnixNano()))
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	m.SetLimits(4, 250*time.Millisecond)

	task, err := m.Spawn(SpawnSpec{Command: sleepShellCmd(30), Kind: KindBash, WorkingDir: t.TempDir()})
	if err != nil {
		m.Cleanup()
		t.Fatalf("Spawn: %v", err)
	}
	m.Background(task.ID)

	info, ok := m.Wait(context.Background(), task.ID, 5*time.Second)
	if !ok || info.Status != TaskFailed {
		m.Cleanup()
		t.Fatalf("ok=%v status=%s, want true/%s", ok, info.Status, TaskFailed)
	}
	notes := m.DrainNotifications()
	if len(notes) != 1 || !strings.Contains(notes[0].Summary, "运行超时已被终止") {
		m.Cleanup()
		t.Fatalf("expected TTL timeout notification, got %+v", notes)
	}
	m.Cleanup()

	// Verify Cleanup waits for task done and removes the session directory cleanly.
	m2, err := NewManager("test-cleanup-" + fmt.Sprintf("%d", time.Now().UnixNano()))
	if err != nil {
		t.Fatalf("NewManager2: %v", err)
	}
	t2, err := m2.Spawn(SpawnSpec{Command: sleepShellCmd(30), WorkingDir: t.TempDir()})
	if err != nil {
		m2.Cleanup()
		t.Fatalf("Spawn2: %v", err)
	}
	sessDir := filepath.Dir(m2.dir)
	m2.Cleanup()

	select {
	case <-t2.done:
	default:
		t.Fatal("Cleanup returned before task done channel closed")
	}
	if _, err := os.Stat(sessDir); !os.IsNotExist(err) {
		t.Fatalf("session directory still exists after Cleanup: %v", err)
	}
}

func TestPTYSessionLifecycleLimitsAndRace(t *testing.T) {
	// 1. closePTMX must be idempotent and race-free; writeInput after close must fail cleanly.
	rPipe, wPipe, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe: %v", err)
	}
	defer rPipe.Close()

	s := &ptySession{
		id:    "sh_test",
		ptmx:  wPipe,
		state: "running",
		done:  make(chan struct{}),
	}
	var wg sync.WaitGroup
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			s.closePTMX()
		}()
	}
	wg.Wait()
	if _, err := s.writeInput([]byte("x")); !errors.Is(err, os.ErrClosed) {
		t.Fatalf("writeInput after closePTMX = %v, want os.ErrClosed", err)
	}

	// 2. totalBytes must be race-free under concurrent append/read.
	s2 := &ptySession{id: "sh_race", state: "running", done: make(chan struct{})}
	var rw sync.WaitGroup
	rw.Add(2)
	go func() {
		defer rw.Done()
		for range 200 {
			s2.append([]byte("chunk-data\n"))
		}
	}()
	go func() {
		defer rw.Done()
		for range 200 {
			tot := s2.totalBytes()
			from := max(tot-64, 0)
			_, _, _ = s2.readSince(from, 0, 64, true)
		}
	}()
	rw.Wait()
	if got := s2.totalBytes(); got != int64(200*len("chunk-data\n")) {
		t.Fatalf("totalBytes = %d, want %d", got, 200*len("chunk-data\n"))
	}

	// 3. Active PTY session cap & reaper lifecycle.
	m := newTestManager(t)
	m.startSessionReaper()
	m.sessMu.Lock()
	for i := range maxActivePTYSessions {
		id := fmt.Sprintf("sh_synth_%d", i+1)
		m.sessions[id] = &ptySession{
			id:      id,
			state:   "running",
			lastOut: time.Now(),
			done:    make(chan struct{}),
		}
	}
	active := m.activePTYSessionsLocked()
	m.sessMu.Unlock()
	if active != maxActivePTYSessions {
		t.Fatalf("activePTYSessionsLocked = %d, want %d", active, maxActivePTYSessions)
	}
	if ptySupported() {
		if _, err := m.openSession("cat", "", nil, 24, 80, "hands-free", nil); err == nil || !strings.Contains(err.Error(), "上限") {
			t.Fatalf("expected active PTY session limit error, got %v", err)
		}
	}
	// Remove synthetic sessions (which have no readLoop to close done) before cleanup.
	m.sessMu.Lock()
	m.sessions = map[string]*ptySession{}
	m.sessMu.Unlock()

	if ptySupported() {
		// Verify natural exit closes ptmx.
		realSess, err := m.openSession("echo done-pty", "", nil, 24, 80, "hands-free", nil)
		if err != nil {
			t.Fatalf("openSession: %v", err)
		}
		select {
		case <-realSess.done:
		case <-time.After(5 * time.Second):
			t.Fatal("PTY session did not exit naturally")
		}
		realSess.mu.Lock()
		ptmxNil := realSess.ptmx == nil
		realSess.mu.Unlock()
		if !ptmxNil {
			t.Fatal("ptmx was not closed on natural PTY exit (FD leak)")
		}
	}
}

func TestCaptureWriterSpillCap(t *testing.T) {
	dir := t.TempDir()
	spillDir := filepath.Join(dir, "spill")
	tc := &ToolContext{MaxOutputChars: 100, WorkingDir: dir, OutputDir: spillDir}
	w := newCaptureWriter(tc)
	w.maxSpill = 1024

	chunk := []byte(strings.Repeat("line\n", 100)) // 500 bytes
	for range 20 {                                // 10,000 bytes total
		if _, err := w.Write(chunk); err != nil {
			t.Fatalf("Write: %v", err)
		}
	}
	out := w.finish()
	if !w.spillTruncated {
		t.Fatal("expected spillTruncated = true")
	}
	if w.total != 10000 {
		t.Fatalf("total = %d, want 10000", w.total)
	}
	if len(w.head) > 100 || len(w.tail) > 50 {
		t.Fatalf("head/tail exceeded memory bounds: head=%d tail=%d", len(w.head), len(w.tail))
	}
	if !strings.Contains(out, "<persisted-output>") || !strings.Contains(out, "truncated") || !strings.Contains(out, "1024") {
		t.Fatalf("missing spill truncation notice in output: %q", out)
	}
	entries, err := os.ReadDir(spillDir)
	if err != nil || len(entries) != 1 {
		t.Fatalf("expected 1 spill file, err=%v count=%d", err, len(entries))
	}
	fi, err := entries[0].Info()
	if err != nil {
		t.Fatalf("stat spill file: %v", err)
	}
	if fi.Size() != 1024 {
		t.Fatalf("spill file size = %d, want 1024", fi.Size())
	}

	// UTF-8 RuneStart safety for captureWriter and oneLine.
	wUTF := newCaptureWriter(&ToolContext{MaxOutputChars: 10})
	_, _ = wUTF.Write([]byte(strings.Repeat("中文", 20)))
	if got := wUTF.finish(); !utf8.ValidString(got) {
		t.Fatalf("captureWriter split multi-byte UTF-8 rune: %q", got)
	}
	if got := oneLine(strings.Repeat("你好世界", 10), 10); !utf8.ValidString(got) {
		t.Fatalf("oneLine split multi-byte UTF-8 rune: %q", got)
	}
}

func TestTailFileCapAndLimitReader(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "big.output")
	payload := strings.Repeat("A", maxTailReadBytes+64*1024) + "TAIL_END_MARKER\n"
	if err := os.WriteFile(path, []byte(payload), 0o600); err != nil {
		t.Fatal(err)
	}
	out, err := tailFile(path, maxTailReadBytes*4)
	if err != nil {
		t.Fatalf("tailFile: %v", err)
	}
	if !strings.Contains(out, "earlier output omitted") {
		t.Fatalf("missing omission notice: %q", out[:min(len(out), 120)])
	}
	if !strings.Contains(out, "TAIL_END_MARKER") {
		t.Fatal("missing tail marker")
	}
	// Output length must stay bounded by maxTailReadBytes + header.
	if len(out) > maxTailReadBytes+256 {
		t.Fatalf("tailFile exceeded 1 MiB cap: len=%d", len(out))
	}
}

func TestRipgrepLinePagerCaps(t *testing.T) {
	t.Run("head_limit=0 enforces maxRipgrepLines", func(t *testing.T) {
		p := newLinePager(0, 0)
		for i := range maxRipgrepLines + 50 {
			fmt.Fprintf(p, "line-%d\n", i)
		}
		kept, more := p.finish()
		if len(kept) != maxRipgrepLines {
			t.Fatalf("kept = %d, want %d", len(kept), maxRipgrepLines)
		}
		if more != 50 {
			t.Fatalf("more = %d, want 50", more)
		}
		if !p.hitSafetyCap(more) {
			t.Fatal("expected hitSafetyCap = true")
		}
	})

	t.Run("total buffered bytes ceiling", func(t *testing.T) {
		p := &linePager{limit: 0, maxLines: 5000, maxBytes: 512, maxLineBytes: 256}
		line := strings.Repeat("a", 120) + "\n"
		for range 10 {
			_, _ = p.Write([]byte(line))
		}
		kept, more := p.finish()
		if len(kept) >= 10 || len(kept) == 0 {
			t.Fatalf("unexpected kept count=%d", len(kept))
		}
		if p.bufferedBytes > 512 {
			t.Fatalf("bufferedBytes = %d > 512", p.bufferedBytes)
		}
		if more != 10-len(kept) || !p.hitSafetyCap(more) {
			t.Fatalf("more=%d hitSafetyCap=%v", more, p.hitSafetyCap(more))
		}
	})

	t.Run("single oversized line truncated once across chunks", func(t *testing.T) {
		p := newLinePager(10, 0)
		big := strings.Repeat("Z", maxRipgrepLineBytes+10000) + "\nnext-line\n"
		for at := 0; at < len(big); at += 1000 {
			_, _ = p.Write([]byte(big[at:min(at+1000, len(big))]))
		}
		kept, more := p.finish()
		if len(kept) != 2 || more != 0 {
			t.Fatalf("kept=%d more=%d, want 2, 0", len(kept), more)
		}
		wantLen := maxRipgrepLineBytes + len("...[truncated]")
		if len(kept[0]) != wantLen {
			t.Fatalf("truncated line len = %d, want %d", len(kept[0]), wantLen)
		}
		if strings.Count(kept[0], "...[truncated]") != 1 {
			t.Fatalf("expected exactly one truncation suffix, got %d", strings.Count(kept[0], "...[truncated]"))
		}
		if kept[1] != "next-line" {
			t.Fatalf("second line corrupted: %q", kept[1])
		}
	})

	t.Run("normal pagination within bounds preserves non-safety notice", func(t *testing.T) {
		p := newLinePager(3, 0)
		for i := range 10 {
			fmt.Fprintf(p, "row-%d\n", i)
		}
		kept, more := p.finish()
		if len(kept) != 3 || more != 7 || p.hitSafetyCap(more) {
			t.Fatalf("kept=%d more=%d safety=%v", len(kept), more, p.hitSafetyCap(more))
		}
	})
}

func TestSearchFileSizeLineCapAndGlobCap(t *testing.T) {
	t.Setenv("NORMA_DISABLE_RIPGREP", "1")
	dir := t.TempDir()

	// 1. scanFile skips files > maxGrepFileBytes.
	bigPath := filepath.Join(dir, "giant.log")
	bigData := make([]byte, maxGrepFileBytes+64)
	copy(bigData, "NEEDLE\n")
	for i := 7; i < len(bigData); i++ {
		bigData[i] = 'x'
	}
	if err := os.WriteFile(bigPath, bigData, 0o600); err != nil {
		t.Fatal(err)
	}
	smallPath := filepath.Join(dir, "small.log")
	if err := os.WriteFile(smallPath, []byte("NEEDLE\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	re := regexp.MustCompile("NEEDLE")
	if hit := scanFile(bigPath, dir, re, "content", true, false, 0, 0); hit != nil {
		t.Fatalf("giant file should be skipped, got %+v", hit)
	}
	if hit := scanFile(smallPath, dir, re, "content", true, false, 0, 0); hit == nil || hit.count != 1 {
		t.Fatalf("small file should match, got %+v", hit)
	}

	// 2. scanLineCount skips absurdly long single lines (> 256 KiB) and matches normal ones.
	longLinePath := filepath.Join(dir, "longline.txt")
	longContent := strings.Repeat("a", maxGrepLineBytes+50000) + "NEEDLE\nnormal NEEDLE line\n"
	if err := os.WriteFile(longLinePath, []byte(longContent), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := scanLineCount(longLinePath, re); got != 1 {
		t.Fatalf("scanLineCount = %d, want 1 (oversized line skipped, normal line counted)", got)
	}

	// 3. runGrep and runGlob honor cancelled ctx.
	cctx, cancel := context.WithCancel(context.Background())
	cancel()
	grepIn, _ := json.Marshal(map[string]any{"pattern": "NEEDLE"})
	if _, err := runGrep(cctx, grepIn, &ToolContext{WorkingDir: dir}); !errors.Is(err, context.Canceled) {
		t.Fatalf("runGrep with cancelled ctx: err = %v, want context.Canceled", err)
	}
	globIn, _ := json.Marshal(map[string]any{"pattern": "**/*"})
	if _, err := runGlob(cctx, globIn, &ToolContext{WorkingDir: dir}); !errors.Is(err, context.Canceled) {
		t.Fatalf("runGlob with cancelled ctx: err = %v, want context.Canceled", err)
	}

	// 4. runGlobWithCap truncates matches at cap and adds truncation notice.
	globDir := t.TempDir()
	for i := range 12 {
		if err := os.WriteFile(filepath.Join(globDir, fmt.Sprintf("f%02d.txt", i)), []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	res, err := runGlobWithCap(context.Background(), globIn, &ToolContext{WorkingDir: globDir}, 5)
	if err != nil {
		t.Fatalf("runGlobWithCap: %v", err)
	}
	out := res.Flatten()
	if !strings.Contains(out, "results truncated at 5 matches") {
		t.Fatalf("expected truncation notice, got: %q", out)
	}
	if strings.Count(out, ".txt") != 5 {
		t.Fatalf("expected 5 matched files, got: %q", out)
	}
}
