package server

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os/exec"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	actool "github.com/RC-CHN/ARTEX/norma/tool"
	"github.com/RC-CHN/ARTEX/traffic"
)

func TestNormalizeProxyURLAndSharedTransportReuse(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{"", ""},
		{"   ", ""},
		{"127.0.0.1:8788", "http://127.0.0.1:8788"},
		{"http://127.0.0.1:8788", "http://127.0.0.1:8788"},
		{"https://proxy.example:8443", "https://proxy.example:8443"},
		{"socks5://127.0.0.1:1080", "socks5://127.0.0.1:1080"},
	}
	for _, tc := range cases {
		if got := normalizeProxyURL(tc.in); got != tc.want {
			t.Errorf("normalizeProxyURL(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}

	s := &Server{}
	tr1, err1 := s.httpProxyTransport(httpExec{Proxy: "http://127.0.0.1:8788"})
	tr2, err2 := s.httpProxyTransport(httpExec{Proxy: "127.0.0.1:8788"})
	if err1 != nil || err2 != nil || tr1 == nil || tr2 == nil {
		t.Fatalf("expected non-nil pooled transports: tr1=(%v,%v) tr2=(%v,%v)", tr1, err1, tr2, err2)
	}
	if tr1 != tr2 {
		t.Fatal("normalized equivalent proxy URLs must share the same pooled transport")
	}
	req, _ := http.NewRequest(http.MethodGet, "http://example.com", nil)
	gotProxy, err := tr1.Proxy(req)
	if err != nil || gotProxy == nil || gotProxy.String() != "http://127.0.0.1:8788" {
		t.Fatalf("proxy = (%v, %v), want http://127.0.0.1:8788", gotProxy, err)
	}
	if tr, err := s.httpProxyTransport(httpExec{}); err != nil || tr != nil {
		t.Fatalf("empty proxy spec should return (nil, nil), got (%v, %v)", tr, err)
	}
}

func TestHTTPProxyTransportRecordingProxyHasNoDoubleScheme(t *testing.T) {
	tr, err := traffic.Open(t.TempDir(), "127.0.0.1:0")
	if err != nil {
		t.Fatalf("traffic.Open: %v", err)
	}
	defer tr.Close()

	addr := tr.ProxyAddr()
	if !strings.HasPrefix(addr, "http://") {
		t.Fatalf("unexpected ProxyAddr format: %q", addr)
	}

	s := &Server{m: &Manager{traffic: tr, trafficOn: true}}
	transport, err := s.httpProxyTransport(httpExec{UseRecordingProxy: true})
	if err != nil || transport == nil {
		t.Fatalf("expected non-nil transport for recording proxy, got (%v, %v)", transport, err)
	}
	req, _ := http.NewRequest(http.MethodGet, "http://example.com", nil)
	gotProxy, err := transport.Proxy(req)
	if err != nil || gotProxy == nil {
		t.Fatalf("transport.Proxy: (%v, %v)", gotProxy, err)
	}
	if strings.HasPrefix(gotProxy.String(), "http://http://") {
		t.Fatalf("double scheme bug regressed: %q", gotProxy.String())
	}
	if gotProxy.String() != addr {
		t.Fatalf("proxy URL = %q, want %q", gotProxy.String(), addr)
	}
}

func TestHTTPProxyTransportFallsBackToGlobalProxy(t *testing.T) {
	s := &Server{m: &Manager{globalProxy: "http://10.0.0.9:8080"}}

	// Unspecified custom proxy and UseRecordingProxy=false must still honor GlobalProxy.
	tr, err := s.httpProxyTransport(httpExec{})
	if err != nil || tr == nil {
		t.Fatalf("expected global proxy transport, got (%v, %v)", tr, err)
	}
	req, _ := http.NewRequest(http.MethodGet, "http://example.com", nil)
	gotProxy, err := tr.Proxy(req)
	if err != nil || gotProxy == nil || gotProxy.String() != "http://10.0.0.9:8080" {
		t.Fatalf("fallback proxy = (%v, %v), want http://10.0.0.9:8080", gotProxy, err)
	}

	// Explicit per-tool proxy overrides GlobalProxy.
	trCustom, err := s.httpProxyTransport(httpExec{Proxy: "socks5://10.0.0.8:1080"})
	if err != nil || trCustom == nil {
		t.Fatalf("expected custom proxy transport, got (%v, %v)", trCustom, err)
	}
	gotCustom, err := trCustom.Proxy(req)
	if err != nil || gotCustom == nil || gotCustom.String() != "socks5://10.0.0.8:1080" {
		t.Fatalf("custom proxy = (%v, %v), want socks5://10.0.0.8:1080", gotCustom, err)
	}
}

func TestLimitedBufferCapsMemoryAndMarksTruncation(t *testing.T) {
	lb := newLimitedBuffer(16)
	var wg sync.WaitGroup
	for range 4 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			n, err := lb.Write([]byte("0123456789"))
			if err != nil || n != 10 {
				t.Errorf("Write returned (%d, %v), want (10, nil)", n, err)
			}
		}()
	}
	wg.Wait()

	out := lb.String()
	if !strings.Contains(out, "输出超出 16 字节上限") {
		t.Fatalf("expected truncation marker in output: %q", out)
	}
	if !strings.Contains(out, "已截断 24 字节") {
		t.Fatalf("expected dropped byte count 24 in output: %q", out)
	}
	if lb.buf.Len() != 16 {
		t.Fatalf("internal buffer length = %d, want 16", lb.buf.Len())
	}
}

func TestConfigurePythonCmdGuards(t *testing.T) {
	cmd := exec.Command("python3", "-c", "pass")
	configurePythonCmd(cmd)
	if cmd.Cancel == nil {
		t.Fatal("configurePythonCmd must install Cancel")
	}
	if cmd.WaitDelay != 3*time.Second {
		t.Fatalf("WaitDelay = %v, want 3s", cmd.WaitDelay)
	}
	// Cancel before Start must be nil-safe.
	if err := cmd.Cancel(); err != nil {
		t.Fatalf("Cancel with nil Process returned error: %v", err)
	}
}

func findRunnablePython(t *testing.T) string {
	t.Helper()
	for _, name := range []string{"python3", "python"} {
		p, err := exec.LookPath(name)
		if err != nil {
			continue
		}
		if exec.Command(p, "-c", "pass").Run() == nil {
			return p
		}
	}
	return ""
}

func TestExecPythonOutputLimitAndTimeout(t *testing.T) {
	interp := findRunnablePython(t)
	if interp == "" {
		t.Skip("runnable python interpreter unavailable")
	}

	t.Run("bounded output truncates cleanly", func(t *testing.T) {
		code := "import sys\nsys.stdout.write('A' * 4096)\nsys.stdout.flush()\n"
		out, err := execPythonWithLimit(context.Background(), interp, "limit", code,
			map[string]any{}, t.TempDir(), nil, 10*time.Second, 256)
		if err != nil {
			t.Fatalf("execPythonWithLimit: %v", err)
		}
		if !strings.Contains(out, "输出超出 256 字节上限") {
			t.Fatalf("missing truncation marker: %q", out)
		}
		if len(out) > 512 {
			t.Fatalf("output was not bounded: len=%d", len(out))
		}
	})

	t.Run("timeout terminates process promptly", func(t *testing.T) {
		code := "import time\ntime.sleep(30)\n"
		if runtime.GOOS != "windows" {
			// Also spawn a grandchild inheriting stdout to verify process-group kill.
			code = "import subprocess, time\nsubprocess.Popen(['sleep', '30'])\ntime.sleep(30)\n"
		}
		start := time.Now()
		out, err := execPython(context.Background(), interp, "timeout", code,
			map[string]any{}, t.TempDir(), nil, 300*time.Millisecond)
		elapsed := time.Since(start)
		if err != nil {
			t.Fatalf("execPython: %v", err)
		}
		if !strings.Contains(out, "[超时终止]") {
			t.Fatalf("expected timeout marker, got: %q", out)
		}
		if elapsed > 5*time.Second {
			t.Fatalf("timed out script hung for %v", elapsed)
		}
	})
}

func TestDecodeAndTrafficDeleteBodyLimits(t *testing.T) {
	oversized := `{"x":"` + strings.Repeat("a", maxDecodeBodyBytes+1024) + `"}`
	req := httptest.NewRequest(http.MethodPost, "/api/test", strings.NewReader(oversized))
	var dst map[string]string
	err := decode(req, &dst)
	var maxErr *http.MaxBytesError
	if !errors.As(err, &maxErr) {
		t.Fatalf("decode oversized body: got err=%v, want *http.MaxBytesError", err)
	}

	tr, err := traffic.Open(t.TempDir(), "")
	if err != nil {
		t.Fatalf("traffic.Open: %v", err)
	}
	defer tr.Close()
	s := &Server{m: &Manager{traffic: tr}}
	bigHosts := `{"hosts":["` + strings.Repeat("h", (4<<20)+1024) + `"]}`
	tReq := httptest.NewRequest(http.MethodPost, "/api/traffic/delete-hosts", strings.NewReader(bigHosts))
	rec := httptest.NewRecorder()
	s.deleteTrafficHosts(rec, tReq)
	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("deleteTrafficHosts oversized status = %d, want 413 (body=%s)", rec.Code, rec.Body.String())
	}
}

func TestCustomToolCommandForwardsTimeoutMS(t *testing.T) {
	// Verify payload builder includes timeout_ms when > 0 and omits it otherwise.
	var withTimeout map[string]any
	if err := json.Unmarshal(buildCommandBashInput("echo ok", 45000), &withTimeout); err != nil {
		t.Fatalf("unmarshal payload with timeout: %v", err)
	}
	if withTimeout["command"] != "echo ok" || withTimeout["timeout_ms"] != float64(45000) {
		t.Fatalf("unexpected payload with timeout: %+v", withTimeout)
	}

	var withoutTimeout map[string]any
	if err := json.Unmarshal(buildCommandBashInput("echo ok", 0), &withoutTimeout); err != nil {
		t.Fatalf("unmarshal payload without timeout: %v", err)
	}
	if _, has := withoutTimeout["timeout_ms"]; has {
		t.Fatalf("timeout_ms should be omitted when <= 0: %+v", withoutTimeout)
	}

	// End-to-end: runCommandTool enforces configured timeout_ms promptly.
	sleepCmd := "sleep 30"
	if runtime.GOOS == "windows" {
		sleepCmd = "Start-Sleep -Seconds 30"
	}
	execRaw, _ := json.Marshal(commandExec{Command: sleepCmd, TimeoutMs: 300})
	start := time.Now()
	res, err := (&Server{}).runCommandTool(context.Background(), execRaw, map[string]any{}, &actool.ToolContext{WorkingDir: t.TempDir()})
	elapsed := time.Since(start)
	if err != nil {
		t.Fatalf("runCommandTool: %v", err)
	}
	out := res.Flatten()
	if !res.IsError || (!strings.Contains(out, "timed out") && !strings.Contains(out, "deadline")) {
		t.Fatalf("expected timeout result, got isErr=%v out=%q", res.IsError, out)
	}
	if elapsed > 6*time.Second {
		t.Fatalf("runCommandTool hung past timeout: %v", elapsed)
	}
}
