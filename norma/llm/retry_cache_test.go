package llm

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestParseRetryAfter(t *testing.T) {
	now := time.Date(2026, 11, 24, 12, 0, 0, 0, time.UTC)

	cases := []struct {
		name   string
		header string
		want   time.Duration
		wantOK bool
	}{
		{"empty", "", 0, false},
		{"garbage", "not-a-header", 0, false},
		{"delta integer", "5", 5 * time.Second, true},
		{"delta float", "0.25", 250 * time.Millisecond, true},
		{"delta zero", "0", 0, true},
		{"delta negative clamped to 0", "-3", 0, true},
		{"delta clamped to 60s", "180", 60 * time.Second, true},
		{"http-date future", now.Add(12 * time.Second).Format(http.TimeFormat), 12 * time.Second, true},
		{"http-date past clamped to 0", now.Add(-10 * time.Second).Format(http.TimeFormat), 0, true},
		{"http-date capped at 60s", now.Add(5 * time.Minute).Format(http.TimeFormat), 60 * time.Second, true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := parseRetryAfter(tc.header, now)
			if ok != tc.wantOK || got != tc.want {
				t.Fatalf("parseRetryAfter(%q) = (%v, %v), want (%v, %v)", tc.header, got, ok, tc.want, tc.wantOK)
			}
		})
	}
}

func TestExpBackoffJitterBoundsAndSpread(t *testing.T) {
	for _, tc := range []struct {
		attempt int
		wantMax time.Duration
	}{
		{0, 500 * time.Millisecond},
		{1, time.Second},
		{2, 2 * time.Second},
		{3, 4 * time.Second},
		{4, 8 * time.Second},
		{10, 8 * time.Second},
		{100, 8 * time.Second}, // must never shift-overflow
	} {
		seen := map[time.Duration]bool{}
		wantMin := tc.wantMax / 2
		for range 64 {
			d := expBackoff(tc.attempt)
			if d < wantMin || d > tc.wantMax {
				t.Fatalf("expBackoff(%d)=%v outside [%v, %v]", tc.attempt, d, wantMin, tc.wantMax)
			}
			seen[d] = true
		}
		if len(seen) < 2 {
			t.Fatalf("expBackoff(%d) produced constant values (%v); jitter not active", tc.attempt, seen)
		}
	}
}

// Verifies doStream honors a Retry-After header when it exceeds the base retry delay.
func TestDoStreamHonorsRetryAfter(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if calls.Add(1) == 1 {
			w.Header().Set("Retry-After", "0.08")
			w.WriteHeader(http.StatusTooManyRequests)
			w.Write([]byte(`{"error":"rate limited"}`))
			return
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`ok`))
	}))
	defer srv.Close()

	cfg := Config{
		HTTPClient:    srv.Client(),
		MaxRetries:    2,
		RetryInterval: 5 * time.Millisecond,
	}
	start := time.Now()
	resp, err := doStream(context.Background(), cfg, srv.URL, []byte(`{}`), func(*http.Request) {}, "openai")
	elapsed := time.Since(start)
	if err != nil {
		t.Fatalf("doStream err: %v", err)
	}
	resp.Body.Close()
	if calls.Load() != 2 {
		t.Fatalf("calls=%d, want 2", calls.Load())
	}
	if elapsed < 60*time.Millisecond {
		t.Fatalf("elapsed=%v, expected Retry-After (>= ~80ms) to override 5ms RetryInterval", elapsed)
	}
}

// Verifies retryable response bodies are drained before closing so net/http
// reuses the underlying TCP keep-alive connection across retries.
func TestDoStreamDrainsRetryBodyForKeepAliveReuse(t *testing.T) {
	var calls atomic.Int32
	var addrs [2]string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := calls.Add(1)
		if n <= 2 {
			addrs[n-1] = r.RemoteAddr
		}
		if n == 1 {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusServiceUnavailable)
			// Small error body (< 4 KiB): if not drained before Close, net/http
			// discards the connection and dials a fresh RemoteAddr on attempt 2.
			w.Write([]byte(strings.Repeat("e", 1024)))
			return
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`ok`))
	}))
	defer srv.Close()

	cfg := Config{
		HTTPClient:    srv.Client(),
		MaxRetries:    1,
		RetryInterval: time.Millisecond,
	}
	resp, err := doStream(context.Background(), cfg, srv.URL, []byte(`{}`), func(*http.Request) {}, "openai")
	if err != nil {
		t.Fatalf("doStream err: %v", err)
	}
	_, _ = io.ReadAll(resp.Body)
	resp.Body.Close()

	if calls.Load() != 2 {
		t.Fatalf("calls=%d, want 2", calls.Load())
	}
	if addrs[0] == "" || addrs[0] != addrs[1] {
		t.Fatalf("keep-alive connection was not reused across retry: addr1=%q addr2=%q", addrs[0], addrs[1])
	}
}

// Verifies cfg.limiter.Wait is invoked INSIDE the retry loop on every attempt,
// including retries, instead of being bypassed after attempt 0.
func TestDoStreamRateLimiterInvokedOnRetries(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if calls.Add(1) < 3 {
			w.WriteHeader(http.StatusServiceUnavailable)
			w.Write([]byte("busy"))
			return
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ok"))
	}))
	defer srv.Close()

	var waitCalls atomic.Int32
	limiter := newRateLimiter(RateLimit{
		PerSecond: 1000,
		Burst:     1000,
		OnWait: func(time.Duration) {
			waitCalls.Add(1)
		},
	})
	cfg := Config{
		HTTPClient:    srv.Client(),
		MaxRetries:    3,
		RetryInterval: time.Millisecond,
		limiter:       limiter,
	}
	resp, err := doStream(context.Background(), cfg, srv.URL, []byte(`{}`), func(*http.Request) {}, "openai")
	if err != nil {
		t.Fatalf("doStream err: %v", err)
	}
	resp.Body.Close()

	if calls.Load() != 3 {
		t.Fatalf("http calls=%d, want 3", calls.Load())
	}
	if waitCalls.Load() != 3 {
		t.Fatalf("limiter Wait calls=%d, want 3 (must run on every retry attempt)", waitCalls.Load())
	}
}

// Verifies terminal error body reads are capped at maxErrorBodyBytes (256 KiB).
func TestDoStreamCapsErrorBodyRead(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte(strings.Repeat("A", maxErrorBodyBytes+64*1024)))
	}))
	defer srv.Close()

	cfg := Config{HTTPClient: srv.Client(), MaxRetries: -1}
	_, err := doStream(context.Background(), cfg, srv.URL, []byte(`{}`), func(*http.Request) {}, "openai")
	if err == nil {
		t.Fatal("expected error for 400")
	}
	if len(err.Error()) > maxErrorBodyBytes+128 {
		t.Fatalf("error body was not capped: len=%d (cap=%d)", len(err.Error()), maxErrorBodyBytes)
	}
}

// Verifies defaultHTTPClient configures transport pooling & handshake timeouts.
func TestDefaultHTTPClientTransportTuning(t *testing.T) {
	for _, proxy := range []string{"", "http://127.0.0.1:8080"} {
		client, err := defaultHTTPClient(proxy)
		if err != nil {
			t.Fatalf("defaultHTTPClient(%q): %v", proxy, err)
		}
		tr, ok := client.Transport.(*http.Transport)
		if !ok {
			t.Fatalf("transport=%T, want *http.Transport", client.Transport)
		}
		if tr.MaxIdleConnsPerHost != 32 {
			t.Fatalf("MaxIdleConnsPerHost=%d, want 32", tr.MaxIdleConnsPerHost)
		}
		if tr.IdleConnTimeout != 60*time.Second {
			t.Fatalf("IdleConnTimeout=%v, want 60s", tr.IdleConnTimeout)
		}
		if tr.TLSHandshakeTimeout != 10*time.Second {
			t.Fatalf("TLSHandshakeTimeout=%v, want 10s", tr.TLSHandshakeTimeout)
		}
	}
}
