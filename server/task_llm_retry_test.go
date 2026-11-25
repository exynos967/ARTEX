package server

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/RC-CHN/ARTEX/db"
	"github.com/RC-CHN/ARTEX/llmpool"
	"github.com/RC-CHN/ARTEX/norma/harness"
	"github.com/RC-CHN/ARTEX/norma/llm"
)

func TestIsRetryableStreamErrorDeduplicatesLowerLayerRetries(t *testing.T) {
	t.Parallel()
	nonRetryable := []struct {
		name string
		err  error
	}{
		{"nil", nil},
		{"http 408", errors.New("openai: status 408: request timeout")},
		{"http 429", errors.New("openai: status 429: rate limit exceeded")},
		{"rate limit phrase", errors.New("anthropic: rate_limit_error: too many requests")},
		{"http 500", errors.New("openai: status 500: internal server error")},
		{"http 502", errors.New("anthropic: status 502: bad gateway")},
		{"http 503", errors.New("anthropic: status 503: service unavailable")},
		{"http 504", errors.New("openai: status 504: gateway timeout")},
		{"dial tcp string", errors.New("Post \"https://api.example.com\": dial tcp 1.2.3.4:443: i/o timeout")},
		{"net.OpError dial", &net.OpError{Op: "dial", Net: "tcp", Err: errors.New("connection refused")}},
		{"dns no such host", errors.New("lookup api.example.com: no such host")},
		{"tls handshake timeout", errors.New("net/http: TLS handshake timeout")},
		{"llmpool exhausted", fmt.Errorf("%w：anthropic: status 503: down", llmpool.ErrExhausted)},
		{"incomplete response", &llm.IncompleteResponseError{Reason: llm.IncompleteMissingTerminal}},
		{"http 400", errors.New("anthropic: status 400: invalid request")},
		{"http 401", errors.New("openai: status 401: invalid api key")},
		{"http 403", errors.New("openai: status 403: forbidden")},
		{"http 413 overflow", errors.New("anthropic: status 413: request too large")},
		{"quota exhausted", errors.New("openai: status 402: insufficient_quota")},
		{"ctx canceled", context.Canceled},
		{"ctx deadline", context.DeadlineExceeded},
	}
	for _, tc := range nonRetryable {
		if isRetryableStreamError(tc.err) {
			t.Errorf("%s (%v): isRetryableStreamError=true, want false", tc.name, tc.err)
		}
	}

	retryable := []struct {
		name string
		err  error
	}{
		{"mid-stream read reset", errors.New("read tcp 10.0.0.1:443: connection reset by peer")},
		{"unexpected EOF", io.ErrUnexpectedEOF},
		{"in-stream anthropic overloaded", errors.New("anthropic: overloaded_error")},
		{"http2 closed body", errors.New("http2: response body closed")},
	}
	for _, tc := range retryable {
		if !isRetryableStreamError(tc.err) {
			t.Errorf("%s (%v): isRetryableStreamError=false, want true", tc.name, tc.err)
		}
	}
}

func TestStreamTaskLLMDoesNotDoubleRetry429Or5xxOrExhausted(t *testing.T) {
	defer withZeroRetryBackoff()()
	cases := []struct {
		name string
		err  error
	}{
		{"429", errors.New("openai: status 429: rate limit exceeded")},
		{"503", errors.New("anthropic: status 503: service unavailable")},
		{"dial", errors.New("dial tcp 1.2.3.4:443: connection refused")},
		{"pool_exhausted", fmt.Errorf("%w：status 503", llmpool.ErrExhausted)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			prov := &flakyThenOKProvider{
				failCount: 99,
				failErr:   tc.err,
			}
			hooks := taskLLMStreamHooks{
				current: func() (taskLLMSelection, error) {
					return taskLLMSelection{profileID: 11, provider: prov}, nil
				},
				exhaust: func(taskLLMSelection, error) (db.TaskLLMTransition, error) {
					return db.TaskLLMTransition{}, nil
				},
			}
			_, err := collectTaskLLMStream(streamTaskLLM(context.Background(), "7", llm.CompletionRequest{}, hooks))
			if err == nil {
				t.Fatal("expected error to surface")
			}
			if prov.calls != 1 {
				t.Fatalf("%s was double-retried by streamTaskLLM: calls=%d, want 1", tc.name, prov.calls)
			}
		})
	}
}

func TestSameProviderRetryBackoffJitterBounds(t *testing.T) {
	t.Parallel()
	cases := []struct {
		attempt int
		base    time.Duration
	}{
		{0, 500 * time.Millisecond},
		{1, 1 * time.Second},
		{2, 2 * time.Second},
		{3, 4 * time.Second},
		{25, 4 * time.Second}, // large attempt must not overflow bit shift
	}
	for _, tc := range cases {
		seen := map[time.Duration]bool{}
		for range 32 {
			d := sameProviderRetryBackoff(tc.attempt)
			if d < tc.base/2 || d > tc.base {
				t.Fatalf("attempt %d: backoff=%v outside [%v, %v]", tc.attempt, d, tc.base/2, tc.base)
			}
			seen[d] = true
		}
		if len(seen) < 2 {
			t.Fatalf("attempt %d: backoff produced constant %v across 32 samples (no jitter)", tc.attempt, seen)
		}
	}
}

func TestRetryableWorkerModelErrorSkipsAlreadyRetriedErrors(t *testing.T) {
	t.Parallel()
	noReplay := []struct {
		name string
		err  error
	}{
		{"429", errors.New("openai: status 429: rate limit exceeded")},
		{"rate limit text", errors.New("rate limit exceeded")},
		{"pool exhausted", fmt.Errorf("%w：status 503", llmpool.ErrExhausted)},
		{"500", errors.New("anthropic: status 500: internal server error")},
		{"502", errors.New("anthropic: status 502: bad gateway")},
		{"503", errors.New("anthropic: status 503: service unavailable")},
		{"504", errors.New("openai: status 504: gateway timeout")},
		{"408", errors.New("openai: status 408: request timeout")},
		{"401", errors.New("openai: status 401: invalid api key")},
		{"incomplete", &llm.IncompleteResponseError{Reason: llm.IncompleteStreamRead}},
		{"quota", errors.New("openai: status 402: insufficient_quota")},
	}
	for _, tc := range noReplay {
		if retryableWorkerModelError(harness.ReasonModelError, tc.err) {
			t.Errorf("%s (%v): retryableWorkerModelError=true, want false", tc.name, tc.err)
		}
	}

	replay := []error{
		errors.New("read tcp 10.0.0.1:443: connection reset by peer"),
		io.ErrUnexpectedEOF,
		errors.New("temporary network error"),
	}
	for _, err := range replay {
		if !retryableWorkerModelError(harness.ReasonModelError, err) {
			t.Errorf("%v: retryableWorkerModelError=false, want true", err)
		}
	}
}

func TestPoolForBindingCacheAndInvalidation(t *testing.T) {
	t.Parallel()
	s := &Server{
		taskAgents: map[string]*taskAgentBundle{},
	}
	var builds atomic.Int32
	builder := func() llm.Provider {
		builds.Add(1)
		return llmpool.New([]*llmpool.Member{
			{ID: 1, Name: "p1", Prov: &scriptedLLMProvider{}},
			{ID: 2, Name: "p2", Prov: &scriptedLLMProvider{}},
		}, nil)
	}

	first := s.poolForBindingCached(42, builder)
	for range 5 {
		got := s.poolForBindingCached(42, builder)
		if got != first {
			t.Fatal("cached binding pool returned a different instance before invalidation")
		}
	}
	if builds.Load() != 1 {
		t.Fatalf("builder called %d times, want 1", builds.Load())
	}

	// invalidateTaskAgents must clear cached binding pools.
	s.invalidateTaskAgents()
	second := s.poolForBindingCached(42, builder)
	if second == first {
		t.Fatal("expected a freshly built pool after invalidateTaskAgents")
	}
	if builds.Load() != 2 {
		t.Fatalf("builder called %d times after invalidateTaskAgents, want 2", builds.Load())
	}

	// Bumping provCacheGen (as invalidateProfileAgents does) must also invalidate.
	s.provCacheMu.Lock()
	s.provCacheGen++
	s.provCacheMu.Unlock()
	third := s.poolForBindingCached(42, builder)
	if third == second {
		t.Fatal("expected a freshly built pool after provCacheGen bump")
	}
	if builds.Load() != 3 {
		t.Fatalf("builder called %d times after provCacheGen bump, want 3", builds.Load())
	}

	// Concurrent reads on a warm entry share one pool instance without races.
	var wg sync.WaitGroup
	for range 16 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if got := s.poolForBindingCached(42, builder); got != third {
				t.Errorf("concurrent cache read returned mismatched pool instance")
			}
		}()
	}
	wg.Wait()
	if builds.Load() != 3 {
		t.Fatalf("concurrent reads triggered rebuilds: builds=%d, want 3", builds.Load())
	}
}
