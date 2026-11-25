package llmpool

import (
	"context"
	"errors"
	"fmt"
	"iter"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/RC-CHN/ARTEX/norma/llm"
	"github.com/RC-CHN/ARTEX/norma/transcript"
)

// Verifies that equal-priority backup profiles stay session-sticky when a
// session key is supplied via PromptCacheKey, WithPromptCacheKey, or
// transcript.WithSessionID, while distinct sessions still spread across backups.
func TestSessionStickyEqualRankRouting(t *testing.T) {
	for _, mode := range []string{"stream", "complete"} {
		t.Run(mode, func(t *testing.T) {
			head := member(1, "head", RankActive, failProv("head", 402))
			b1 := okProv("b1", "b1")
			b2 := okProv("b2", "b2")
			b3 := okProv("b3", "b3")
			b4 := okProv("b4", "b4")
			reg := NewRegistry(nil, nil)
			reg.Trip(1, "402", true) // head already tripped so backups handle traffic
			p := New([]*Member{
				head,
				member(2, "b1", 5, b1),
				member(3, "b2", 5, b2),
				member(4, "b3", 5, b3),
				member(5, "b4", 5, b4),
			}, reg)

			call := func(ctx context.Context, req llm.CompletionRequest) string {
				if mode == "stream" {
					txt, err := drain(p.Stream(ctx, req))
					if err != nil {
						t.Fatalf("stream err: %v", err)
					}
					return txt
				}
				msg, _, _, err := p.Complete(ctx, req)
				if err != nil {
					t.Fatalf("complete err: %v", err)
				}
				return msg.Text()
			}

			// 1. PromptCacheKey on context: repeated turns stick to the exact same backup.
			ctxCache := llm.WithPromptCacheKey(context.Background(), "cache-session-alpha")
			first := call(ctxCache, llm.CompletionRequest{})
			for range 8 {
				if got := call(ctxCache, llm.CompletionRequest{}); got != first {
					t.Fatalf("WithPromptCacheKey did not stick: first=%q got=%q", first, got)
				}
			}

			// 2. transcript.WithSessionID on context: repeated turns stick to the exact same backup.
			ctxSID := transcript.WithSessionID(context.Background(), "transcript-session-beta")
			firstSID := call(ctxSID, llm.CompletionRequest{})
			for range 8 {
				if got := call(ctxSID, llm.CompletionRequest{}); got != firstSID {
					t.Fatalf("WithSessionID did not stick: first=%q got=%q", firstSID, got)
				}
			}

			// 3. Explicit req.PromptCacheKey: repeated turns stick to the exact same backup.
			reqKey := llm.CompletionRequest{PromptCacheKey: "explicit-req-key"}
			firstReq := call(context.Background(), reqKey)
			for range 8 {
				if got := call(context.Background(), reqKey); got != firstReq {
					t.Fatalf("req.PromptCacheKey did not stick: first=%q got=%q", firstReq, got)
				}
			}

			// 4. Different sessions still distribute across multiple equal-rank backups.
			dist := map[string]int{}
			for i := range 32 {
				ctx := llm.WithPromptCacheKey(context.Background(), fmt.Sprintf("session-%d", i))
				dist[call(ctx, llm.CompletionRequest{})]++
			}
			if len(dist) < 2 {
				t.Fatalf("expected different sessions to spread across backups, got %v", dist)
			}
		})
	}
}

// Verifies Registry.AllowProbe single-flight behavior on half-open profiles:
// only one caller is admitted until Pass, Trip, Reset, ReleaseProbe, or lease expiry.
func TestRegistryHalfOpenSingleFlightAllowProbe(t *testing.T) {
	reg := NewRegistry(nil, nil)
	reg.probeTimeout = 40 * time.Millisecond

	// Closed profile allows concurrent callers freely.
	if !reg.AllowProbe(1) || !reg.AllowProbe(1) {
		t.Fatal("closed profile should allow repeated concurrent calls")
	}

	// Open profile denies callers.
	reg.Trip(1, "402", true)
	if reg.AllowProbe(1) {
		t.Fatal("open profile should deny probe")
	}

	// Half-open (expired OpenUntil): only ONE caller admitted at a time.
	reg.Restore(1, State{Trips: 1, OpenUntil: time.Now().Add(-time.Second)})
	tok1, ok := reg.TryAcquireProbe(1)
	if !ok || tok1 == 0 {
		t.Fatalf("first half-open caller should be admitted with non-zero token, got (%d, %v)", tok1, ok)
	}
	if _, ok := reg.TryAcquireProbe(1); ok {
		t.Fatal("second concurrent half-open caller must be denied while probe is in flight")
	}

	// Wrong token must NOT release the active probe lease.
	reg.ReleaseProbe(1, tok1+999)
	if _, ok := reg.TryAcquireProbe(1); ok {
		t.Fatal("mismatched token must not release active probe lease")
	}

	// Matching ReleaseProbe unlocks without resetting failure state.
	reg.ReleaseProbe(1, tok1)
	if reg.Get(1).Trips != 1 {
		t.Fatalf("ReleaseProbe mutated state: %+v", reg.Get(1))
	}
	tok2, ok := reg.TryAcquireProbe(1)
	if !ok || tok2 == 0 {
		t.Fatalf("after ReleaseProbe, next caller should be admitted, got (%d, %v)", tok2, ok)
	}

	// Lease expiry safety net re-admits a newer probe; late ReleaseProbe with
	// the expired tok2 must NOT delete tok3's active lease!
	time.Sleep(55 * time.Millisecond)
	tok3, ok := reg.TryAcquireProbe(1)
	if !ok || tok3 == 0 || tok3 == tok2 {
		t.Fatalf("after probe lease expiry, next caller should be admitted with fresh token, got (%d, %v)", tok3, ok)
	}
	reg.ReleaseProbe(1, tok2) // stale slow probe finishes late
	if _, ok := reg.TryAcquireProbe(1); ok {
		t.Fatal("expired slow probe's ReleaseProbe deleted newer probe's active lease")
	}

	// Failed transient probe immediately re-opens the breaker.
	if !reg.Trip(1, "503", false) {
		t.Fatal("failed half-open probe should re-trip the breaker")
	}
	if !reg.IsOpen(1) || reg.AllowProbe(1) {
		t.Fatal("re-tripped breaker should stay open and deny probes")
	}

	// Successful probe clears state and re-admits concurrent callers.
	reg.Restore(1, State{Trips: 2, OpenUntil: time.Now().Add(-time.Second)})
	if !reg.AllowProbe(1) {
		t.Fatal("expected probe admission")
	}
	reg.Pass(1)
	if reg.Get(1) != (State{}) || !reg.AllowProbe(1) || !reg.AllowProbe(1) {
		t.Fatalf("Pass should fully recover profile: %+v", reg.Get(1))
	}
}

// Verifies that when the head profile's breaker expires (half-open) and 16
// concurrent goroutines arrive, ONLY ONE probes the head while the other 15
// immediately use the healthy backup without waiting or hammering the head.
func TestPoolHalfOpenSingleFlightNoThunderingHerd(t *testing.T) {
	for _, mode := range []string{"stream", "complete"} {
		t.Run(mode, func(t *testing.T) {
			var headCalls, backupCalls atomic.Int32
			probeStarted := make(chan struct{})
			releaseProbe := make(chan struct{})

			headProv := callbackProvider{
				stream: func(ctx context.Context, _ llm.CompletionRequest) iter.Seq2[llm.StreamEvent, error] {
					return func(yield func(llm.StreamEvent, error) bool) {
						if headCalls.Add(1) == 1 {
							close(probeStarted)
							<-releaseProbe
						}
						yield(llm.StreamEvent{Type: llm.SETextDelta, Text: "head"}, nil)
						yield(llm.StreamEvent{Type: llm.SEMessageStop}, nil)
					}
				},
				complete: func(ctx context.Context, _ llm.CompletionRequest) (llm.Message, string, llm.Usage, error) {
					if headCalls.Add(1) == 1 {
						close(probeStarted)
						<-releaseProbe
					}
					return llm.Message{Role: llm.RoleAssistant, Content: []llm.ContentBlock{llm.TextBlock("head")}}, "end_turn", llm.Usage{}, nil
				},
			}
			backupProv := callbackProvider{
				stream: func(ctx context.Context, _ llm.CompletionRequest) iter.Seq2[llm.StreamEvent, error] {
					backupCalls.Add(1)
					return func(yield func(llm.StreamEvent, error) bool) {
						yield(llm.StreamEvent{Type: llm.SETextDelta, Text: "backup"}, nil)
						yield(llm.StreamEvent{Type: llm.SEMessageStop}, nil)
					}
				},
				complete: func(ctx context.Context, _ llm.CompletionRequest) (llm.Message, string, llm.Usage, error) {
					backupCalls.Add(1)
					return llm.Message{Role: llm.RoleAssistant, Content: []llm.ContentBlock{llm.TextBlock("backup")}}, "end_turn", llm.Usage{}, nil
				},
			}

			reg := NewRegistry(nil, nil)
			reg.Restore(1, State{Trips: 1, OpenUntil: time.Now().Add(-time.Second)}) // head is half-open
			p := New([]*Member{member(1, "head", RankActive, headProv), member(2, "backup", 5, backupProv)}, reg)

			const total = 16
			var wg sync.WaitGroup
			wg.Add(1)
			go func() {
				defer wg.Done()
				if mode == "stream" {
					txt, err := drain(p.Stream(context.Background(), llm.CompletionRequest{}))
					if err != nil || txt != "head" {
						t.Errorf("probe stream: txt=%q err=%v", txt, err)
					}
				} else {
					msg, _, _, err := p.Complete(context.Background(), llm.CompletionRequest{})
					if err != nil || msg.Text() != "head" {
						t.Errorf("probe complete: msg=%q err=%v", msg.Text(), err)
					}
				}
			}()

			// Wait until the single probe is in flight.
			<-probeStarted

			// Launch remaining concurrent callers; all must skip head and hit backup immediately.
			var othersWG sync.WaitGroup
			for range total - 1 {
				othersWG.Add(1)
				go func() {
					defer othersWG.Done()
					if mode == "stream" {
						txt, err := drain(p.Stream(context.Background(), llm.CompletionRequest{}))
						if err != nil || txt != "backup" {
							t.Errorf("concurrent stream: txt=%q err=%v", txt, err)
						}
					} else {
						msg, _, _, err := p.Complete(context.Background(), llm.CompletionRequest{})
						if err != nil || msg.Text() != "backup" {
							t.Errorf("concurrent complete: msg=%q err=%v", msg.Text(), err)
						}
					}
				}()
			}
			othersWG.Wait()

			if got := headCalls.Load(); got != 1 {
				t.Fatalf("head received %d concurrent probes, want exactly 1", got)
			}
			if got := backupCalls.Load(); got != total-1 {
				t.Fatalf("backup calls=%d, want %d", got, total-1)
			}

			// Release the probe; it succeeds and fully closes the breaker.
			close(releaseProbe)
			wg.Wait()

			if reg.Get(1) != (State{}) {
				t.Fatalf("head breaker should be clean after probe success, got %+v", reg.Get(1))
			}
		})
	}
}

// Verifies that when ALL breakers in the pool are open, at most ONE concurrent
// goroutine probes the head while all other concurrent callers fail fast with
// ErrExhausted rather than hammering members[:1].
func TestPoolAllOpenSingleFlightHeadProbe(t *testing.T) {
	for _, mode := range []string{"stream", "complete"} {
		t.Run(mode, func(t *testing.T) {
			var headCalls atomic.Int32
			probeStarted := make(chan struct{})
			releaseProbe := make(chan struct{})

			headProv := callbackProvider{
				stream: func(ctx context.Context, _ llm.CompletionRequest) iter.Seq2[llm.StreamEvent, error] {
					return func(yield func(llm.StreamEvent, error) bool) {
						if headCalls.Add(1) == 1 {
							close(probeStarted)
							<-releaseProbe
						}
						yield(llm.StreamEvent{Type: llm.SETextDelta, Text: "recovered"}, nil)
						yield(llm.StreamEvent{Type: llm.SEMessageStop}, nil)
					}
				},
				complete: func(ctx context.Context, _ llm.CompletionRequest) (llm.Message, string, llm.Usage, error) {
					if headCalls.Add(1) == 1 {
						close(probeStarted)
						<-releaseProbe
					}
					return llm.Message{Role: llm.RoleAssistant, Content: []llm.ContentBlock{llm.TextBlock("recovered")}}, "end_turn", llm.Usage{}, nil
				},
			}
			backupProv := failProv("backup", 402)

			reg := NewRegistry(nil, nil)
			reg.Trip(1, "402", true)
			reg.Trip(2, "402", true)
			p := New([]*Member{member(1, "head", RankActive, headProv), member(2, "backup", 5, backupProv)}, reg)

			var probeWG sync.WaitGroup
			probeWG.Add(1)
			go func() {
				defer probeWG.Done()
				if mode == "stream" {
					txt, err := drain(p.Stream(context.Background(), llm.CompletionRequest{}))
					if err != nil || txt != "recovered" {
						t.Errorf("last-resort probe stream: txt=%q err=%v", txt, err)
					}
				} else {
					msg, _, _, err := p.Complete(context.Background(), llm.CompletionRequest{})
					if err != nil || msg.Text() != "recovered" {
						t.Errorf("last-resort probe complete: msg=%q err=%v", msg.Text(), err)
					}
				}
			}()

			<-probeStarted

			const herd = 19
			var fastFail atomic.Int32
			var herdWG sync.WaitGroup
			for range herd {
				herdWG.Add(1)
				go func() {
					defer herdWG.Done()
					var err error
					if mode == "stream" {
						_, err = drain(p.Stream(context.Background(), llm.CompletionRequest{}))
					} else {
						_, _, _, err = p.Complete(context.Background(), llm.CompletionRequest{})
					}
					if errors.Is(err, ErrExhausted) {
						fastFail.Add(1)
					} else {
						t.Errorf("expected ErrExhausted fast-fail, got %v", err)
					}
				}()
			}
			herdWG.Wait()

			if headCalls.Load() != 1 {
				t.Fatalf("all-open herd hammered head %d times, want exactly 1", headCalls.Load())
			}
			if fastFail.Load() != herd {
				t.Fatalf("fast-failed=%d, want %d", fastFail.Load(), herd)
			}

			close(releaseProbe)
			probeWG.Wait()
		})
	}
}

// Verifies that cancelling a half-open probe releases the probe lease without
// resetting failure state, and that a failed transient probe re-opens the
// breaker and fails over to the backup.
func TestPoolHalfOpenProbeCancelAndFailure(t *testing.T) {
	t.Run("cancelled probe releases lease", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		started := make(chan struct{})
		headProv := callbackProvider{
			stream: func(ctx context.Context, _ llm.CompletionRequest) iter.Seq2[llm.StreamEvent, error] {
				return func(yield func(llm.StreamEvent, error) bool) {
					close(started)
					<-ctx.Done()
					yield(llm.StreamEvent{}, ctx.Err())
				}
			},
		}
		backup := okProv("backup", "b")
		reg := NewRegistry(nil, nil)
		reg.Restore(1, State{Trips: 1, OpenUntil: time.Now().Add(-time.Second)})
		p := New([]*Member{member(1, "head", RankActive, headProv), member(2, "backup", 5, backup)}, reg)

		done := make(chan error, 1)
		go func() {
			_, err := drain(p.Stream(ctx, llm.CompletionRequest{}))
			done <- err
		}()
		<-started
		cancel()
		if err := <-done; !errors.Is(err, context.Canceled) {
			t.Fatalf("err=%v, want context.Canceled", err)
		}
		// State still has Trips=1 (not reset), and lease is released so next AllowProbe succeeds.
		if reg.Get(1).Trips != 1 {
			t.Fatalf("cancelled probe modified state: %+v", reg.Get(1))
		}
		if !reg.AllowProbe(1) {
			t.Fatal("probe lease was not released after cancellation")
		}
	})

	t.Run("failed transient probe re-opens breaker and fails over", func(t *testing.T) {
		head := failProv("head", 503)
		backup := okProv("backup", "backup-ok")
		reg := NewRegistry(nil, nil)
		reg.Restore(1, State{Trips: 1, OpenUntil: time.Now().Add(-time.Second)})
		p := New([]*Member{member(1, "head", RankActive, head), member(2, "backup", 5, backup)}, reg)

		got, err := drain(p.Stream(context.Background(), llm.CompletionRequest{}))
		if err != nil || got != "backup-ok" {
			t.Fatalf("got=%q err=%v, want backup-ok / nil", got, err)
		}
		if !reg.IsOpen(1) || reg.Get(1).Trips != 2 {
			t.Fatalf("failed half-open probe should immediately re-open breaker: %+v", reg.Get(1))
		}
	})
}

// Verifies Complete does NOT mark a half-open member healthy (Pass) when it
// returns *llm.IncompleteResponseError — only releases the probe lease, matching Stream.
func TestPoolCompleteIncompleteResponseDoesNotCallPass(t *testing.T) {
	incErr := &llm.IncompleteResponseError{Reason: llm.IncompleteEmptyOutput}
	headProv := callbackProvider{
		complete: func(context.Context, llm.CompletionRequest) (llm.Message, string, llm.Usage, error) {
			return llm.Message{}, "end_turn", llm.Usage{}, incErr
		},
	}
	reg := NewRegistry(nil, nil)
	reg.Restore(1, State{Trips: 2, OpenUntil: time.Now().Add(-time.Second)})
	p := New([]*Member{member(1, "head", RankActive, headProv)}, reg)

	_, _, _, err := p.Complete(context.Background(), llm.CompletionRequest{})
	if !errors.Is(err, incErr) {
		t.Fatalf("err=%v, want IncompleteResponseError", err)
	}
	// Failure counter / trip state must remain untouched (NOT cleared by Pass).
	if got := reg.Get(1).Trips; got != 2 {
		t.Fatalf("Complete cleared breaker Trips on IncompleteResponseError: got %d, want 2", got)
	}
	// Probe lease must be released so a subsequent probe is admitted.
	if tok, ok := reg.TryAcquireProbe(1); !ok || tok == 0 {
		t.Fatalf("probe lease not released after IncompleteResponseError: (%d, %v)", tok, ok)
	}
}

// Verifies last-resort fallback prefers candidates[0] (whose context window fits
// the request) over p.members[0] (whose window is too small) when all members
// are tripped.
func TestPoolLastResortPrefersWindowFittingCandidate(t *testing.T) {
	for _, mode := range []string{"stream", "complete"} {
		t.Run(mode, func(t *testing.T) {
			small := okProv("small", "small-should-not-run")
			big := okProv("big", "big-fits")
			mSmall := member(1, "small", RankActive, small)
			mSmall.WindowTokens = 100
			mBig := member(2, "big", 5, big)
			mBig.WindowTokens = 1_000_000

			reg := NewRegistry(nil, nil)
			reg.Trip(1, "402", true)
			reg.Trip(2, "402", true)
			p := New([]*Member{mSmall, mBig}, reg)

			req := llm.CompletionRequest{Messages: []llm.Message{llm.UserText(strings.Repeat("x", 10_000))}}
			var got string
			var err error
			if mode == "stream" {
				got, err = drain(p.Stream(context.Background(), req))
			} else {
				var msg llm.Message
				msg, _, _, err = p.Complete(context.Background(), req)
				got = msg.Text()
			}
			if err != nil || got != "big-fits" {
				t.Fatalf("got=%q err=%v, want big-fits / nil", got, err)
			}
			if small.calls != 0 || big.calls != 1 {
				t.Fatalf("calls: small=%d big=%d, want 0/1", small.calls, big.calls)
			}
		})
	}
}

func TestTrimErrUTF8Safe(t *testing.T) {
	raw := strings.Repeat("a", 299) + "中文错误信息"
	got := trimErr(errors.New(raw))
	if !utf8.ValidString(got) {
		t.Fatalf("trimErr split UTF-8 rune: %q", got)
	}
	if !strings.HasSuffix(got, "…") {
		t.Fatalf("trimErr missing ellipsis: %q", got)
	}
}
