package agent

import (
	"context"
	"encoding/json"
	"errors"
	"iter"
	"sync/atomic"
	"testing"
	"time"

	"github.com/RC-CHN/ARTEX/db"
	"github.com/RC-CHN/ARTEX/norma/llm"
)

type blockingCompactionProvider struct {
	started   chan struct{}
	cancelled chan struct{}
	allowExit chan struct{}
	calls     atomic.Int64
	onCall    func(ctx context.Context) (llm.Message, string, llm.Usage, error)
}

func (p *blockingCompactionProvider) Complete(ctx context.Context, _ llm.CompletionRequest) (llm.Message, string, llm.Usage, error) {
	p.calls.Add(1)
	if p.onCall != nil {
		return p.onCall(ctx)
	}
	if p.started != nil {
		p.started <- struct{}{}
	}
	<-ctx.Done()
	if p.cancelled != nil {
		p.cancelled <- struct{}{}
	}
	if p.allowExit != nil {
		<-p.allowExit
	}
	return llm.Message{}, "", llm.Usage{}, ctx.Err()
}

func (p *blockingCompactionProvider) Stream(context.Context, llm.CompletionRequest) iter.Seq2[llm.StreamEvent, error] {
	return func(func(llm.StreamEvent, error) bool) {}
}

func testCompactionFixture() (*coldGraph, block, map[int64]*db.Node) {
	g := newColdGraph([]cgNode{
		{ID: 1, Kind: db.KindFact, State: "done"},
		{ID: 2, Kind: db.KindFact, State: "done"},
	}, []cgEdge{{From: 1, Rel: "yields", To: 2}})
	nodes := map[int64]*db.Node{
		1: {ID: 1, Kind: db.KindFact, State: "done", Payload: json.RawMessage(`{"summary":"fact 1"}`)},
		2: {ID: 2, Kind: db.KindFact, State: "done", Payload: json.RawMessage(`{"summary":"fact 2"}`)},
	}
	return g, block{Members: []int64{1, 2}}, nodes
}

func TestCompactorStopCancelsInflightCompress(t *testing.T) {
	prov := &blockingCompactionProvider{
		started:   make(chan struct{}, 2),
		cancelled: make(chan struct{}, 2),
	}
	c := NewCompactor(prov, "test-model")
	g, blk, nodes := testCompactionFixture()

	roundCtx, cancelRound := context.WithCancel(context.Background())
	done := make(chan error, 1)
	if !c.launchBackground(roundCtx, 42, func(bg context.Context) {
		_, err := c.compress(bg, g, blk, nodes)
		done <- err
	}) {
		t.Fatal("launchBackground returned false")
	}

	select {
	case <-prov.started:
	case <-time.After(time.Second):
		t.Fatal("background compress did not start")
	}

	// Ending the single planner round must NOT cancel background compaction.
	cancelRound()
	select {
	case <-prov.cancelled:
		t.Fatal("single planner round cancel prematurely aborted background compaction")
	case <-time.After(40 * time.Millisecond):
	}

	// Stopping the exploration must cancel the in-flight LLM call promptly.
	c.Stop(42)
	select {
	case <-prov.cancelled:
	case <-time.After(time.Second):
		t.Fatal("Compactor.Stop did not cancel in-flight compress")
	}
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("compress err = %v, want context.Canceled", err)
		}
	case <-time.After(time.Second):
		t.Fatal("background compaction goroutine did not exit")
	}

	c.Close()
	c.mu.Lock()
	runningLen, cancelsLen, lastRunLen := len(c.running), len(c.cancels), len(c.lastRun)
	c.mu.Unlock()
	if runningLen != 0 || cancelsLen != 0 || lastRunLen != 0 {
		t.Fatalf("compactor maps not cleaned up: running=%d cancels=%d lastRun=%d", runningLen, cancelsLen, lastRunLen)
	}
}

func TestCompactorCloseCancelsAndWaitsAllGoroutines(t *testing.T) {
	prov := &blockingCompactionProvider{
		started:   make(chan struct{}, 4),
		cancelled: make(chan struct{}, 4),
		allowExit: make(chan struct{}),
	}
	c := NewCompactor(prov, "test-model")
	g, blk, nodes := testCompactionFixture()

	for _, expID := range []int64{1, 2} {
		if !c.launchBackground(context.Background(), expID, func(bg context.Context) {
			_, _ = c.compress(bg, g, blk, nodes)
		}) {
			t.Fatalf("launchBackground(%d) returned false", expID)
		}
	}
	for range 2 {
		select {
		case <-prov.started:
		case <-time.After(time.Second):
			t.Fatal("compaction worker did not start")
		}
	}

	closeDone := make(chan struct{})
	go func() {
		c.Close()
		close(closeDone)
	}()

	// Both LLM calls must observe cancellation immediately.
	for range 2 {
		select {
		case <-prov.cancelled:
		case <-time.After(time.Second):
			t.Fatal("Close did not cancel all in-flight compactions")
		}
	}
	// Close must wait for goroutines to finish exiting (no leaked goroutines).
	select {
	case <-closeDone:
		t.Fatal("Close returned before background goroutines exited")
	case <-time.After(40 * time.Millisecond):
	}

	close(prov.allowExit)
	select {
	case <-closeDone:
	case <-time.After(time.Second):
		t.Fatal("Close did not finish after goroutines exited")
	}

	// Post-close launches must be rejected cleanly.
	if c.launchBackground(context.Background(), 3, func(context.Context) {
		t.Error("post-close goroutine should never execute")
	}) {
		t.Fatal("launchBackground succeeded after Close")
	}
}

func TestCompactorLifecycleAndBaseContextCancelBackground(t *testing.T) {
	t.Run("WithCompactionLifecycle", func(t *testing.T) {
		prov := &blockingCompactionProvider{
			started:   make(chan struct{}, 1),
			cancelled: make(chan struct{}, 1),
		}
		c := NewCompactor(prov, "test-model")
		defer c.Close()
		g, blk, nodes := testCompactionFixture()

		taskCtx, cancelTask := context.WithCancel(context.Background())
		roundCtx, cancelRound := context.WithCancel(context.Background())
		ctx := WithCompactionLifecycle(roundCtx, taskCtx)

		if !c.launchBackground(ctx, 10, func(bg context.Context) {
			_, _ = c.compress(bg, g, blk, nodes)
		}) {
			t.Fatal("launchBackground returned false")
		}
		<-prov.started
		cancelRound()
		select {
		case <-prov.cancelled:
			t.Fatal("round cancel should not abort lifecycle-bound compaction")
		case <-time.After(40 * time.Millisecond):
		}

		cancelTask()
		select {
		case <-prov.cancelled:
		case <-time.After(time.Second):
			t.Fatal("lifecycle context cancel did not abort compaction")
		}
	})

	t.Run("SetBaseContext", func(t *testing.T) {
		prov := &blockingCompactionProvider{
			started:   make(chan struct{}, 1),
			cancelled: make(chan struct{}, 1),
		}
		baseCtx, cancelBase := context.WithCancel(context.Background())
		c := NewCompactor(prov, "test-model")
		c.SetBaseContext(baseCtx)
		defer c.Close()
		g, blk, nodes := testCompactionFixture()

		if !c.launchBackground(context.Background(), 11, func(bg context.Context) {
			_, _ = c.compress(bg, g, blk, nodes)
		}) {
			t.Fatal("launchBackground returned false")
		}
		<-prov.started
		cancelBase()
		select {
		case <-prov.cancelled:
		case <-time.After(time.Second):
			t.Fatal("baseCtx cancel did not abort compaction")
		}
		if c.launchBackground(context.Background(), 12, func(context.Context) {
			t.Error("cancelled baseCtx must reject new compactions")
		}) {
			t.Fatal("launchBackground succeeded after baseCtx cancellation")
		}
	})
}

func TestCompactorFoldBlockSkipsOnCancellation(t *testing.T) {
	prov := &blockingCompactionProvider{}
	c := NewCompactor(prov, "test-model")
	g, blk, nodes := testCompactionFixture()

	cancelledCtx, cancel := context.WithCancel(context.Background())
	cancel()
	c.foldBlock(cancelledCtx, nil, g, blk, nodes, map[int64]int{}, 1)
	if prov.calls.Load() != 0 {
		t.Fatalf("foldBlock invoked provider %d times with cancelled context, want 0", prov.calls.Load())
	}

	// If ctx cancels during compress, foldBlock must skip fresh re-read and DB write.
	ctx2, cancel2 := context.WithCancel(context.Background())
	prov2 := &blockingCompactionProvider{
		onCall: func(context.Context) (llm.Message, string, llm.Usage, error) {
			cancel2()
			return llm.Message{Role: llm.RoleAssistant, Content: []llm.ContentBlock{llm.TextBlock("digest")}}, "end_turn", llm.Usage{}, nil
		},
	}
	c2 := NewCompactor(prov2, "test-model")
	// ts=nil would panic if foldBlock attempted loadColdStructure or AddDigest.
	c2.foldBlock(ctx2, nil, g, blk, nodes, map[int64]int{}, 1)
	if prov2.calls.Load() != 1 {
		t.Fatalf("expected 1 compress call, got %d", prov2.calls.Load())
	}
}
