package agentcore

import (
	"context"
	"encoding/json"
	"iter"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/RC-CHN/ARTEX/norma/compaction"
	"github.com/RC-CHN/ARTEX/norma/harness"
	"github.com/RC-CHN/ARTEX/norma/llm"
	"github.com/RC-CHN/ARTEX/norma/permission"
	"github.com/RC-CHN/ARTEX/norma/tool"
	"github.com/RC-CHN/ARTEX/norma/transcript"
)

type spyProvider struct {
	ctxs []context.Context
	reqs []llm.CompletionRequest
	fn   func(call int, req llm.CompletionRequest) (string, llm.Usage)
}

func (p *spyProvider) Stream(ctx context.Context, req llm.CompletionRequest) iter.Seq2[llm.StreamEvent, error] {
	p.ctxs = append(p.ctxs, ctx)
	p.reqs = append(p.reqs, req)
	call := len(p.reqs)
	text, usage := "ok", llm.Usage{InputTokens: 10, OutputTokens: 5}
	if p.fn != nil {
		text, usage = p.fn(call, req)
	}
	return func(yield func(llm.StreamEvent, error) bool) {
		if !yield(llm.StreamEvent{Type: llm.SETextDelta, Text: text}, nil) {
			return
		}
		if !yield(llm.StreamEvent{Type: llm.SEMessageDelta, StopReason: "end_turn", Usage: usage}, nil) {
			return
		}
		yield(llm.StreamEvent{Type: llm.SEMessageStop}, nil)
	}
}

func (p *spyProvider) Complete(ctx context.Context, req llm.CompletionRequest) (llm.Message, string, llm.Usage, error) {
	acc := llm.NewAccumulator()
	for ev, err := range p.Stream(ctx, req) {
		if err != nil {
			return llm.Message{}, "", llm.Usage{}, err
		}
		acc.Add(ev)
	}
	return acc.Message(), acc.StopReason, acc.Usage, nil
}

func TestSessionDateFrozenAcrossPromptsAndResume(t *testing.T) {
	p := &spyProvider{}
	s := NewSession(Options{
		Provider:               p,
		SystemPrompt:           []string{"base"},
		Tools:                  []tool.CoreTool{},
		DisableBackgroundTasks: true,
	})
	// Simulate a session created on a fixed earlier date (e.g. before midnight).
	s.sessionDate = "2026-01-10"

	drainPrompt(t, s, "first turn")
	drainPrompt(t, s, "second turn")

	if len(p.reqs) != 2 {
		t.Fatalf("calls=%d, want 2", len(p.reqs))
	}
	r0 := p.reqs[0].Messages[0].Text()
	r1 := p.reqs[1].Messages[0].Text()
	if !strings.Contains(r0, "Today's date is 2026-01-10.") {
		t.Fatalf("turn 1 reminder=%q, want frozen date 2026-01-10", r0)
	}
	if r0 != r1 {
		t.Fatalf("reminder mutated between turns:\n  1: %q\n  2: %q", r0, r1)
	}

	// Resume from a transcript whose first record carries a historical timestamp.
	store := transcript.NewStore(t.TempDir())
	sid := "historical-session"
	histTS := time.Date(2025, 7, 4, 12, 0, 0, 0, time.Local).UTC().Format(time.RFC3339Nano)
	u := llm.UserText("old prompt")
	if err := store.Append(store.MainPath(sid), transcript.Record{
		UUID:      "u1",
		SessionID: sid,
		Timestamp: histTS,
		Type:      "message",
		Message:   &u,
	}); err != nil {
		t.Fatalf("append transcript: %v", err)
	}

	p2 := &spyProvider{}
	resumed := NewSession(Options{
		Provider:               p2,
		SystemPrompt:           []string{"base"},
		Tools:                  []tool.CoreTool{},
		Transcript:             store,
		DisableBackgroundTasks: true,
	})
	if err := resumed.Resume(sid); err != nil {
		t.Fatalf("Resume: %v", err)
	}
	drainPrompt(t, resumed, "follow up")
	if len(p2.reqs) != 1 {
		t.Fatalf("resumed calls=%d, want 1", len(p2.reqs))
	}
	gotReminder := p2.reqs[0].Messages[0].Text()
	if !strings.Contains(gotReminder, "Today's date is 2025-07-04.") {
		t.Fatalf("resumed reminder=%q, want original session date 2025-07-04", gotReminder)
	}
}

func TestPromptAttachesPromptCacheKey(t *testing.T) {
	t.Run("explicit SessionID", func(t *testing.T) {
		p := &spyProvider{}
		s := NewSession(Options{
			Provider:               p,
			SessionID:              "sess-sticky-42",
			Tools:                  []tool.CoreTool{},
			DisableBackgroundTasks: true,
		})
		drainPrompt(t, s, "hello")
		if got := llm.PromptCacheKeyFrom(p.ctxs[0]); got != "sess-sticky-42" {
			t.Fatalf("PromptCacheKeyFrom(ctx)=%q, want sess-sticky-42", got)
		}
	})

	t.Run("generated SessionID stays sticky", func(t *testing.T) {
		p := &spyProvider{}
		s := NewSession(Options{
			Provider:               p,
			Tools:                  []tool.CoreTool{},
			DisableBackgroundTasks: true,
		})
		drainPrompt(t, s, "turn 1")
		drainPrompt(t, s, "turn 2")
		k1 := llm.PromptCacheKeyFrom(p.ctxs[0])
		k2 := llm.PromptCacheKeyFrom(p.ctxs[1])
		if k1 == "" || k1 != s.SessionID() || k1 != k2 {
			t.Fatalf("cache keys=%q,%q sessionID=%q, want stable non-empty match", k1, k2, s.SessionID())
		}
	})

	t.Run("caller supplied key preserved", func(t *testing.T) {
		p := &spyProvider{}
		s := NewSession(Options{
			Provider:               p,
			SessionID:              "sess-ignored",
			Tools:                  []tool.CoreTool{},
			DisableBackgroundTasks: true,
		})
		ctx := llm.WithPromptCacheKey(context.Background(), "caller-key")
		for _, err := range s.Prompt(ctx, "hi") {
			if err != nil {
				t.Fatal(err)
			}
		}
		if got := llm.PromptCacheKeyFrom(p.ctxs[0]); got != "caller-key" {
			t.Fatalf("PromptCacheKeyFrom(ctx)=%q, want caller-key", got)
		}
	})
}

func TestCompactorReceivesParentPrefixForCacheSafeSummary(t *testing.T) {
	visible := tool.Build(tool.Spec{
		Name:   "VisibleTool",
		Schema: map[string]any{"type": "object"},
		Run:    func(context.Context, json.RawMessage, *tool.ToolContext) (tool.Result, error) { return tool.Text("ok"), nil },
	})
	deferred := tool.Build(tool.Spec{
		Name:   "HiddenDeferred",
		Schema: map[string]any{"type": "object"},
		Run:    func(context.Context, json.RawMessage, *tool.ToolContext) (tool.Result, error) { return tool.Text("ok"), nil },
	})

	p := &spyProvider{
		fn: func(call int, req llm.CompletionRequest) (string, llm.Usage) {
			if req.Thinking == "disabled" {
				return "<summary>COMPACTED</summary>", llm.Usage{InputTokens: 100, OutputTokens: 20}
			}
			return "reply", llm.Usage{InputTokens: 500, OutputTokens: 50}
		},
	}

	s := NewSession(Options{
		Provider:               p,
		SystemPrompt:           []string{"static-1", "static-2", "<dynamic-time>t</dynamic-time>"},
		DynamicBoundary:        2,
		Tools:                  []tool.CoreTool{visible, deferred},
		DeferredTools:          []string{"HiddenDeferred"},
		PermissionMode:         permission.ModeBypass,
		DisableBackgroundTasks: true,
		Compaction:             &compaction.Config{ContextWindow: 16000, MaxOutputTokens: 1000, KeepRecent: 2},
	})
	// Seed enough history so the next Prompt crosses autoThreshold via estimation
	// (eff=15000, autoThreshold=2000; 6 large turns >> 2000 tokens).
	big := strings.Repeat("a", 8000)
	s.messages = []llm.Message{
		llm.UserText(big),
		{Role: llm.RoleAssistant, Content: []llm.ContentBlock{llm.TextBlock(big)}},
		llm.UserText(big),
		{Role: llm.RoleAssistant, Content: []llm.ContentBlock{llm.TextBlock(big)}},
	}

	for ev, err := range s.Prompt(context.Background(), "trigger compaction") {
		if err != nil {
			t.Fatalf("Prompt: %v", err)
		}
		if ev.Kind == harness.KindResult && ev.Terminal != nil && ev.Terminal.Err != nil {
			t.Fatalf("terminal err: %v", ev.Terminal.Err)
		}
	}

	if len(p.reqs) != 2 {
		t.Fatalf("provider calls=%d, want 2 (summary + main turn)", len(p.reqs))
	}
	sumReq := p.reqs[0]
	mainReq := p.reqs[1]
	if sumReq.Thinking != "disabled" {
		t.Fatalf("first request should be the summary call with Thinking=disabled, got %q", sumReq.Thinking)
	}
	if !reflect.DeepEqual(sumReq.System, mainReq.System) {
		t.Fatalf("summary System differs from parent:\nsum:  %v\nmain: %v", sumReq.System, mainReq.System)
	}
	if sumReq.DynamicBoundary != mainReq.DynamicBoundary || sumReq.DynamicBoundary != 2 {
		t.Fatalf("summary DynamicBoundary=%d, main=%d, want 2", sumReq.DynamicBoundary, mainReq.DynamicBoundary)
	}
	if !reflect.DeepEqual(sumReq.Tools, mainReq.Tools) {
		t.Fatalf("summary Tools differ from parent:\nsum:  %+v\nmain: %+v", sumReq.Tools, mainReq.Tools)
	}
	if sumReq.Messages[0].Text() != mainReq.Messages[0].Text() {
		t.Fatalf("summary leading reminder differs from parent:\nsum:  %q\nmain: %q", sumReq.Messages[0].Text(), mainReq.Messages[0].Text())
	}
	// Verify deferred tool was filtered out of both summary and main tool lists.
	for _, ts := range sumReq.Tools {
		if ts.Name == "HiddenDeferred" {
			t.Fatal("deferred tool leaked into summary Tools")
		}
	}
}
