package compaction

import (
	"context"
	"encoding/json"
	"fmt"
	"iter"
	"reflect"
	"strings"
	"testing"

	"github.com/RC-CHN/ARTEX/norma/llm"
)

// TestMicroHysteresisPreservesPrefixAcrossTurns verifies that once a MicroCompact
// sweep fires above microThreshold, subsequent turns do NOT slide and mutate one
// tool result per turn; the prefix stays byte-identical until tokens cross the
// next hysteresis high-water mark, when a full new batch is cleared at once.
func TestMicroHysteresisPreservesPrefixAcrossTurns(t *testing.T) {
	// eff = 192000, microThreshold = 115200, hysteresis = 19200.
	c := New(Config{ContextWindow: 200000, MaxOutputTokens: 8000}, nil)
	msgs := manyReadPairs(microKeepRecent + 3) // 8 Read pairs: r0..r7

	// Turn 1: cross microThreshold -> epoch 1 clears r0, r1, r2 (3 cleared).
	out1 := c.Pre(context.Background(), msgs, 120000)
	if got := countCleared(out1); got != 3 {
		t.Fatalf("epoch 1 cleared=%d, want 3", got)
	}
	snapshot := append([]llm.Message(nil), out1...)

	// Turns 2..11: add 10 more Read pairs with lastInputTokens still above
	// microThreshold (115200) but below the hysteresis target (~139k).
	// Previously cleared r0..r2 stay cleared, NO new IDs are cleared, and the
	// entire prior prefix remains byte-identical across every single turn.
	cur := out1
	for i := range 10 {
		cur = append(cur, toolPair("Read", fmt.Sprintf("extra_%d", i), strings.Repeat("z", 200))...)
		cur = c.Pre(context.Background(), cur, 121000+i*1000)
		if got := countCleared(cur); got != 3 {
			t.Fatalf("turn %d inside hysteresis band cleared=%d, want 3 (must not slide per turn)", i, got)
		}
		if !reflect.DeepEqual(cur[:len(snapshot)], snapshot) {
			t.Fatalf("turn %d mutated prior prefix during hysteresis cooldown", i)
		}
	}

	// Next turn crosses the hysteresis high-water trigger -> epoch 2 clears the
	// entire accumulated batch at once (18 total - 5 kept = 13 cleared).
	cur = append(cur, toolPair("Read", "trigger_next_epoch", strings.Repeat("z", 200))...)
	cur = c.Pre(context.Background(), cur, 145000)
	want := (microKeepRecent + 3 + 10 + 1) - microKeepRecent
	if got := countCleared(cur); got != want {
		t.Fatalf("epoch 2 cleared=%d, want %d (full batch sweep)", got, want)
	}
}

// TestMicroReappliesClearedIDsOnRawSlice verifies that previously cleared IDs
// are re-applied idempotently even if a caller passes a fresh raw copy (e.g.
// from transcript history) or if tokens temporarily dip below microThreshold.
func TestMicroReappliesClearedIDsOnRawSlice(t *testing.T) {
	c := New(Config{ContextWindow: 200000, MaxOutputTokens: 8000}, nil)
	raw := manyReadPairs(microKeepRecent + 2) // r0..r6

	// Trigger sweep: r0, r1 cleared.
	out1 := c.Pre(context.Background(), raw, 120000)
	if got := countCleared(out1); got != 2 {
		t.Fatalf("first sweep cleared=%d, want 2", got)
	}

	// Pass a raw (un-cleared) copy with a new pair and a low token count:
	// r0, r1 must STILL be re-applied as cleared, and r2 must NOT be cleared.
	freshCopy := append(manyReadPairs(microKeepRecent+2), toolPair("Read", "r_new", strings.Repeat("y", 200))...)
	out2 := c.Pre(context.Background(), freshCopy, 50000)
	if got := countCleared(out2); got != 2 {
		t.Fatalf("re-applied cleared=%d, want 2 (r0,r1 stayed cleared, r2 untouched)", got)
	}
	if !strings.Contains(resultText(out2[1].Content[0]), "cleared") ||
		!strings.Contains(resultText(out2[3].Content[0]), "cleared") {
		t.Fatal("r0 and r1 should remain cleared on re-application")
	}
	if strings.Contains(resultText(out2[5].Content[0]), "cleared") {
		t.Fatal("r2 should remain intact below next sweep trigger")
	}
}

// TestMicroEpochResetsAfterAutoCompact verifies that AutoCompact resets the
// micro-compaction epoch and leaves pre-boundary history untouched.
func TestMicroEpochResetsAfterAutoCompact(t *testing.T) {
	rs := &recSummarizer{reply: "DIGEST"}
	c := New(Config{ContextWindow: 100000, MaxOutputTokens: 4000, KeepRecent: 2}, rs.fn)

	msgs := manyReadPairs(microKeepRecent + 2)
	msgs = c.Pre(context.Background(), msgs, 60000) // triggers micro epoch 1
	if len(c.clearedIDs) == 0 || c.microNextTrigger == 0 {
		t.Fatalf("expected active micro epoch, got cleared=%d nextTrigger=%d", len(c.clearedIDs), c.microNextTrigger)
	}

	// Push over autoThreshold (83000) without triggering a second micro sweep first.
	msgs = c.Pre(context.Background(), msgs, 90000)
	if boundaryCount(msgs) != 1 {
		t.Fatalf("expected autoCompact boundary, got %d", boundaryCount(msgs))
	}
	if len(c.clearedIDs) != 0 || c.microNextTrigger != 0 {
		t.Fatalf("autoCompact should reset micro epoch, got cleared=%d nextTrigger=%d", len(c.clearedIDs), c.microNextTrigger)
	}
}

// TestCacheSafeForkedSummarizerForwardsParentPrefix verifies that when System,
// DynamicBoundary, Tools, and SystemReminder are provided on Config, AutoCompact
// forwards the exact parent prefix to ProviderSummarizer while keeping thinking
// disabled and instructing the model not to call tools.
func TestCacheSafeForkedSummarizerForwardsParentPrefix(t *testing.T) {
	p := &captureProvider{reply: "<analysis>thinking</analysis><summary>CACHED DIGEST</summary>"}
	parentSystem := []string{"static base instructions", "static tool guide", "<dynamic-time>now</dynamic-time>"}
	parentTools := []llm.ToolSchema{
		{Name: "Read", Description: "read file", InputSchema: map[string]any{"type": "object"}},
		{Name: "Bash", Description: "run shell", InputSchema: map[string]any{"type": "object"}},
	}
	reminder := "<system-reminder>\n# currentDate\nToday's date is 2026-11-24.\n</system-reminder>"

	cfg := Config{
		ContextWindow:   16000,
		MaxOutputTokens: 1000,
		KeepRecent:      2,
		System:          parentSystem,
		DynamicBoundary: 2,
		Tools:           parentTools,
		SystemReminder:  reminder,
	}
	c := New(cfg, ProviderSummarizer(p, 8000, false))

	msgs := []llm.Message{
		llm.UserText("first request"),
		asstText("first response"),
		llm.UserText("second request"),
		asstText("second response"),
		llm.UserText("tail 1"),
		asstText("tail 2"),
	}
	out, ok := c.autoCompact(context.Background(), msgs, 15000, "auto")
	if !ok {
		t.Fatal("autoCompact did not run")
	}
	if len(p.reqs) != 1 {
		t.Fatalf("provider calls=%d, want 1", len(p.reqs))
	}
	req := p.reqs[0]
	if !reflect.DeepEqual(req.System, parentSystem) {
		t.Fatalf("req.System=%v, want %v", req.System, parentSystem)
	}
	if req.DynamicBoundary != 2 {
		t.Fatalf("req.DynamicBoundary=%d, want 2", req.DynamicBoundary)
	}
	if !reflect.DeepEqual(req.Tools, parentTools) {
		t.Fatalf("req.Tools=%+v, want %+v", req.Tools, parentTools)
	}
	if req.Thinking != "disabled" {
		t.Fatalf("req.Thinking=%q, want disabled", req.Thinking)
	}
	// Messages = [SystemReminder, 4 summarized head msgs..., compactPrompt].
	if len(req.Messages) != 6 {
		t.Fatalf("len(req.Messages)=%d, want 6", len(req.Messages))
	}
	if req.Messages[0].Text() != reminder {
		t.Fatalf("req.Messages[0]=%q, want parent SystemReminder", req.Messages[0].Text())
	}
	if req.Messages[1].Text() != "first request" {
		t.Fatalf("req.Messages[1]=%q, want first request", req.Messages[1].Text())
	}
	if !strings.Contains(req.Messages[len(req.Messages)-1].Text(), "Do NOT call any tools") {
		t.Fatal("missing no-tools instruction in summary prompt")
	}
	if api := llm.MessagesForAPI(out); !strings.Contains(api[0].Text(), "CACHED DIGEST") {
		t.Fatalf("summary not recorded in API view: %q", api[0].Text())
	}
}

// TestCacheSafeForkedSummarizerPTLRetryDropsReminderKeepsPrefix verifies that on
// a PTL retry after head truncation, System/DynamicBoundary/Tools stay intact
// while the stale SystemReminder is not duplicated before ptlRetryMarker.
func TestCacheSafeForkedSummarizerPTLRetryDropsReminderKeepsPrefix(t *testing.T) {
	p := &captureProvider{reply: "<summary>RETRIED</summary>", failN: 1}
	parentSystem := []string{"static prompt"}
	parentTools := []llm.ToolSchema{{Name: "Read"}}
	ctx := WithSummaryPrefix(context.Background(), SummaryPrefix{
		System:          parentSystem,
		DynamicBoundary: 1,
		Tools:           parentTools,
		SystemReminder:  "<system-reminder>date</system-reminder>",
	})
	head := []llm.Message{llm.UserText("u0"), asstText("a1"), llm.UserText("u1"), asstText("a2")}
	got, err := ProviderSummarizer(p, 0, false)(ctx, head)
	if err != nil {
		t.Fatalf("summarizer failed: %v", err)
	}
	if got != "Summary:\nRETRIED" {
		t.Fatalf("got %q", got)
	}
	if len(p.reqs) != 2 {
		t.Fatalf("calls=%d, want 2", len(p.reqs))
	}
	// Attempt 1 includes reminder.
	if p.reqs[0].Messages[0].Text() != "<system-reminder>date</system-reminder>" {
		t.Fatalf("attempt 1 missing reminder: %q", p.reqs[0].Messages[0].Text())
	}
	// Attempt 2 (PTL-truncated) starts directly with ptlRetryMarker and keeps System+Tools.
	if p.reqs[1].Messages[0].Text() != ptlRetryMarker {
		t.Fatalf("attempt 2 first msg=%q, want ptlRetryMarker", p.reqs[1].Messages[0].Text())
	}
	if !reflect.DeepEqual(p.reqs[1].System, parentSystem) || !reflect.DeepEqual(p.reqs[1].Tools, parentTools) {
		t.Fatalf("attempt 2 lost System/Tools prefix: sys=%v tools=%v", p.reqs[1].System, p.reqs[1].Tools)
	}
}

type scriptedSummaryProvider struct {
	reqs    []llm.CompletionRequest
	replies []llm.Message
}

func (p *scriptedSummaryProvider) next(req llm.CompletionRequest) llm.Message {
	p.reqs = append(p.reqs, req)
	idx := len(p.reqs) - 1
	if idx >= len(p.replies) {
		idx = len(p.replies) - 1
	}
	return p.replies[idx]
}

func (p *scriptedSummaryProvider) Complete(_ context.Context, req llm.CompletionRequest) (llm.Message, string, llm.Usage, error) {
	return p.next(req), "end_turn", llm.Usage{}, nil
}

func (p *scriptedSummaryProvider) Stream(_ context.Context, req llm.CompletionRequest) iter.Seq2[llm.StreamEvent, error] {
	msg := p.next(req)
	return func(yield func(llm.StreamEvent, error) bool) {
		for _, b := range msg.Content {
			switch b.Type {
			case llm.BlockText:
				if !yield(llm.StreamEvent{Type: llm.SETextDelta, Text: b.Text}, nil) {
					return
				}
			case llm.BlockToolUse:
				if !yield(llm.StreamEvent{Type: llm.SEToolUseStart, ToolID: b.ID, ToolName: b.Name}, nil) {
					return
				}
				if len(b.Input) > 0 {
					if !yield(llm.StreamEvent{Type: llm.SEToolInputJSON, ToolID: b.ID, Text: string(b.Input)}, nil) {
						return
					}
				}
			}
		}
		yield(llm.StreamEvent{Type: llm.SEMessageStop}, nil)
	}
}

// TestCacheSafeForkedSummarizerRejectsToolUseAndBlankSummary verifies that if a
// cache-safe forked summary call (with parent Tools attached) responds with a
// tool_use block, blank text, or analysis-only text, ProviderSummarizer retries
// once with Tools=nil and the standalone summary system prompt, and fails cleanly
// (never replacing history with a blank summary) if the fallback is also invalid.
func TestCacheSafeForkedSummarizerRejectsToolUseAndBlankSummary(t *testing.T) {
	parentTools := []llm.ToolSchema{{Name: "Read", Description: "read", InputSchema: map[string]any{"type": "object"}}}
	parentSystem := []string{"parent static system"}
	head := []llm.Message{llm.UserText("u1"), asstText("a1"), llm.UserText("u2"), asstText("a2")}

	toolOnlyMsg := llm.Message{
		Role: llm.RoleAssistant,
		Content: []llm.ContentBlock{{
			Type:  llm.BlockToolUse,
			ID:    "call_1",
			Name:  "Read",
			Input: json.RawMessage(`{"file_path":"a.go"}`),
		}},
	}
	analysisOnlyMsg := asstText("<analysis>private thoughts only</analysis>")
	emptySummaryTagMsg := asstText("<analysis>thoughts</analysis><summary>   </summary>")
	validSummaryMsg := asstText("<analysis>ok</analysis><summary>CLEAN FALLBACK DIGEST</summary>")

	for _, nonStreaming := range []bool{false, true} {
		mode := "stream"
		if nonStreaming {
			mode = "non-stream"
		}
		for _, tc := range []struct {
			name    string
			first   llm.Message
			second  llm.Message
			wantOK  bool
			wantSub string
		}{
			{"tool_use_recovers_on_standalone_retry", toolOnlyMsg, validSummaryMsg, true, "CLEAN FALLBACK DIGEST"},
			{"analysis_only_recovers_on_standalone_retry", analysisOnlyMsg, validSummaryMsg, true, "CLEAN FALLBACK DIGEST"},
			{"empty_summary_tag_recovers_on_standalone_retry", emptySummaryTagMsg, validSummaryMsg, true, "CLEAN FALLBACK DIGEST"},
			{"persistent_tool_use_fails_without_blanking_history", toolOnlyMsg, toolOnlyMsg, false, ""},
			{"persistent_blank_fails_without_blanking_history", asstText("   "), asstText(""), false, ""},
		} {
			t.Run(mode+"/"+tc.name, func(t *testing.T) {
				p := &scriptedSummaryProvider{replies: []llm.Message{tc.first, tc.second}}
				cfg := Config{
					ContextWindow:   16000,
					MaxOutputTokens: 1000,
					KeepRecent:      2,
					System:          parentSystem,
					DynamicBoundary: 1,
					Tools:           parentTools,
					SystemReminder:  "<system-reminder>today</system-reminder>",
				}
				c := New(cfg, ProviderSummarizer(p, 8000, nonStreaming))
				msgs := append(append([]llm.Message(nil), head...), llm.UserText("tail1"), asstText("tail2"))

				out, ok := c.autoCompact(context.Background(), msgs, 15000, "auto")
				if ok != tc.wantOK {
					t.Fatalf("autoCompact ok=%v, want %v", ok, tc.wantOK)
				}
				if len(p.reqs) != 2 {
					t.Fatalf("provider calls=%d, want 2 (forked + standalone retry)", len(p.reqs))
				}
				if len(p.reqs[0].Tools) != 1 || !reflect.DeepEqual(p.reqs[0].System, parentSystem) {
					t.Fatalf("attempt 1 should use parent prefix: sys=%v tools=%v", p.reqs[0].System, p.reqs[0].Tools)
				}
				if len(p.reqs[1].Tools) != 0 || !reflect.DeepEqual(p.reqs[1].System, []string{summarySystemPrompt}) || p.reqs[1].DynamicBoundary != 0 {
					t.Fatalf("attempt 2 must retry standalone with Tools=nil: sys=%v boundary=%d tools=%v",
						p.reqs[1].System, p.reqs[1].DynamicBoundary, p.reqs[1].Tools)
				}
				if tc.wantOK {
					api := llm.MessagesForAPI(out)
					if !strings.Contains(api[0].Text(), tc.wantSub) {
						t.Fatalf("summary=%q missing %q", api[0].Text(), tc.wantSub)
					}
				} else {
					if boundaryCount(out) != 0 || !reflect.DeepEqual(out, msgs) {
						t.Fatalf("failed summary must leave history untouched, got boundaries=%d", boundaryCount(out))
					}
				}
			})
		}
	}

	// Standalone call (no parent tools) must fail immediately on blank summary without burning a retry.
	t.Run("standalone_blank_fails_without_retry", func(t *testing.T) {
		p := &scriptedSummaryProvider{replies: []llm.Message{asstText("   ")}}
		_, err := ProviderSummarizer(p, 8000, false)(context.Background(), head)
		if err == nil {
			t.Fatal("expected error for blank standalone summary")
		}
		if len(p.reqs) != 1 {
			t.Fatalf("standalone blank summary calls=%d, want 1", len(p.reqs))
		}
	})
}
