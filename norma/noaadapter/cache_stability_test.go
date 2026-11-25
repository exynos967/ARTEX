package noaadapter

import (
	"fmt"
	"strings"
	"testing"

	"github.com/RC-CHN/ARTEX/norma/agentcore"
	"github.com/RC-CHN/ARTEX/norma/llm"
	"github.com/RC-CHN/ARTEX/norma/noa"
	"github.com/RC-CHN/ARTEX/norma/tool"
)

// TestEnablePreservesDynamicBoundaryForDynamicTime verifies that Enable splices
// noa's static prompt AT opts.DynamicBoundary rather than overwriting it past
// post-boundary dynamic segments such as <artex-dynamic-time>.
func TestEnablePreservesDynamicBoundaryForDynamicTime(t *testing.T) {
	const dynamicTime = "<artex-dynamic-time>2026-11-24T14:20:00Z</artex-dynamic-time>"

	t.Run("dynamic segment inside SystemPrompt", func(t *testing.T) {
		opts := agentcore.Options{
			SystemPrompt:    []string{"static-role", "static-rules", dynamicTime},
			DynamicBoundary: 2,
			Tools:           []tool.CoreTool{},
		}
		if err := Enable(&opts, Options{ArchiveBaseDir: t.TempDir(), SessionID: "s1"}); err != nil {
			t.Fatalf("Enable: %v", err)
		}

		// Combine exactly the way agentcore.Session.system() does.
		combined := append(append([]string(nil), opts.SystemPrompt...), opts.AppendSystemPrompt...)
		if opts.DynamicBoundary != 3 {
			t.Fatalf("DynamicBoundary=%d, want 3 (2 original static + 1 noa static)", opts.DynamicBoundary)
		}
		staticPart := strings.Join(combined[:opts.DynamicBoundary], "\n")
		dynamicPart := strings.Join(combined[opts.DynamicBoundary:], "\n")

		if !strings.Contains(staticPart, noa.SystemPromptHeader) {
			t.Fatal("noa static prompt must be inside System[:DynamicBoundary]")
		}
		if strings.Contains(staticPart, dynamicTime) {
			t.Fatalf("<artex-dynamic-time> was pulled inside DynamicBoundary! static=%q", staticPart)
		}
		if !strings.Contains(dynamicPart, dynamicTime) {
			t.Fatalf("<artex-dynamic-time> missing after DynamicBoundary! dynamic=%q", dynamicPart)
		}
	})

	t.Run("dynamic segment inside AppendSystemPrompt with explicit boundary", func(t *testing.T) {
		opts := agentcore.Options{
			SystemPrompt:       []string{"static-role"},
			AppendSystemPrompt: []string{dynamicTime},
			DynamicBoundary:    1,
			Tools:              []tool.CoreTool{},
		}
		if err := Enable(&opts, Options{ArchiveBaseDir: t.TempDir(), SessionID: "s2"}); err != nil {
			t.Fatalf("Enable: %v", err)
		}

		combined := append(append([]string(nil), opts.SystemPrompt...), opts.AppendSystemPrompt...)
		if opts.DynamicBoundary != 2 {
			t.Fatalf("DynamicBoundary=%d, want 2", opts.DynamicBoundary)
		}
		staticPart := strings.Join(combined[:opts.DynamicBoundary], "\n")
		dynamicPart := strings.Join(combined[opts.DynamicBoundary:], "\n")
		if !strings.Contains(staticPart, noa.SystemPromptHeader) {
			t.Fatal("noa static prompt must be inside static prefix")
		}
		if strings.Contains(staticPart, dynamicTime) || !strings.Contains(dynamicPart, dynamicTime) {
			t.Fatalf("<artex-dynamic-time> must stay strictly after DynamicBoundary: static=%q dynamic=%q", staticPart, dynamicPart)
		}
	})

	t.Run("static segment inside AppendSystemPrompt with zero boundary stays cached", func(t *testing.T) {
		const staticAppend = "static-host-append-guide"
		opts := agentcore.Options{
			SystemPrompt:       []string{"static-role"},
			AppendSystemPrompt: []string{staticAppend},
			DynamicBoundary:    0,
			Tools:              []tool.CoreTool{},
		}
		if err := Enable(&opts, Options{ArchiveBaseDir: t.TempDir(), SessionID: "s3"}); err != nil {
			t.Fatalf("Enable: %v", err)
		}

		combined := append(append([]string(nil), opts.SystemPrompt...), opts.AppendSystemPrompt...)
		if opts.DynamicBoundary != 3 {
			t.Fatalf("DynamicBoundary=%d, want 3 (all static segments covered)", opts.DynamicBoundary)
		}
		staticPart := strings.Join(combined[:opts.DynamicBoundary], "\n")
		if !strings.Contains(staticPart, staticAppend) {
			t.Fatalf("pre-existing static AppendSystemPrompt was pushed past DynamicBoundary: static=%q", staticPart)
		}
		if !strings.Contains(staticPart, noa.SystemPromptHeader) {
			t.Fatal("noa static prompt must be inside static prefix")
		}
	})

	t.Run("explicit boundary inside AppendSystemPrompt splits static and dynamic cleanly", func(t *testing.T) {
		const staticAppend = "static-host-append"
		opts := agentcore.Options{
			SystemPrompt:       []string{"static-role"},
			AppendSystemPrompt: []string{staticAppend, dynamicTime},
			DynamicBoundary:    2,
			Tools:              []tool.CoreTool{},
		}
		if err := Enable(&opts, Options{ArchiveBaseDir: t.TempDir(), SessionID: "s4"}); err != nil {
			t.Fatalf("Enable: %v", err)
		}

		combined := append(append([]string(nil), opts.SystemPrompt...), opts.AppendSystemPrompt...)
		if opts.DynamicBoundary != 3 {
			t.Fatalf("DynamicBoundary=%d, want 3", opts.DynamicBoundary)
		}
		staticPart := strings.Join(combined[:opts.DynamicBoundary], "\n")
		dynamicPart := strings.Join(combined[opts.DynamicBoundary:], "\n")
		if !strings.Contains(staticPart, staticAppend) || !strings.Contains(staticPart, noa.SystemPromptHeader) {
			t.Fatalf("static prefix missing staticAppend or noa prompt: %q", staticPart)
		}
		if strings.Contains(staticPart, dynamicTime) || !strings.Contains(dynamicPart, dynamicTime) {
			t.Fatalf("dynamic segment misplaced: static=%q dynamic=%q", staticPart, dynamicPart)
		}
	})
}

// TestCompactorStickyTruncationPreventsTurnByTurnFlipFlop verifies that once
// Compactor.View truncates early tool outputs at >= 95%, subsequent turns stay
// byte-identical on the earlier prefix (re-applying the same truncations and
// not truncating newer outputs) until effective usage crosses 95% again.
func TestCompactorStickyTruncationPreventsTurnByTurnFlipFlop(t *testing.T) {
	const window = 100_000 // threshold=95K, target=75K
	sess := simSession(t, window)
	c := &Compactor{sess: sess}

	var msgs []llm.Message
	msgs = append(msgs, userText("Investigate the repository."))
	// 4 large early tool results (~25K tokens each -> 100K total > 95K threshold).
	for i := range 4 {
		id := fmt.Sprintf("early_%d", i)
		msgs = append(msgs,
			assistantWith(toolUse(id, "Bash", `{"command":"cat log"}`)),
			toolResult(id, fmt.Sprintf("early-%d ", i)+strings.Repeat("A", 100_000)),
		)
	}
	// Protected tail (5+ messages) so the 4 early tool results are eligible.
	for i := range 4 {
		id := fmt.Sprintf("tail_%d", i)
		msgs = append(msgs,
			assistantWith(toolUse(id, "Bash", `{"command":"echo ok"}`)),
			toolResult(id, fmt.Sprintf("small tail %d", i)),
		)
	}

	// Turn 1: exceeds 95K -> batch truncates down to <= 75K.
	view1 := c.View(t.Context(), msgs)
	sent1 := estimateMessages(view1)
	if sent1 > 75_000+5_000 { // allow small ref-tag / nudge overhead
		t.Fatalf("turn 1 sent=%d, expected batch truncation down near 75%% (75000)", sent1)
	}
	trunc1 := truncatedToolIDs(view1)
	if len(trunc1) == 0 {
		t.Fatal("turn 1 did not truncate any tool outputs at >95% usage")
	}

	// Repeat View without Pre (simulating a retry): truncated IDs and every tool
	// body in the prefix MUST remain 100% identical (no double truncation or flip).
	view1Retry := c.View(t.Context(), msgs)
	if got := truncatedToolIDs(view1Retry); strings.Join(got, ",") != strings.Join(trunc1, ",") {
		t.Fatalf("repeated View before Pre changed truncated IDs: got %v, want %v", got, trunc1)
	}
	prevToolBodies := toolBodiesByID(view1)
	for tid, wantBody := range prevToolBodies {
		if gotBody := toolBodiesByID(view1Retry)[tid]; gotBody != wantBody {
			t.Fatalf("repeated View before Pre mutated tool result %s", tid)
		}
	}

	// Feed back provider-reported input tokens for turn 1, then append 3 more
	// turns (including 4K-token tool results). Effective size stays well below
	// 95K, so the truncated set MUST NOT change and every earlier tool result
	// MUST remain byte-identical!
	c.Pre(t.Context(), msgs, sent1)

	for step := range 3 {
		id := fmt.Sprintf("next_%d", step)
		body := fmt.Sprintf("next-%d ", step) + strings.Repeat("B", 16_000) // ~4K tokens each
		msgs = append(msgs,
			assistantWith(toolUse(id, "Bash", `{"command":"go test"}`)),
			toolResult(id, body),
		)
		v := c.View(t.Context(), msgs)
		curTrunc := truncatedToolIDs(v)
		if strings.Join(curTrunc, ",") != strings.Join(trunc1, ",") {
			t.Fatalf("step %d flipped truncated set: got %v, want stable %v", step, curTrunc, trunc1)
		}
		curBodies := toolBodiesByID(v)
		for tid, wantBody := range prevToolBodies {
			if gotBody := curBodies[tid]; gotBody != wantBody {
				t.Fatalf("step %d mutated earlier tool result %s (breaks KV cache)", step, tid)
			}
		}
		c.Pre(t.Context(), msgs, estimateMessages(v))
	}

	// Now push effective usage back over 95% with new large tool outputs (plus
	// fresh tail turns so they leave the protected zone) -> a second batch sweep
	// fires while keeping all epoch-1 truncated outputs byte-identical.
	for i := range 3 {
		id := fmt.Sprintf("wave2_%d", i)
		msgs = append(msgs,
			assistantWith(toolUse(id, "Bash", `{"command":"cat big2"}`)),
			toolResult(id, fmt.Sprintf("wave2-%d ", i)+strings.Repeat("C", 80_000)),
		)
	}
	for i := range 4 {
		id := fmt.Sprintf("tail2_%d", i)
		msgs = append(msgs,
			assistantWith(toolUse(id, "Bash", `{"command":"echo ok2"}`)),
			toolResult(id, fmt.Sprintf("small tail2 %d", i)),
		)
	}
	vWave2 := c.View(t.Context(), msgs)
	trunc2 := truncatedToolIDs(vWave2)
	if len(trunc2) <= len(trunc1) {
		t.Fatalf("wave 2 should truncate additional outputs above 95%%: wave1=%v wave2=%v", trunc1, trunc2)
	}
	wave2Bodies := toolBodiesByID(vWave2)
	for _, tid := range trunc1 {
		if wave2Bodies[tid] != prevToolBodies[tid] {
			t.Fatalf("wave 2 mutated epoch-1 truncated tool result %s", tid)
		}
	}
}

func truncatedToolIDs(msgs []llm.Message) []string {
	var ids []string
	for _, m := range msgs {
		for _, b := range m.Content {
			if b.Type == llm.BlockToolResult {
				for _, inner := range b.Content {
					if strings.Contains(inner.Text, noa.TruncationMarker) {
						ids = append(ids, b.ToolUseID)
						break
					}
				}
			}
		}
	}
	return ids
}

func toolBodiesByID(msgs []llm.Message) map[string]string {
	out := map[string]string{}
	for _, m := range msgs {
		for _, b := range m.Content {
			if b.Type == llm.BlockToolResult && len(b.Content) > 0 {
				out[b.ToolUseID] = b.Content[0].Text
			}
		}
	}
	return out
}
