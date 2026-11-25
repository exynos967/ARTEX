package harness

import (
	"context"
	"encoding/json"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/RC-CHN/ARTEX/norma/llm"
	"github.com/RC-CHN/ARTEX/norma/permission"
	"github.com/RC-CHN/ARTEX/norma/tool"
)

// TestSettlementKeepsToolSchemasByteIdenticalAndBlocksAtExecution verifies that
// entering settlement does not mutate req.Tools (preserving the KV cache prefix)
// while DisabledTools are still rejected at execution time without running.
func TestSettlementKeepsToolSchemasByteIdenticalAndBlocksAtExecution(t *testing.T) {
	for _, syncMode := range []bool{false, true} {
		modeName := "stream"
		if syncMode {
			modeName = "sync"
		}
		t.Run(modeName, func(t *testing.T) {
			var disabledCalls, allowedCalls atomic.Int32
			disabledTool := tool.Build(tool.Spec{
				Name:   "Explore",
				Schema: map[string]any{"type": "object"},
				Run: func(context.Context, json.RawMessage, *tool.ToolContext) (tool.Result, error) {
					disabledCalls.Add(1)
					return tool.Text("explored"), nil
				},
			})
			allowedTool := tool.Build(tool.Spec{
				Name:   "Checkpoint",
				Schema: map[string]any{"type": "object"},
				Run: func(context.Context, json.RawMessage, *tool.ToolContext) (tool.Result, error) {
					allowedCalls.Add(1)
					return tool.Text("checkpointed"), nil
				},
			})

			var captured [][]llm.ToolSchema
			calls := 0
			deps := finalContinueDeps(func(_ context.Context, req llm.CompletionRequest) (llm.Message, string, llm.Usage, error) {
				calls++
				captured = append(captured, append([]llm.ToolSchema(nil), req.Tools...))
				switch calls {
				case 1:
					// Main turn runs Explore -> hits MaxTurns=1 -> enters settlement.
					return finalContinueCall("c1", "Explore", `{}`), "tool_use", llm.Usage{InputTokens: 100}, nil
				case 2:
					// Settlement turn attempts both the disabled tool and the allowed tool.
					msg := finalContinueCall("c2", "Explore", `{}`)
					msg.Content = append(msg.Content, finalContinueCall("c3", "Checkpoint", `{}`).Content...)
					return msg, "tool_use", llm.Usage{InputTokens: 120}, nil
				default:
					return finalContinueText("wrapped up"), "end_turn", llm.Usage{InputTokens: 140}, nil
				}
			})

			in := QueryInput{
				Messages:       []llm.Message{llm.UserText("start")},
				Tools:          tool.NewRegistry(disabledTool, allowedTool),
				PermissionMode: permission.ModeBypass,
				MaxTurns:       1,
				NonStreaming:   syncMode,
				Settlement: &Settlement{
					Prompt:        "Wrap up now.",
					MaxTurns:      2,
					DisabledTools: []string{"Explore"},
				},
			}
			term := drain(t, in, deps)

			if term.Reason != ReasonMaxTurns {
				t.Fatalf("reason=%v, want ReasonMaxTurns", term.Reason)
			}
			if len(captured) != 3 {
				t.Fatalf("captured %d requests, want 3", len(captured))
			}
			for i := 1; i < len(captured); i++ {
				if !reflect.DeepEqual(captured[0], captured[i]) {
					t.Fatalf("req %d mutated req.Tools:\nwant %+v\ngot  %+v", i, captured[0], captured[i])
				}
			}
			if disabledCalls.Load() != 1 {
				t.Fatalf("Explore ran %d times, want 1 (blocked during settlement)", disabledCalls.Load())
			}
			if allowedCalls.Load() != 1 {
				t.Fatalf("Checkpoint ran %d times, want 1 (allowed during settlement)", allowedCalls.Load())
			}
			raw, _ := json.Marshal(term.Messages)
			if !strings.Contains(string(raw), "settlement_tool_disabled") {
				t.Fatalf("missing settlement_tool_disabled rejection receipt in messages: %s", raw)
			}
		})
	}
}

// TestSummaryOnlyKeepsToolSchemasByteIdenticalAndBlocksAtExecution verifies that
// summary-only recovery keeps req.Tools identical to normal turns (preserving
// the KV cache prefix) while rejecting every tool call at execution time.
func TestSummaryOnlyKeepsToolSchemasByteIdenticalAndBlocksAtExecution(t *testing.T) {
	for _, syncMode := range []bool{false, true} {
		modeName := "stream"
		if syncMode {
			modeName = "sync"
		}
		t.Run(modeName, func(t *testing.T) {
			var toolCalls atomic.Int32
			probe := tool.Build(tool.Spec{
				Name:   "WriteReport",
				Schema: map[string]any{"type": "object"},
				Run: func(context.Context, json.RawMessage, *tool.ToolContext) (tool.Result, error) {
					toolCalls.Add(1)
					return tool.Text("written"), nil
				},
			})

			var captured [][]llm.ToolSchema
			calls := 0
			deps := finalContinueDeps(func(_ context.Context, req llm.CompletionRequest) (llm.Message, string, llm.Usage, error) {
				calls++
				captured = append(captured, append([]llm.ToolSchema(nil), req.Tools...))
				switch calls {
				case 1:
					// Thinking-only empty reply triggers summaryOnly recovery.
					return finalContinueThinking(), "end_turn", llm.Usage{InputTokens: 100}, nil
				default:
					// Model still tries to call a tool during summaryOnly recovery.
					return finalContinueCall("bad", "WriteReport", `{}`), "tool_use", llm.Usage{InputTokens: 120}, nil
				}
			})

			in := QueryInput{
				Messages:         []llm.Message{llm.UserText("summarize")},
				Tools:            tool.NewRegistry(probe),
				PermissionMode:   permission.ModeBypass,
				RequireFinalText: true,
				NonStreaming:     syncMode,
			}
			term := drain(t, in, deps)

			if len(captured) != 2 {
				t.Fatalf("captured %d requests, want 2", len(captured))
			}
			if !reflect.DeepEqual(captured[0], captured[1]) {
				t.Fatalf("summaryOnly recovery mutated req.Tools:\nwant %+v\ngot  %+v", captured[0], captured[1])
			}
			if toolCalls.Load() != 0 {
				t.Fatalf("tool ran %d times during summaryOnly recovery, want 0", toolCalls.Load())
			}
			raw, _ := json.Marshal(term.Messages)
			if !strings.Contains(string(raw), "summary_only") {
				t.Fatalf("missing summary_only rejection receipt: %s", raw)
			}
		})
	}
}
