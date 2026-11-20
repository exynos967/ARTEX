package harness

import (
	"context"
	"encoding/json"
	"iter"
	"sync"
	"testing"

	"github.com/RC-CHN/ARTEX/norma/llm"
	"github.com/RC-CHN/ARTEX/norma/permission"
	"github.com/RC-CHN/ARTEX/norma/tool"
)

// The harness must assemble parallel calls from their own fragments and run
// both, even when the deltas arrive interleaved. With one shared buffer, B's
// JSON was appended to A's and the run ended as incomplete_response.
func TestHarnessRoutesInterleavedParallelToolArguments(t *testing.T) {
	var (
		mu  sync.Mutex
		ran []string
	)
	probe := tool.Build(tool.Spec{
		Name:   "probe",
		Schema: map[string]any{"type": "object"},
		Permissions: func(context.Context, json.RawMessage, permission.Context) permission.Decision {
			return permission.Allowed()
		},
		Run: func(_ context.Context, in json.RawMessage, _ *tool.ToolContext) (tool.Result, error) {
			var v struct {
				ID   string `json:"id"`
				Path string `json:"path"`
			}
			if err := json.Unmarshal(in, &v); err != nil {
				return tool.Errorf("bad arguments: " + err.Error()), nil
			}
			mu.Lock()
			ran = append(ran, v.ID+":"+v.Path)
			mu.Unlock()
			return tool.Text("ok"), nil
		},
	})

	turns := 0
	callModel := func(context.Context, llm.CompletionRequest) iter.Seq2[llm.StreamEvent, error] {
		turns++
		return func(yield func(llm.StreamEvent, error) bool) {
			if turns > 1 {
				for _, ev := range textTurn("done") {
					if !yield(ev, nil) {
						return
					}
				}
				return
			}
			for _, ev := range []llm.StreamEvent{
				{Type: llm.SEToolUseStart, ToolID: "a", ToolName: "probe"},
				{Type: llm.SEToolUseStart, ToolID: "b", ToolName: "probe"},
				{Type: llm.SEToolInputJSON, ToolID: "a", Text: `{"id":"a","path":`},
				{Type: llm.SEToolInputJSON, ToolID: "b", Text: `{"id":"b","path":`},
				{Type: llm.SEToolInputJSON, ToolID: "a", Text: `"/a.txt"}`},
				{Type: llm.SEToolInputJSON, ToolID: "b", Text: `"/b.txt"}`},
				{Type: llm.SEMessageDelta, StopReason: "tool_use"},
				{Type: llm.SEMessageStop},
			} {
				if !yield(ev, nil) {
					return
				}
			}
		}
	}

	term := drain(t, QueryInput{
		Messages:       []llm.Message{llm.UserText("read both")},
		Tools:          tool.NewRegistry(probe),
		PermissionMode: permission.ModeBypass,
	}, QueryDeps{CallModel: callModel})

	if term.Reason != ReasonCompleted {
		t.Fatalf("terminal = %s (%v)", term.Reason, term.Err)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(ran) != 2 || ran[0] != "a:/a.txt" || ran[1] != "b:/b.txt" {
		t.Fatalf("tools ran with %v, want both calls with their own arguments", ran)
	}
	var results []llm.ContentBlock
	for _, msg := range term.Messages {
		for _, b := range msg.Content {
			if b.Type == llm.BlockToolResult {
				results = append(results, b)
			}
		}
	}
	if len(results) != 2 || results[0].ToolUseID != "a" || results[1].ToolUseID != "b" {
		t.Fatalf("results = %+v, want one receipt per call in arrival order", results)
	}
}
