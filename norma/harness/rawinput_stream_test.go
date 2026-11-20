package harness

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/RC-CHN/ARTEX/norma/llm"
	"github.com/RC-CHN/ARTEX/norma/permission"
	"github.com/RC-CHN/ARTEX/norma/tool"
)

// The end-to-end path the unit tests cannot see: a real HTTP provider feeds the
// loop, and the loop must hand a cut-off call to the tool that repairs it instead
// of ending the whole run at the transport.
//
// This is the regression the production log showed: the model streams a
// Compress call, the JSON never closes, and the worker dies with
// incomplete_response even though the tool was built to salvage exactly that.

const unfinishedToolArgs = `{"content":[{"startId":"m00001","end`

func sse(w io.Writer, payload string) { fmt.Fprintf(w, "data: %s\n\n", payload) }

// toolServer streams an unfinished call on the first request and a normal answer
// on the second, so the loop can finish once the tool has run.
func toolServer(t *testing.T, name string, calls *atomic.Int32) *httptest.Server {
	t.Helper()
	args, err := json.Marshal(unfinishedToolArgs)
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if calls.Add(1) == 1 {
			sse(w, `{"choices":[{"delta":{"tool_calls":[{"index":0,"id":"call_1","function":{"name":"`+name+`","arguments":`+string(args)+`}}]}}]}`)
			sse(w, `{"choices":[{"delta":{},"finish_reason":"tool_calls"}],"usage":{"prompt_tokens":9,"completion_tokens":4}}`)
			fmt.Fprint(w, "data: [DONE]\n\n")
			return
		}
		sse(w, `{"choices":[{"delta":{"content":"done"},"finish_reason":"stop"}]}`)
		fmt.Fprint(w, "data: [DONE]\n\n")
	}))
	t.Cleanup(srv.Close)
	return srv
}

func openAIProviderFor(t *testing.T, url string, client *http.Client) llm.Provider {
	t.Helper()
	p, err := llm.NewProvider(llm.Config{Format: llm.FormatOpenAI, BaseURL: url, HTTPClient: client, MaxRetries: -1, EmptyResponseRetries: -1})
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func TestHarnessDeliversUnfinishedArgumentsToRawTool(t *testing.T) {
	var calls atomic.Int32
	srv := toolServer(t, "Lenient", &calls)
	p := openAIProviderFor(t, srv.URL, srv.Client())

	var (
		effects   atomic.Int32
		malformed atomic.Bool
		received  atomic.Value
	)
	raw := tool.Build(tool.Spec{
		Name:     "Lenient",
		Schema:   map[string]any{"type": "object"},
		RawInput: true,
		Permissions: func(context.Context, json.RawMessage, permission.Context) permission.Decision {
			return permission.Allowed()
		},
		Run: func(_ context.Context, in json.RawMessage, tc *tool.ToolContext) (tool.Result, error) {
			effects.Add(1)
			received.Store(string(in))
			malformed.Store(tc.InputMalformed)
			return tool.Text("salvaged"), nil
		},
	})

	term := drain(t, QueryInput{
		Provider:       p,
		Messages:       []llm.Message{llm.UserText("compress the old ranges")},
		Tools:          tool.NewRegistry(raw),
		PermissionMode: permission.ModeBypass,
	}, QueryDeps{})

	if effects.Load() != 1 {
		t.Fatalf("the raw-input tool ran %d times, want 1", effects.Load())
	}
	if got, _ := received.Load().(string); got != unfinishedToolArgs {
		t.Fatalf("tool received %q, want %q", got, unfinishedToolArgs)
	}
	if !malformed.Load() {
		t.Fatal("the tool was not told its arguments were malformed")
	}
	if term.Reason != ReasonCompleted || term.Text != "done" {
		t.Fatalf("terminal = %s (%q), want completed/done", term.Reason, term.Text)
	}
}

func TestHarnessRefusesUnfinishedArgumentsForOtherTools(t *testing.T) {
	var calls atomic.Int32
	srv := toolServer(t, "Strict", &calls)
	p := openAIProviderFor(t, srv.URL, srv.Client())

	var effects atomic.Int32
	strict := tool.Build(tool.Spec{
		Name:   "Strict",
		Schema: map[string]any{"type": "object"},
		Permissions: func(context.Context, json.RawMessage, permission.Context) permission.Decision {
			return permission.Allowed()
		},
		Run: func(context.Context, json.RawMessage, *tool.ToolContext) (tool.Result, error) {
			effects.Add(1)
			return tool.Text("ran"), nil
		},
	})

	term := drain(t, QueryInput{
		Provider:       p,
		Messages:       []llm.Message{llm.UserText("do the thing")},
		Tools:          tool.NewRegistry(strict),
		PermissionMode: permission.ModeBypass,
	}, QueryDeps{})

	if effects.Load() != 0 {
		t.Fatal("a partial call was executed for a tool that did not opt in")
	}
	if term.Reason != ReasonIncompleteResponse {
		t.Fatalf("terminal = %s, want incomplete_response", term.Reason)
	}
	if calls.Load() != 1 {
		t.Fatalf("the provider was called %d times; a partial call must not be retried", calls.Load())
	}
}

// Non-streaming responses are atomic: the tool still gets the bytes the model
// sent, while the recorded message (replayed on the next request) carries "{}".
func TestNonStreamingRawToolGetsRawArgumentsAndReplayableHistory(t *testing.T) {
	var (
		calls    atomic.Int32
		received atomic.Value
	)
	raw := tool.Build(tool.Spec{
		Name:     "Lenient",
		Schema:   map[string]any{"type": "object"},
		RawInput: true,
		Permissions: func(context.Context, json.RawMessage, permission.Context) permission.Decision {
			return permission.Allowed()
		},
		Run: func(_ context.Context, in json.RawMessage, _ *tool.ToolContext) (tool.Result, error) {
			received.Store(string(in))
			return tool.Text("salvaged"), nil
		},
	})
	sync := func(context.Context, llm.CompletionRequest) (llm.Message, string, llm.Usage, error) {
		if calls.Add(1) == 1 {
			return llm.Message{Role: llm.RoleAssistant, Content: []llm.ContentBlock{{
				Type: llm.BlockToolUse, ID: "c1", Name: "Lenient", Input: json.RawMessage(unfinishedToolArgs),
			}}}, "tool_use", llm.Usage{}, nil
		}
		return llm.Message{Role: llm.RoleAssistant, Content: []llm.ContentBlock{llm.TextBlock("done")}}, "end_turn", llm.Usage{}, nil
	}

	term := drain(t, QueryInput{
		NonStreaming:   true,
		Messages:       []llm.Message{llm.UserText("compress the old ranges")},
		Tools:          tool.NewRegistry(raw),
		PermissionMode: permission.ModeBypass,
	}, QueryDeps{CallModelSync: sync})

	if got, _ := received.Load().(string); got != unfinishedToolArgs {
		t.Fatalf("tool received %q, want %q", got, unfinishedToolArgs)
	}
	if term.Reason != ReasonCompleted {
		t.Fatalf("terminal = %s", term.Reason)
	}
	for _, msg := range term.Messages {
		for _, b := range msg.Content {
			if b.Type == llm.BlockToolUse && b.Name == "Lenient" && string(b.Input) != "{}" {
				t.Fatalf("history kept unparseable arguments: %q", b.Input)
			}
		}
	}
}

// Hosts may supply their own Provider (FR-03.7). One that skips the transport
// check must still not get a partial call executed: the harness is the last gate.
func TestHarnessRefusesInvalidArgumentsFromHostProviders(t *testing.T) {
	var effects atomic.Int32
	strict := tool.Build(tool.Spec{
		Name:   "Strict",
		Schema: map[string]any{"type": "object"},
		Permissions: func(context.Context, json.RawMessage, permission.Context) permission.Decision {
			return permission.Allowed()
		},
		Run: func(context.Context, json.RawMessage, *tool.ToolContext) (tool.Result, error) {
			effects.Add(1)
			return tool.Text("ran"), nil
		},
	})
	m := &scriptedModel{turns: [][]llm.StreamEvent{
		toolTurn("c1", "Strict", unfinishedToolArgs),
		textTurn("done"),
	}}

	term := drain(t, QueryInput{
		Messages:       []llm.Message{llm.UserText("go")},
		Tools:          tool.NewRegistry(strict),
		PermissionMode: permission.ModeBypass,
	}, QueryDeps{CallModel: m.call})

	if effects.Load() != 0 {
		t.Fatal("a partial call from a host provider was executed")
	}
	if term.Reason != ReasonCompleted {
		t.Fatalf("terminal = %s, want the loop to continue with a tool error", term.Reason)
	}
	found := false
	for _, msg := range term.Messages {
		for _, b := range msg.Content {
			if b.Type == llm.BlockToolResult && b.IsError {
				for _, inner := range b.Content {
					if strings.Contains(inner.Text, "NOT executed") {
						found = true
					}
				}
			}
		}
	}
	if !found {
		t.Fatal("the model was never told its call was refused; it will repeat it")
	}
}
