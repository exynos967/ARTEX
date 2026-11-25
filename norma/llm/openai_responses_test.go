package llm

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestResponsesStreaming drives the Responses SSE event vocabulary through the
// adapter and asserts the neutral message it accumulates: reasoning summary →
// thinking, output_text → text, function_call added + arg deltas → tool_use.
func TestResponsesStreaming(t *testing.T) {
	body := sse2(
		event("response.created", `{"type":"response.created"}`),
		event("response.reasoning_summary_text.delta", `{"type":"response.reasoning_summary_text.delta","delta":"thinking…"}`),
		event("response.output_text.delta", `{"type":"response.output_text.delta","delta":"Hello "}`),
		event("response.output_item.added", `{"type":"response.output_item.added","item":{"type":"function_call","call_id":"call_1","name":"Read"}}`),
		event("response.function_call_arguments.delta", `{"type":"response.function_call_arguments.delta","delta":"{\"file_path\":\"a\"}"}`),
		event("response.completed", `{"type":"response.completed","response":{"status":"completed","usage":{"input_tokens":11,"output_tokens":6,"input_tokens_details":{"cached_tokens":3}}}}`),
	)
	var gotBody map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/responses" {
			t.Errorf("path=%s", r.URL.Path)
		}
		raw, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(raw, &gotBody)
		w.Write([]byte(body))
	}))
	defer srv.Close()

	p, _ := NewProvider(Config{Format: FormatOpenAIResponses, BaseURL: srv.URL, APIKey: "k", Model: "m"})
	acc := NewAccumulator()
	var usage Usage
	var stopReason string
	sawStop := false
	for ev, err := range p.Stream(context.Background(), CompletionRequest{Messages: []Message{UserText("go")}}) {
		if err != nil {
			t.Fatalf("stream err: %v", err)
		}
		if ev.Type == SEMessageDelta {
			usage = ev.Usage
			stopReason = ev.StopReason
		}
		if ev.Type == SEMessageStop {
			sawStop = true
		}
		acc.Add(ev)
	}
	if !sawStop {
		t.Fatal("missing SEMessageStop after response.completed")
	}
	if stopReason != "tool_use" {
		t.Fatalf("stopReason=%q, want tool_use when function_call was emitted", stopReason)
	}
	// stateless wire: store must be false, and the system prompt is top-level.
	if gotBody["store"] != false {
		t.Fatalf("store=%v, want false", gotBody["store"])
	}
	msg := acc.Message()
	if msg.Text() != "Hello " {
		t.Fatalf("text=%q", msg.Text())
	}
	if u := msg.ToolUses(); len(u) != 1 || u[0].ID != "call_1" || u[0].Name != "Read" || string(u[0].Input) != `{"file_path":"a"}` {
		t.Fatalf("tooluse=%+v", u)
	}
	if usage.InputTokens != 11 || usage.OutputTokens != 6 || usage.CacheReadTokens != 3 {
		t.Fatalf("usage=%+v", usage)
	}
}

// TestResponsesComplete verifies the non-streaming path parses output[] items
// (message / reasoning / function_call) and sends a stateless stream:false body.
func TestResponsesComplete(t *testing.T) {
	var gotBody map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/responses" {
			t.Errorf("path=%s", r.URL.Path)
		}
		raw, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(raw, &gotBody)
		w.Header().Set("content-type", "application/json")
		w.Write([]byte(`{"status":"completed","output":[{"type":"reasoning","summary":[{"type":"summary_text","text":"hmm"}]},{"type":"message","role":"assistant","content":[{"type":"output_text","text":"Hi"}]},{"type":"function_call","call_id":"c9","name":"Bash","arguments":"{\"command\":\"ls\"}"}],"usage":{"input_tokens":10,"output_tokens":5,"input_tokens_details":{"cached_tokens":2}}}`))
	}))
	defer srv.Close()

	p, _ := NewProvider(Config{Format: FormatOpenAIResponses, BaseURL: srv.URL, APIKey: "k", Model: "m"})
	msg, stop, usage, err := p.Complete(context.Background(), CompletionRequest{Messages: []Message{UserText("go")}})
	if err != nil {
		t.Fatalf("Complete err: %v", err)
	}
	if gotBody["stream"] != false {
		t.Fatalf("stream=%v, want false", gotBody["stream"])
	}
	if msg.Text() != "Hi" {
		t.Fatalf("text=%q", msg.Text())
	}
	var think string
	for _, b := range msg.Content {
		if b.Type == BlockThinking {
			think = b.Thinking
		}
	}
	if think != "hmm" {
		t.Fatalf("thinking=%q", think)
	}
	if u := msg.ToolUses(); len(u) != 1 || u[0].ID != "c9" || u[0].Name != "Bash" {
		t.Fatalf("tooluse=%+v", u)
	}
	if stop != "tool_use" {
		t.Fatalf("stop=%q", stop)
	}
	if usage.InputTokens != 10 || usage.OutputTokens != 5 || usage.CacheReadTokens != 2 {
		t.Fatalf("usage=%+v", usage)
	}
}

// A reasoning item may carry its thinking in `content` (reasoning_text parts)
// instead of `summary`. The streaming path already handles both event kinds;
// the non-streaming parse must not drop the content variant.
func TestResponsesReasoningTextContent(t *testing.T) {
	msg, _, _, err := parseResponsesResponse([]byte(`{"status":"completed","output":[{"type":"reasoning","content":[{"type":"reasoning_text","text":"deep thought"}]},{"type":"message","role":"assistant","content":[{"type":"output_text","text":"Hi"}]}]}`))
	if err != nil {
		t.Fatalf("parse err: %v", err)
	}
	var think string
	for _, b := range msg.Content {
		if b.Type == BlockThinking {
			think = b.Thinking
		}
	}
	if think != "deep thought" {
		t.Fatalf("thinking=%q", think)
	}
	if msg.Text() != "Hi" {
		t.Fatalf("text=%q", msg.Text())
	}
}

// TestToResponsesInput checks the neutral→input-item translation: tool_use →
// function_call, tool_result → function_call_output (call_id paired), text →
// role message, thinking dropped.
func TestToResponsesInput(t *testing.T) {
	msgs := []Message{
		UserText("hi"),
		{Role: RoleAssistant, Content: []ContentBlock{
			{Type: BlockThinking, Thinking: "dropped"},
			{Type: BlockText, Text: "calling"},
			{Type: BlockToolUse, ID: "c1", Name: "Bash", Input: []byte(`{"command":"ls"}`)},
		}},
		{Role: RoleUser, Content: []ContentBlock{ToolResultText("c1", "file.txt", false)}},
	}
	in := toResponsesInput(msgs)
	// user message, assistant text message, function_call, function_call_output.
	if len(in) != 4 {
		t.Fatalf("items=%d: %+v", len(in), in)
	}
	if in[0].Role != "user" || in[0].Content != "hi" {
		t.Fatalf("item0=%+v", in[0])
	}
	if in[1].Role != "assistant" || in[1].Content != "calling" {
		t.Fatalf("item1=%+v", in[1])
	}
	if in[2].Type != "function_call" || in[2].CallID != "c1" || in[2].Name != "Bash" {
		t.Fatalf("item2=%+v", in[2])
	}
	if in[3].Type != "function_call_output" || in[3].CallID != "c1" || in[3].Output != "file.txt" {
		t.Fatalf("item3=%+v", in[3])
	}
	// thinking must not leak into any item.
	for _, it := range in {
		if strings.Contains(it.Content, "dropped") {
			t.Fatalf("thinking leaked: %+v", it)
		}
	}
}

// TestResponsesStreamingParallelToolCallsAndStop verifies interleaved parallel
// function_call deltas are attributed by item_id / output_index, StopReason is
// "tool_use", and SEMessageStop is emitted after response.completed / incomplete.
func TestResponsesStreamingParallelToolCallsAndStop(t *testing.T) {
	body := sse2(
		event("response.created", `{"type":"response.created"}`),
		event("response.output_item.added", `{"type":"response.output_item.added","output_index":0,"item":{"id":"fc_0","type":"function_call","call_id":"call_a","name":"Read"}}`),
		event("response.output_item.added", `{"type":"response.output_item.added","output_index":1,"item":{"id":"fc_1","type":"function_call","call_id":"call_b","name":"Bash"}}`),
		// Interleave deltas: item 1 by item_id, item 0 by output_index, item 1 by output_index, item 0 by item_id.
		event("response.function_call_arguments.delta", `{"type":"response.function_call_arguments.delta","item_id":"fc_1","output_index":1,"delta":"{\"command\":"}`),
		event("response.function_call_arguments.delta", `{"type":"response.function_call_arguments.delta","output_index":0,"delta":"{\"path\":"}`),
		event("response.function_call_arguments.delta", `{"type":"response.function_call_arguments.delta","output_index":1,"delta":"\"ls\"}"}`),
		event("response.function_call_arguments.delta", `{"type":"response.function_call_arguments.delta","item_id":"fc_0","delta":"\"a.go\"}"}`),
		event("response.completed", `{"type":"response.completed","response":{"status":"completed","usage":{"input_tokens":20,"output_tokens":10}}}`),
	)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(body))
	}))
	defer srv.Close()

	p, _ := NewProvider(Config{Format: FormatOpenAIResponses, BaseURL: srv.URL, APIKey: "k", Model: "m"})
	acc := NewAccumulator()
	var events []StreamEvent
	for ev, err := range p.Stream(context.Background(), CompletionRequest{Messages: []Message{UserText("go")}}) {
		if err != nil {
			t.Fatalf("stream err: %v", err)
		}
		events = append(events, ev)
		acc.Add(ev)
	}
	if len(events) == 0 || events[len(events)-1].Type != SEMessageStop {
		t.Fatalf("last event=%+v, want SEMessageStop", events)
	}
	if acc.StopReason != "tool_use" {
		t.Fatalf("StopReason=%q, want tool_use", acc.StopReason)
	}
	// Verify every SEToolInputJSON carries the right ToolID and Index.
	for _, ev := range events {
		if ev.Type != SEToolInputJSON {
			continue
		}
		switch ev.ToolID {
		case "call_a":
			if ev.Index != 0 {
				t.Fatalf("call_a delta has Index=%d, want 0", ev.Index)
			}
		case "call_b":
			if ev.Index != 1 {
				t.Fatalf("call_b delta has Index=%d, want 1", ev.Index)
			}
		default:
			t.Fatalf("unexpected ToolID %q on SEToolInputJSON %+v", ev.ToolID, ev)
		}
	}
	uses := acc.Message().ToolUses()
	if len(uses) != 2 {
		t.Fatalf("tool_uses=%d, want 2: %+v", len(uses), uses)
	}
	if uses[0].ID != "call_a" || string(uses[0].Input) != `{"path":"a.go"}` {
		t.Fatalf("call 0 wrong: %+v (%s)", uses[0], uses[0].Input)
	}
	if uses[1].ID != "call_b" || string(uses[1].Input) != `{"command":"ls"}` {
		t.Fatalf("call 1 wrong: %+v (%s)", uses[1], uses[1].Input)
	}
}

// TestResponsesStreamingEOFWithoutTerminalReturnsIncompleteError verifies that a
// truncated SSE stream without response.completed / response.incomplete yields
// an IncompleteResponseError instead of succeeding silently.
func TestResponsesStreamingEOFWithoutTerminalReturnsIncompleteError(t *testing.T) {
	body := sse2(
		event("response.created", `{"type":"response.created"}`),
		event("response.output_text.delta", `{"type":"response.output_text.delta","delta":"partial"}`),
	)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(body))
	}))
	defer srv.Close()

	p, _ := NewProvider(Config{Format: FormatOpenAIResponses, BaseURL: srv.URL, APIKey: "k", Model: "m"})
	var gotErr error
	sawStop := false
	for ev, err := range p.Stream(context.Background(), CompletionRequest{Messages: []Message{UserText("go")}}) {
		if err != nil {
			gotErr = err
			break
		}
		if ev.Type == SEMessageStop {
			sawStop = true
		}
	}
	if sawStop {
		t.Fatal("must not emit SEMessageStop when stream ends without terminal event")
	}
	var inc *IncompleteResponseError
	if !errors.As(gotErr, &inc) || inc.Reason != IncompleteMissingTerminal {
		t.Fatalf("err=%v, want IncompleteResponseError(%q)", gotErr, IncompleteMissingTerminal)
	}
}

// event wraps a data payload with a named SSE event line (Responses uses these).
func event(name, data string) string { return "event: " + name + "\ndata: " + data + "\n" }

// sse2 joins named SSE frames into one response body.
func sse2(frames ...string) string { return strings.Join(frames, "\n") + "\n" }
