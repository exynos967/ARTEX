package llm

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
)

// A tool that declares RawInput parses its own arguments, so the transport has
// to hand over even bytes that never became valid JSON. Refusing them at the
// adapter is what made noa's argument repair unreachable in production: the turn
// ended before the tool could salvage a single range.

const unfinishedCompressArgs = `{"content":[{"startId":"m00001","endId":"m00009","summary":"first range"},{"startId":"m0001`

func openAIStreamBody(t *testing.T, args, finish string) string {
	t.Helper()
	quoted, err := json.Marshal(args)
	if err != nil {
		t.Fatal(err)
	}
	frame := func(payload string) string { return "data: " + payload + "\n\n" }
	return frame(`{"choices":[{"delta":{"tool_calls":[{"index":0,"id":"call_1","function":{"name":"Compress","arguments":`+string(quoted)+`}}]}}]}`) +
		frame(`{"choices":[{"delta":{},"finish_reason":"`+finish+`"}],"usage":{"prompt_tokens":9,"completion_tokens":4}}`) +
		"data: [DONE]\n\n"
}

func TestOpenAIRawInputToolReceivesUnfinishedArguments(t *testing.T) {
	p := fixtureProvider(t, openAIStreamBody(t, unfinishedCompressArgs, "tool_calls"))
	req := CompletionRequest{
		Messages: []Message{UserText("compress please")},
		Tools:    []ToolSchema{{Name: "Compress", RawInput: true}},
	}
	acc := NewAccumulator()
	var delivered string
	stopped := false
	for ev, err := range p.Stream(t.Context(), req) {
		if err != nil {
			t.Fatalf("a raw-input tool's partial arguments ended the turn: %v", err)
		}
		if ev.Type == SEToolInputJSON {
			delivered += ev.Text
		}
		if ev.Type == SEMessageStop {
			stopped = true
		}
		acc.Add(ev)
	}
	if delivered != unfinishedCompressArgs {
		t.Fatalf("delivered %q, want the bytes the model actually produced", delivered)
	}
	if !stopped {
		t.Fatal("no terminal boundary: the turn cannot have completed")
	}
	uses := acc.Message().ToolUses()
	if len(uses) != 1 || uses[0].Name != "Compress" {
		t.Fatalf("tool calls = %+v", uses)
	}
	// The recorded message is what gets replayed to a provider next turn, and no
	// wire format accepts invalid tool arguments. The tool still received the
	// originals; only the transcript is normalized.
	if string(uses[0].Input) != "{}" {
		t.Fatalf("history kept unparseable arguments: %q", uses[0].Input)
	}
}

func TestToolWithoutRawInputStillRejectsUnfinishedArguments(t *testing.T) {
	p := fixtureProvider(t, openAIStreamBody(t, unfinishedCompressArgs, "tool_calls"))
	var gotErr error
	for _, err := range p.Stream(t.Context(), CompletionRequest{
		Messages: []Message{UserText("compress please")},
		// Same bytes, same tool name, but no RawInput opt-in: a partial call must
		// not be submitted for a tool that cannot parse it.
		Tools: []ToolSchema{{Name: "Compress"}},
	}) {
		if err != nil {
			gotErr = err
			break
		}
	}
	assertIncomplete(t, gotErr, IncompleteInvalidToolInput)
}

func TestCompleteDeliversUnfinishedArgumentsToRawTool(t *testing.T) {
	quoted, err := json.Marshal(unfinishedCompressArgs)
	if err != nil {
		t.Fatal(err)
	}
	body := `{"choices":[{"message":{"content":null,"tool_calls":[{"id":"call_1","type":"function","function":{"name":"Compress","arguments":` + string(quoted) + `}}]},"finish_reason":"tool_calls"}],"usage":{"prompt_tokens":9,"completion_tokens":4}}`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, body) }))
	defer srv.Close()
	p, err := NewProvider(Config{Format: FormatOpenAI, BaseURL: srv.URL, HTTPClient: srv.Client(), MaxRetries: -1, EmptyResponseRetries: -1})
	if err != nil {
		t.Fatal(err)
	}

	msg, _, _, err := p.Complete(t.Context(), CompletionRequest{
		Messages: []Message{UserText("compress please")},
		Tools:    []ToolSchema{{Name: "Compress", RawInput: true}},
	})
	if err != nil {
		t.Fatalf("non-streaming raw-input call ended the turn: %v", err)
	}
	uses := msg.ToolUses()
	if len(uses) != 1 || string(uses[0].Input) != unfinishedCompressArgs {
		t.Fatalf("raw arguments not delivered: %+v", uses)
	}

	if _, _, _, err := p.Complete(t.Context(), CompletionRequest{
		Messages: []Message{UserText("compress please")},
		Tools:    []ToolSchema{{Name: "Compress"}},
	}); err == nil {
		t.Fatal("a partial call was accepted for a tool that did not opt in")
	} else {
		assertIncomplete(t, err, IncompleteInvalidToolInput)
	}
}

func TestAnthropicRawInputToolReceivesUnfinishedArguments(t *testing.T) {
	const partial = `{"content":[{"startId":`
	quoted, err := json.Marshal(partial)
	if err != nil {
		t.Fatal(err)
	}
	body := anthropicFrame(`{"type":"content_block_start","content_block":{"type":"tool_use","id":"call_1","name":"Compress","input":{}}}`) +
		anthropicFrame(fmt.Sprintf(`{"type":"content_block_delta","delta":{"type":"input_json_delta","partial_json":%s}}`, quoted)) +
		anthropicFrame(`{"type":"content_block_stop","index":0}`) +
		anthropicFrame(`{"type":"message_delta","delta":{"stop_reason":"max_tokens"},"usage":{"output_tokens":4}}`) +
		anthropicFrame(`{"type":"message_stop"}`)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, body) }))
	defer srv.Close()
	p, err := NewProvider(Config{Format: FormatAnthropic, BaseURL: srv.URL, EmptyResponseRetries: -1})
	if err != nil {
		t.Fatal(err)
	}

	var delivered string
	for ev, err := range p.Stream(t.Context(), CompletionRequest{
		Messages: []Message{UserText("compress please")},
		Tools:    []ToolSchema{{Name: "Compress", RawInput: true}},
	}) {
		if err != nil {
			t.Fatalf("a raw-input tool's partial arguments ended the turn: %v", err)
		}
		if ev.Type == SEToolInputJSON {
			delivered += ev.Text
		}
	}
	if delivered != partial {
		t.Fatalf("delivered %q, want %q", delivered, partial)
	}

	var gotErr error
	for _, err := range p.Stream(t.Context(), CompletionRequest{
		Messages: []Message{UserText("compress please")},
		Tools:    []ToolSchema{{Name: "Compress"}},
	}) {
		if err != nil {
			gotErr = err
			break
		}
	}
	assertIncomplete(t, gotErr, IncompleteInvalidToolInput)
}
