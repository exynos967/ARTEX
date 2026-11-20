package llm

import (
	"testing"
)

// Parallel tool calls may have their argument deltas interleaved by a gateway.
// A single shared buffer then splices call A's tail into call B's JSON, and a
// perfectly good response dies as invalid tool input. Each call now assembles
// from its own fragments, and the events carry the id that attributes them.

func openAIFrame(payload string) string { return "data: " + payload + "\n\n" }

func TestOpenAIInterleavedParallelToolArgumentsStaySeparate(t *testing.T) {
	body := openAIFrame(`{"choices":[{"delta":{"tool_calls":[{"index":0,"id":"a","function":{"name":"Read","arguments":"{\"path\":\""}}]}}]}`) +
		openAIFrame(`{"choices":[{"delta":{"tool_calls":[{"index":1,"id":"b","function":{"name":"Read","arguments":"{\"path\":\""}}]}}]}`) +
		openAIFrame(`{"choices":[{"delta":{"tool_calls":[{"index":0,"function":{"arguments":"/a.txt\"}"}}]}}]}`) +
		openAIFrame(`{"choices":[{"delta":{"tool_calls":[{"index":1,"function":{"arguments":"/b.txt\"}"}}]}}]}`) +
		openAIFrame(`{"choices":[{"delta":{},"finish_reason":"tool_calls"}]}`) +
		"data: [DONE]\n\n"

	p := fixtureProvider(t, body)
	acc := NewAccumulator()
	delivered := map[string]string{}
	for ev, err := range p.Stream(t.Context(), CompletionRequest{
		Messages: []Message{UserText("read both")},
		Tools:    []ToolSchema{{Name: "Read"}},
	}) {
		if err != nil {
			t.Fatalf("interleaved deltas ended the turn: %v", err)
		}
		if ev.Type == SEToolInputJSON {
			delivered[ev.ToolID] += ev.Text
		}
		acc.Add(ev)
	}

	if want := `{"path":"/a.txt"}`; delivered["a"] != want {
		t.Fatalf("call a received %q, want %q", delivered["a"], want)
	}
	if want := `{"path":"/b.txt"}`; delivered["b"] != want {
		t.Fatalf("call b received %q, want %q", delivered["b"], want)
	}
	uses := acc.Message().ToolUses()
	if len(uses) != 2 || string(uses[0].Input) != `{"path":"/a.txt"}` || string(uses[1].Input) != `{"path":"/b.txt"}` {
		t.Fatalf("recorded calls = %+v", uses)
	}
}

func TestOpenAIInterleavedParallelCallsStillValidated(t *testing.T) {
	body := openAIFrame(`{"choices":[{"delta":{"tool_calls":[{"index":0,"id":"a","function":{"name":"Read","arguments":"{}"}}]}}]}`) +
		openAIFrame(`{"choices":[{"delta":{"tool_calls":[{"index":1,"id":"b","function":{"name":"Read","arguments":"{\"path\":\""}}]}}]}`) +
		openAIFrame(`{"choices":[{"delta":{"tool_calls":[{"index":0,"function":{"arguments":""}}]}}]}`) +
		openAIFrame(`{"choices":[{"delta":{},"finish_reason":"tool_calls"}]}`) +
		"data: [DONE]\n\n"

	var gotErr error
	for _, err := range fixtureProvider(t, body).Stream(t.Context(), CompletionRequest{
		Messages: []Message{UserText("read both")},
		Tools:    []ToolSchema{{Name: "Read"}},
	}) {
		if err != nil {
			gotErr = err
			break
		}
	}
	assertIncomplete(t, gotErr, IncompleteInvalidToolInput)
}
