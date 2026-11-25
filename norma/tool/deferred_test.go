package tool

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
)

// echoTool is a trivial deferred tool that echoes its "msg" param.
func echoTool() CoreTool {
	return Build(Spec{
		Name:        "echo",
		Description: "Echoes the msg parameter back.",
		Schema: map[string]any{
			"type":       "object",
			"properties": map[string]any{"msg": map[string]any{"type": "string"}},
			"required":   []any{"msg"},
		},
		Run: func(_ context.Context, in json.RawMessage, _ *ToolContext) (Result, error) {
			var a struct {
				Msg string `json:"msg"`
			}
			_ = json.Unmarshal(in, &a)
			return Text("echo:" + a.Msg), nil
		},
	})
}

func TestUnlockSet(t *testing.T) {
	s := NewUnlockSet("a", "b")
	if !s.Has("a") || !s.Has("b") || s.Has("c") {
		t.Fatalf("seed wrong: %v", s.List())
	}
	s.Add("c")
	if !s.Has("c") {
		t.Fatal("Add failed")
	}
	if got := s.List(); len(got) != 3 || got[0] != "a" || got[2] != "c" {
		t.Fatalf("List not sorted/complete: %v", got)
	}
}

func TestRenderDeferredToolsBlock(t *testing.T) {
	if RenderDeferredToolsBlock(nil) != "" {
		t.Fatal("empty names should render empty")
	}
	out := RenderDeferredToolsBlock([]string{"mcp__b__y", "mcp__a__x"})
	if !strings.Contains(out, "<available-deferred-tools>") ||
		!strings.Contains(out, "mcp__a__x") || !strings.Contains(out, "mcp__b__y") ||
		!strings.Contains(out, ExecuteExtraToolName) {
		t.Fatalf("block missing parts:\n%s", out)
	}
	// sorted: a before b
	if strings.Index(out, "mcp__a__x") > strings.Index(out, "mcp__b__y") {
		t.Fatal("names not sorted")
	}
}

func TestSearchExtraTools(t *testing.T) {
	reg := NewRegistry(echoTool())
	search := NewSearchExtraTools(reg, []string{"echo"})

	// exact select
	r, _ := search.Call(context.Background(), json.RawMessage(`{"query":"select:echo"}`), nil)
	txt := r.Content[0].Text
	if !strings.Contains(txt, "## echo") || !strings.Contains(txt, "params schema") {
		t.Fatalf("select:echo missing schema:\n%s", txt)
	}
	// keyword
	r, _ = search.Call(context.Background(), json.RawMessage(`{"query":"echoes"}`), nil)
	if !strings.Contains(r.Content[0].Text, "## echo") {
		t.Fatalf("keyword search failed:\n%s", r.Content[0].Text)
	}
	// non-deferred name → not found (registry has it but it is not in deferred list)
	reg2 := NewRegistry(echoTool())
	search2 := NewSearchExtraTools(reg2, []string{"other"})
	r, _ = search2.Call(context.Background(), json.RawMessage(`{"query":"select:echo"}`), nil)
	if !strings.Contains(r.Content[0].Text, "No matching") {
		t.Fatalf("non-deferred should not surface:\n%s", r.Content[0].Text)
	}
}

func TestExecuteExtraTool(t *testing.T) {
	reg := NewRegistry(echoTool())
	unlock := NewUnlockSet("echo")
	exec := NewExecuteExtraTool(reg, unlock)

	// unlocked → runs
	r, _ := exec.Call(context.Background(), json.RawMessage(`{"tool_name":"echo","params":{"msg":"hi"}}`), nil)
	if r.IsError || r.Content[0].Text != "echo:hi" {
		t.Fatalf("expected echo:hi, got %+v", r)
	}

	// locked → rejected
	locked := NewExecuteExtraTool(reg, NewUnlockSet())
	r, _ = locked.Call(context.Background(), json.RawMessage(`{"tool_name":"echo","params":{"msg":"hi"}}`), nil)
	if !r.IsError || !strings.Contains(r.Content[0].Text, "not unlocked") {
		t.Fatalf("locked tool should be rejected, got %+v", r)
	}

	// unknown tool
	r, _ = exec.Call(context.Background(), json.RawMessage(`{"tool_name":"nope","params":{}}`), nil)
	if !r.IsError || !strings.Contains(r.Content[0].Text, "unknown tool") {
		t.Fatalf("unknown tool should error, got %+v", r)
	}

	// invalid params (missing required msg) → schema validation error
	r, _ = exec.Call(context.Background(), json.RawMessage(`{"tool_name":"echo","params":{}}`), nil)
	if !r.IsError || !strings.Contains(r.Content[0].Text, "invalid params") {
		t.Fatalf("invalid params should error, got %+v", r)
	}
}

func TestDynamicAddDeferredToolLifecycle(t *testing.T) {
	reg := NewRegistry()
	unlock := NewUnlockSet()
	search := NewSearchExtraTools(reg, nil)
	exec := NewExecuteExtraTool(reg, unlock)
	reg.Add(search)
	reg.Add(exec)

	beforeSchemas := reg.Schemas()

	// Dynamically register a deferred tool after NewSearchExtraTools was built.
	lazy := Build(Spec{
		Name:        "mcp__playwright__navigate",
		Description: "Navigate browser to a URL.",
		Schema: map[string]any{
			"type":       "object",
			"properties": map[string]any{"url": map[string]any{"type": "string"}},
			"required":   []any{"url"},
		},
		Run: func(_ context.Context, in json.RawMessage, _ *ToolContext) (Result, error) {
			var a struct {
				URL string `json:"url"`
			}
			_ = json.Unmarshal(in, &a)
			return Text("navigated:" + a.URL), nil
		},
	})
	reg.AddDeferred(lazy)

	// Schemas() must remain completely unchanged (zero prompt-cache bust).
	afterSchemas := reg.Schemas()
	if len(afterSchemas) != len(beforeSchemas) {
		t.Fatalf("Schemas() mutated after AddDeferred: before=%d after=%d", len(beforeSchemas), len(afterSchemas))
	}
	for _, sc := range afterSchemas {
		if sc.Name == "mcp__playwright__navigate" {
			t.Fatal("deferred tool leaked into Schemas()")
		}
	}

	// Immediately discoverable via SearchExtraTools (both exact and keyword/suffix).
	r, _ := search.Call(context.Background(), json.RawMessage(`{"query":"select:navigate"}`), nil)
	if r.IsError || !strings.Contains(r.Content[0].Text, "## mcp__playwright__navigate") {
		t.Fatalf("SearchExtraTools select failed for dynamic deferred tool:\n%s", r.Content[0].Text)
	}
	r, _ = search.Call(context.Background(), json.RawMessage(`{"query":"playwright url"}`), nil)
	if r.IsError || !strings.Contains(r.Content[0].Text, "## mcp__playwright__navigate") {
		t.Fatalf("SearchExtraTools keyword failed for dynamic deferred tool:\n%s", r.Content[0].Text)
	}

	// Blocked by ExecuteExtraTool while still locked.
	r, _ = exec.Call(context.Background(), json.RawMessage(`{"tool_name":"mcp__playwright__navigate","params":{"url":"https://example.com"}}`), nil)
	if !r.IsError || !strings.Contains(r.Content[0].Text, "not unlocked") {
		t.Fatalf("locked dynamic deferred tool should be rejected, got %+v", r)
	}

	// Callable once unlocked.
	unlock.Add("mcp__playwright__navigate")
	r, _ = exec.Call(context.Background(), json.RawMessage(`{"tool_name":"mcp__playwright__navigate","params":{"url":"https://example.com"}}`), nil)
	if r.IsError || r.Content[0].Text != "navigated:https://example.com" {
		t.Fatalf("unlocked dynamic deferred tool should run, got %+v", r)
	}
}
