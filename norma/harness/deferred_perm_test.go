package harness

import (
	"context"
	"encoding/json"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/RC-CHN/ARTEX/norma/llm"
	"github.com/RC-CHN/ARTEX/norma/permission"
	"github.com/RC-CHN/ARTEX/norma/tool"
)

type recordHooks struct {
	preNames  []string
	preInputs []string
	postNames []string
	blockName string
	rewriteTo []byte
}

func (h *recordHooks) PreToolUse(_ context.Context, name string, input []byte) (bool, string, []byte) {
	h.preNames = append(h.preNames, name)
	h.preInputs = append(h.preInputs, string(input))
	if h.blockName != "" && name == h.blockName {
		return true, "blocked " + name, nil
	}
	return false, "", h.rewriteTo
}

func (h *recordHooks) PostToolUse(_ context.Context, name string, _ []byte, _ []byte, _ bool) {
	h.postNames = append(h.postNames, name)
}

func (h *recordHooks) Stop(context.Context, []llm.Message) (bool, []string, string) {
	return false, nil, ""
}

func wrapExtra(t *testing.T, name string, params any) json.RawMessage {
	t.Helper()
	b, err := json.Marshal(map[string]any{"tool_name": name, "params": params})
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// TestDeferredToolPermissionAndHookEnforcement verifies that ExecuteExtraTool
// is unwrapped at the harness choke point so DisallowedTools, tool
// CheckPermissions, ModePlan (allowing read-only deferred tools while blocking
// mutating ones), CanUseTool, PreToolUse/PostToolUse hooks, input rewrites,
// nested wrappers, and UnlockSet gating all hold.
func TestDeferredToolPermissionAndHookEnforcement(t *testing.T) {
	var readCalls, writeCalls atomic.Int32
	var lastWriteArg string

	roTool := tool.Build(tool.Spec{
		Name:     "DeferredRead",
		ReadOnly: func(json.RawMessage) bool { return true },
		Schema: map[string]any{
			"type":       "object",
			"properties": map[string]any{"id": map[string]any{"type": "string"}},
			"required":   []any{"id"},
		},
		Run: func(_ context.Context, in json.RawMessage, _ *tool.ToolContext) (tool.Result, error) {
			readCalls.Add(1)
			return tool.Text("read:" + string(in)), nil
		},
	})
	rwTool := tool.Build(tool.Spec{
		Name:     "DeferredWrite",
		ReadOnly: func(json.RawMessage) bool { return false },
		Schema: map[string]any{
			"type":       "object",
			"properties": map[string]any{"val": map[string]any{"type": "string"}},
			"required":   []any{"val"},
		},
		Permissions: func(_ context.Context, in json.RawMessage, _ permission.Context) permission.Decision {
			var a struct{ Val string }
			_ = json.Unmarshal(in, &a)
			if a.Val == "FORBIDDEN" {
				return permission.Denied("hard-denied by target tool")
			}
			return permission.AskUser("write " + a.Val)
		},
		Run: func(_ context.Context, in json.RawMessage, _ *tool.ToolContext) (tool.Result, error) {
			writeCalls.Add(1)
			lastWriteArg = string(in)
			return tool.Text("wrote:" + string(in)), nil
		},
	})

	newRegistry := func(unlocked ...string) *tool.Registry {
		reg := tool.NewRegistry()
		reg.AddDeferred(roTool)
		reg.AddDeferred(rwTool)
		reg.Add(tool.NewExecuteExtraTool(reg, tool.NewUnlockSet(unlocked...)))
		return reg
	}

	t.Run("DisallowedTools blocks deferred target even in ModeBypass", func(t *testing.T) {
		reg := newRegistry("DeferredWrite")
		l := &loop{ctx: t.Context(), in: QueryInput{
			Tools:          reg,
			PermissionMode: permission.ModeBypass,
			Disallowed:     []string{"DeferredWrite"},
		}}
		before := writeCalls.Load()
		res, _ := l.execOne(t.Context(), llm.ContentBlock{
			ID: "u1", Name: tool.ExecuteExtraToolName,
			Input: wrapExtra(t, "DeferredWrite", map[string]any{"val": "ok"}),
		}, nil)
		if !res.IsError || !strings.Contains(res.Content[0].Text, "disallowed") {
			t.Fatalf("expected disallowed error, got %+v", res)
		}
		if writeCalls.Load() != before {
			t.Fatal("disallowed deferred tool executed")
		}
	})

	t.Run("target CheckPermissions hard-deny blocks even in ModeBypass", func(t *testing.T) {
		reg := newRegistry("DeferredWrite")
		l := &loop{ctx: t.Context(), in: QueryInput{
			Tools:          reg,
			PermissionMode: permission.ModeBypass,
		}}
		before := writeCalls.Load()
		res, _ := l.execOne(t.Context(), llm.ContentBlock{
			ID: "u2", Name: tool.ExecuteExtraToolName,
			Input: wrapExtra(t, "DeferredWrite", map[string]any{"val": "FORBIDDEN"}),
		}, nil)
		if !res.IsError || !strings.Contains(res.Content[0].Text, "hard-denied by target tool") {
			t.Fatalf("expected target hard-deny, got %+v", res)
		}
		if writeCalls.Load() != before {
			t.Fatal("hard-denied deferred tool executed")
		}
	})

	t.Run("ModePlan permits read-only deferred tool and blocks mutating deferred tool", func(t *testing.T) {
		reg := newRegistry("DeferredRead", "DeferredWrite")
		l := &loop{ctx: t.Context(), in: QueryInput{
			Tools:          reg,
			PermissionMode: permission.ModePlan,
		}}
		resRO, _ := l.execOne(t.Context(), llm.ContentBlock{
			ID: "u3", Name: tool.ExecuteExtraToolName,
			Input: wrapExtra(t, "DeferredRead", map[string]any{"id": "42"}),
		}, nil)
		if resRO.IsError || !strings.Contains(resRO.Content[0].Text, `"id":"42"`) {
			t.Fatalf("read-only deferred tool should be allowed in ModePlan, got %+v", resRO)
		}

		before := writeCalls.Load()
		resRW, _ := l.execOne(t.Context(), llm.ContentBlock{
			ID: "u4", Name: tool.ExecuteExtraToolName,
			Input: wrapExtra(t, "DeferredWrite", map[string]any{"val": "mutate"}),
		}, nil)
		if !resRW.IsError || !strings.Contains(resRW.Content[0].Text, "plan mode") {
			t.Fatalf("mutating deferred tool must be blocked in ModePlan, got %+v", resRW)
		}
		if writeCalls.Load() != before {
			t.Fatal("mutating deferred tool ran in ModePlan")
		}
	})

	t.Run("CanUseTool and hooks see unwrapped target name and propagate input rewrites", func(t *testing.T) {
		reg := newRegistry("DeferredWrite")
		var askedName string
		hooks := &recordHooks{rewriteTo: []byte(`{"val":"rewritten-by-hook"}`)}
		l := &loop{ctx: t.Context(), in: QueryInput{
			Tools:          reg,
			PermissionMode: permission.ModeDefault,
			Hooks:          hooks,
			CanUseTool: func(_ context.Context, toolName string, input json.RawMessage, _ permission.Context) permission.Decision {
				askedName = toolName
				return permission.Decision{Behavior: permission.Allow, UpdatedInput: []byte(`{"val":"rewritten-by-perm"}`)}
			},
		}}
		res, _ := l.execOne(t.Context(), llm.ContentBlock{
			ID: "u5", Name: tool.ExecuteExtraToolName,
			Input: wrapExtra(t, "DeferredWrite", map[string]any{"val": "orig"}),
		}, nil)
		if res.IsError {
			t.Fatalf("expected allowed execution, got %+v", res)
		}
		if askedName != "DeferredWrite" {
			t.Fatalf("CanUseTool saw toolName=%q, want DeferredWrite", askedName)
		}
		if len(hooks.preNames) != 1 || hooks.preNames[0] != "DeferredWrite" || hooks.preInputs[0] != `{"val":"rewritten-by-perm"}` {
			t.Fatalf("PreToolUse saw names=%v inputs=%v", hooks.preNames, hooks.preInputs)
		}
		if len(hooks.postNames) != 1 || hooks.postNames[0] != "DeferredWrite" {
			t.Fatalf("PostToolUse saw names=%v, want [DeferredWrite]", hooks.postNames)
		}
		if lastWriteArg != `{"val":"rewritten-by-hook"}` {
			t.Fatalf("target received %s, want rewritten hook params", lastWriteArg)
		}
	})

	t.Run("PreToolUse hook blocks deferred target and UnlockSet remains enforced", func(t *testing.T) {
		reg := newRegistry("DeferredRead") // DeferredWrite is locked
		hooks := &recordHooks{blockName: "DeferredRead"}
		l := &loop{ctx: t.Context(), in: QueryInput{
			Tools:          reg,
			PermissionMode: permission.ModeBypass,
			Hooks:          hooks,
		}}
		resBlocked, _ := l.execOne(t.Context(), llm.ContentBlock{
			ID: "u6", Name: tool.ExecuteExtraToolName,
			Input: wrapExtra(t, "DeferredRead", map[string]any{"id": "1"}),
		}, nil)
		if !resBlocked.IsError || !strings.Contains(resBlocked.Content[0].Text, "Blocked by hook") {
			t.Fatalf("expected hook block, got %+v", resBlocked)
		}
		// Locked tool passes permissions in ModeBypass but is still rejected by UnlockSet.
		resLocked, _ := l.execOne(t.Context(), llm.ContentBlock{
			ID: "u7", Name: tool.ExecuteExtraToolName,
			Input: wrapExtra(t, "DeferredWrite", map[string]any{"val": "x"}),
		}, nil)
		if !resLocked.IsError || !strings.Contains(resLocked.Content[0].Text, "not unlocked") {
			t.Fatalf("expected UnlockSet rejection, got %+v", resLocked)
		}
	})

	t.Run("nested ExecuteExtraTool unwraps through multiple layers", func(t *testing.T) {
		reg := newRegistry("DeferredWrite")
		l := &loop{ctx: t.Context(), in: QueryInput{
			Tools:          reg,
			PermissionMode: permission.ModeBypass,
			Disallowed:     []string{"DeferredWrite"},
		}}
		inner := wrapExtra(t, "DeferredWrite", map[string]any{"val": "x"})
		nested := wrapExtra(t, tool.ExecuteExtraToolName, json.RawMessage(inner))
		res, _ := l.execOne(t.Context(), llm.ContentBlock{
			ID: "u8", Name: tool.ExecuteExtraToolName, Input: nested,
		}, nil)
		if !res.IsError || !strings.Contains(res.Content[0].Text, "disallowed") {
			t.Fatalf("nested ExecuteExtraTool bypassed Disallowed: %+v", res)
		}
	})
}
