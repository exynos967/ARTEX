package harness

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"

	"github.com/RC-CHN/ARTEX/norma/llm"
	"github.com/RC-CHN/ARTEX/norma/permission"
	"github.com/RC-CHN/ARTEX/norma/tool"
)

// acceptsRawInput is the optional opt-out from schema validation. Discovered by
// assertion rather than declared on tool.CoreTool, so hosts implementing that
// interface are unaffected. The same predicate decides, one layer up, whether
// the transport may deliver a partial call at all (see llm.ToolSchema.RawInput).
func acceptsRawInput(t tool.CoreTool) bool { return tool.AcceptsRawInput(t) }

const maxExtraToolDepth = 8

type extraWrapFrame struct {
	toolName string
}

// unwrapExtraTool peels ExecuteExtraTool wrapper envelopes (up to
// maxExtraToolDepth) so settlement, permission evaluation, DisallowedTools,
// ModePlan, and PreToolUse/PostToolUse hooks always inspect the real target
// tool and its params.
func unwrapExtraTool(name string, input json.RawMessage) (effName string, effInput json.RawMessage, frames []extraWrapFrame, depthExceeded bool) {
	effName, effInput = name, input
	for depth := 0; effName == tool.ExecuteExtraToolName; depth++ {
		if depth >= maxExtraToolDepth {
			return effName, effInput, frames, true
		}
		var a struct {
			Name   string          `json:"tool_name"`
			Params json.RawMessage `json:"params"`
		}
		if json.Unmarshal(effInput, &a) != nil || a.Name == "" {
			return effName, effInput, frames, false
		}
		params := a.Params
		if len(bytes.TrimSpace(params)) == 0 {
			params = json.RawMessage("{}")
		}
		frames = append(frames, extraWrapFrame{toolName: a.Name})
		effName, effInput = a.Name, params
	}
	return effName, effInput, frames, false
}

// rewrapExtraTool rebuilds nested ExecuteExtraTool JSON envelopes after a
// permission decision or PreToolUse hook rewrites the target tool's params.
func rewrapExtraTool(frames []extraWrapFrame, innerInput json.RawMessage) json.RawMessage {
	cur := innerInput
	for i := len(frames) - 1; i >= 0; i-- {
		wrapped, err := json.Marshal(struct {
			ToolName string          `json:"tool_name"`
			Params   json.RawMessage `json:"params"`
		}{
			ToolName: frames[i].toolName,
			Params:   cur,
		})
		if err != nil {
			return cur
		}
		cur = wrapped
	}
	return cur
}

// execOne resolves, permission-checks, and runs a single tool call, returning a
// tool_result block and any extra messages the tool injects after its result
// (Result.Extra — e.g. the Skill tool's instructions message). It never panics;
// failures become error results. It is safe to call from the streaming
// executor's goroutines (read-only access to loop config; permission/hook
// callbacks are the host's responsibility to make safe).
func (l *loop) execOne(toolCtx context.Context, use llm.ContentBlock, emitProgress func(tool.ProgressInfo)) (llm.ContentBlock, []llm.Message) {
	if l.settling.Load() && l.in.Settlement != nil {
		name, _, _, depthExceeded := unwrapExtraTool(use.Name, use.Input)
		blocked := depthExceeded || name == tool.ExecuteExtraToolName
		for _, disabled := range l.in.Settlement.DisabledTools {
			if name == disabled {
				blocked = true
			}
		}
		if blocked {
			r := tool.Fail("settlement_tool_disabled", "收尾阶段该工具不可执行。", "保存已有事实和证据，并输出最终汇报；需要继续探索时请求追加预算。")
			return llm.ToolResultText(use.ID, r.Flatten(), true), nil
		}
	}
	t, ok := l.in.Tools.Get(use.Name)
	if !ok {
		return llm.ToolResultText(use.ID, fmt.Sprintf("Error: unknown tool %q", use.Name), true), nil
	}
	input := use.Input
	rawInput := acceptsRawInput(t)
	// Empty arguments mean "no arguments", which is a complete call — host
	// providers may omit the field entirely. A raw-input tool decides that for
	// itself and receives the bytes verbatim ("" is not "{}" to its parser).
	// Arguments that are not valid JSON can only be here because the model's
	// call was cut off or mangled and the transport let it through for a
	// raw-input tool — or because a host-supplied provider skipped its own
	// check. Either way they must never reach a tool that did not opt in: the
	// call did not complete, so executing it would be executing something the
	// model never finished saying.
	malformed := false
	if len(bytes.TrimSpace(input)) == 0 {
		if !rawInput {
			input = json.RawMessage("{}")
		}
	} else {
		malformed = !json.Valid(input)
		if malformed && !rawInput {
			return llm.ToolResultText(use.ID, invalidInputMessage, true), nil
		}
	}

	// Schema validation (FR-04.5).
	//
	// A tool may opt out by reporting AcceptsRawInput: it parses its own
	// arguments and would rather repair a malformed call than have it rejected
	// here, where the only possible answer is a generic error. The schema is
	// still advertised to the model either way — see tool.Spec.RawInput.
	if !rawInput {
		if err := tool.ValidateInput(t.InputSchema(), input); err != nil {
			return llm.ToolResultText(use.ID, "Error: invalid tool input: "+err.Error(), true), nil
		}
	}

	mode := l.in.PermissionMode
	if l.in.PermissionModeFunc != nil {
		mode = l.in.PermissionModeFunc()
	}
	pc := permission.Context{
		Mode:       mode,
		WorkingDir: l.in.WorkingDir,
		Allowed:    l.in.Allowed,
		Disallowed: l.in.Disallowed,
	}

	// Unwrap ExecuteExtraTool at the permission and hook choke point so target
	// tool rules (DisallowedTools, CheckPermissions, ModePlan read-only checks,
	// CanUseTool, PreToolUse, PostToolUse) always apply to the real target tool.
	effName, effTool, effInput := use.Name, t, input
	var wrapFrames []extraWrapFrame
	if use.Name == tool.ExecuteExtraToolName {
		// Honor an explicit Disallowed rule targeting ExecuteExtraTool itself
		// without letting its non-read-only wrapper block read-only targets in ModePlan.
		outerPC := pc
		outerPC.Mode = permission.ModeBypass
		if outerDec := permission.Evaluate(l.ctx, permission.Request{
			ToolName:     use.Name,
			Input:        input,
			IsReadOnly:   false,
			ToolDecision: t.CheckPermissions(l.ctx, input, outerPC),
			Ctx:          outerPC,
		}); outerDec.Behavior != permission.Allow {
			msg := outerDec.Message
			if msg == "" {
				msg = "denied"
			}
			return llm.ToolResultText(use.ID, "Tool call was not permitted: "+msg, true), nil
		}

		unwrappedName, unwrappedInput, frames, depthExceeded := unwrapExtraTool(use.Name, input)
		if depthExceeded {
			return llm.ToolResultText(use.ID, "Tool call was not permitted: nested ExecuteExtraTool depth limit exceeded", true), nil
		}
		if len(frames) > 0 {
			wrapFrames = frames
			effName = unwrappedName
			effInput = unwrappedInput
			if target, found := l.in.Tools.Get(effName); found {
				effTool = target
				if !acceptsRawInput(effTool) && !json.Valid(effInput) {
					return llm.ToolResultText(use.ID, invalidInputMessage, true), nil
				}
			} else {
				effTool = nil
			}
		}
	}

	var isReadOnly bool
	var toolDec permission.Decision
	if effTool != nil {
		isReadOnly = effTool.IsReadOnly(effInput)
		toolDec = effTool.CheckPermissions(l.ctx, effInput, pc)
	} else {
		toolDec = permission.AskUser("run tool: " + effName)
	}
	dec := permission.Evaluate(l.ctx, permission.Request{
		ToolName:     effName,
		Input:        effInput,
		IsReadOnly:   isReadOnly,
		ToolDecision: toolDec,
		Ctx:          pc,
		Ask:          l.in.CanUseTool,
	})
	if dec.Behavior != permission.Allow {
		msg := dec.Message
		if msg == "" {
			msg = "denied"
		}
		return llm.ToolResultText(use.ID, "Tool call was not permitted: "+msg, true), nil
	}
	if len(dec.UpdatedInput) > 0 {
		effInput = dec.UpdatedInput
	}

	// Pre-tool hook.
	if l.in.Hooks != nil {
		if block, msg, updated := l.in.Hooks.PreToolUse(l.ctx, effName, effInput); block {
			return llm.ToolResultText(use.ID, "Blocked by hook: "+msg, true), nil
		} else if len(updated) > 0 {
			effInput = updated
		}
	}

	callInput := effInput
	if len(wrapFrames) > 0 {
		callInput = rewrapExtraTool(wrapFrames, effInput)
	}

	tc := &tool.ToolContext{
		WorkingDir:     l.in.WorkingDir,
		AgentID:        l.in.AgentID,
		ToolUseID:      use.ID,
		Emit:           emitProgress,
		OutputDir:      l.in.ToolOutputDir,
		MaxOutputChars: l.in.MaxToolOutputChars,
		Tasks:          l.in.Tasks,
		Env:            l.in.BashEnv,
		InputMalformed: malformed,
	}
	// toolCtx carries the run's MaxDuration deadline, so a tool that overruns the
	// wall-clock budget is interrupted here (the turn loop then enters wrap-up). During
	// the wrap-up phase toolCtx is the live parent ctx, so settlement tools run freely.
	res, err := t.Call(toolCtx, callInput, tc)
	if err != nil {
		if tool.IsFatalExecution(err) && l.cancelRun != nil {
			l.cancelRun(err)
		}
		res = tool.Errorf("Error: " + err.Error())
	}
	res = tool.NormalizeError(res, isReadOnly)
	// Global output cap at the single post-tool choke point: EVERY tool —
	// built-in, MCP, custom, host — is bounded here regardless of whether it
	// remembered to Capture itself, so no tool can overflow the context window
	// (the failure mode that motivated this net). CaptureOnce is idempotent:
	// output a tool already spilled/truncated carries a marker and is left
	// untouched, so this never double-truncates or double-spills.
	res = tool.CapToolResult(effName, tc, res)

	if l.in.Hooks != nil {
		raw, _ := json.Marshal(res.Flatten())
		l.in.Hooks.PostToolUse(l.ctx, effName, effInput, raw, res.IsError)
	}

	content := res.Content
	if len(content) == 0 {
		content = []llm.ContentBlock{llm.TextBlock("(no output)")}
	}
	return llm.ContentBlock{Type: llm.BlockToolResult, ToolUseID: use.ID, Content: content, IsError: res.IsError}, res.Extra
}

// invalidInputMessage tells the model exactly what went wrong and that nothing
// ran. Vague validation errors make it repeat the same oversized call.
const invalidInputMessage = "Error: invalid or unfinished tool input: the arguments were not complete JSON, " +
	"so this call was NOT executed. Re-send it with complete arguments. If the reply was cut off by the " +
	"output limit, produce less in one call — split the work into smaller calls."

// capOutput runs every text block of a tool result through the idempotent
// output cap (tool.CaptureOnce). Non-text blocks pass through untouched. It is
// the one place that guarantees no tool's output — however constructed — can
// blow past the context budget.
func capOutput(tc *tool.ToolContext, res tool.Result) tool.Result {
	return tool.CapResult(tc, res)
}
