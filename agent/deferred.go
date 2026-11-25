package agent

import (
	"encoding/json"
	"strings"

	"github.com/RC-CHN/ARTEX/norma/llm"
	actool "github.com/RC-CHN/ARTEX/norma/tool"
)

// isDynamicExecutionGuidance reports whether ExecutionGuidance carries per-node
// or per-intent remote runner details that must sit after DynamicBoundary so
// concurrent workers still share the static cached prefix. Local host toolenv
// inventories stay static before the boundary.
func isDynamicExecutionGuidance(guidance string) bool {
	return strings.Contains(guidance, "独立远程沙箱") ||
		strings.Contains(guidance, "；节点：") ||
		strings.Contains(guidance, "当前工作目录（默认 CWD）")
}

// deferredSystem builds an agent's system-prompt segments and cache boundary from
// its DeferredInfo. When globally-available MCP tools are present, their names + a
// "prefer core tools" instruction render into a <available-deferred-tools> block
// placed as the LAST static system-prompt segment, with DynamicBoundary set so the
// whole static prefix — including the block — is cached (design doc §2.1 / C1).
// Skill-gated MCP names are NOT in this block; they surface when their skill loads.
// The stable system prefix is cached even without a global block; per-node remote
// execution guidance and per-turn time, when present, follow the boundary.
func deferredSystem(sysText string, def DeferredInfo) (system []string, boundary int) {
	return deferredSystemWithDynamic(sysText, def)
}

// deferredSystemWithDynamic splits the system prompt at DynamicBoundary: staticBody
// + FindingGuidance (+ local static ExecutionGuidance) + <available-deferred-tools>
// stay BEFORE DynamicBoundary for cross-worker/cross-turn prompt cache reuse, while
// per-node remote ExecutionGuidance, caller-supplied dynamicBlocks (e.g. per-intent
// runDir/mandate/assets or mutable constraints), and <artex-dynamic-time> follow
// AFTER DynamicBoundary (still in system prompt, immune to conversation compaction).
func deferredSystemWithDynamic(sysText string, def DeferredInfo, dynamicBlocks ...string) (system []string, boundary int) {
	dynamicTime := ""
	if start := strings.Index(sysText, dynamicTimeStart); start >= 0 {
		if end := strings.Index(sysText[start+len(dynamicTimeStart):], dynamicTimeEnd); end >= 0 {
			end += start + len(dynamicTimeStart)
			dynamicTime = sysText[start+len(dynamicTimeStart) : end]
			sysText = sysText[:start] + sysText[end+len(dynamicTimeEnd):]
		}
	}
	sysText += def.FindingGuidance
	dynamicExec := ""
	if def.ExecutionGuidance != "" {
		if isDynamicExecutionGuidance(def.ExecutionGuidance) {
			dynamicExec = strings.TrimLeft(def.ExecutionGuidance, "\r\n")
		} else {
			sysText += def.ExecutionGuidance
		}
	}
	block := actool.RenderDeferredToolsBlock(def.GlobalNames)
	system = []string{sysText}
	if block != "" {
		system = append(system, block)
	}
	boundary = len(system) // b >= len → whole system prompt cached (SDK guard)
	if dynamicExec != "" {
		system = append(system, dynamicExec)
	}
	for _, blk := range dynamicBlocks {
		if strings.TrimSpace(blk) == "" {
			continue
		}
		system = append(system, strings.TrimLeft(blk, "\r\n"))
	}
	if dynamicTime != "" {
		system = append(system, dynamicTime)
	}
	return system, boundary
}

// seedUnlockFromHistory replays prior Skill() invocations in the conversation so
// their skill-gated MCPs are re-unlocked on a resumed session (design doc C2). The
// main agent builds a fresh session each turn; its in-memory unlock set would
// otherwise reset, leaving the model able to see a skill-revealed tool name yet
// unable to call it. No-op when unlockSkill is nil (no deferred tools).
func seedUnlockFromHistory(msgs []llm.Message, unlockSkill func(string)) {
	if unlockSkill == nil {
		return
	}
	for _, m := range msgs {
		for _, b := range m.ToolUses() {
			if b.Name != "Skill" {
				continue
			}
			var in struct {
				Name string `json:"name"`
			}
			if json.Unmarshal(b.Input, &in) == nil && in.Name != "" {
				unlockSkill(in.Name)
			}
		}
	}
}
