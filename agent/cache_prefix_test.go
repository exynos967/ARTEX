package agent

import (
	"context"
	"encoding/json"
	"iter"
	"net/http"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/RC-CHN/ARTEX/db"
	"github.com/RC-CHN/ARTEX/norma/agentcore"
	"github.com/RC-CHN/ARTEX/norma/compaction"
	"github.com/RC-CHN/ARTEX/norma/llm"
	"github.com/RC-CHN/ARTEX/norma/noa"
	"github.com/RC-CHN/ARTEX/norma/permission"
	actool "github.com/RC-CHN/ARTEX/norma/tool"
	"github.com/RC-CHN/ARTEX/norma/transcript"
)

func TestWorkerStaticPrefixByteIdenticalAcrossIntentsAndRunners(t *testing.T) {
	oldOverride, oldEnv := PromptOverride, EnvironmentPrompt
	t.Cleanup(func() { PromptOverride, EnvironmentPrompt = oldOverride, oldEnv })
	EnvironmentPrompt = nil
	PromptOverride = func(key string) (string, bool) {
		if key == "worker" {
			return "Worker static rules. Proxy={{.ProxyAddr}} Time={{.Now}}", true
		}
		return "", false
	}

	intentA := &db.Node{ID: 101, Payload: json.RawMessage(`{"summary":"probe https://a.example.com/login","asset_ids":[10]}`)}
	intentB := &db.Node{ID: 202, Payload: json.RawMessage(`{"summary":"probe https://b.example.com/admin","asset_ids":[20]}`)}

	assetsA := []*db.Asset{{ID: 10, Type: "service", URL: "https://a.example.com/login", LastSeen: "2026-11-24T10:00:00Z"}}
	assetsB := []*db.Asset{{ID: 20, Type: "service", URL: "https://b.example.com/admin", LastSeen: "2026-11-24T11:00:00Z"}}

	defA := DeferredInfo{
		FindingGuidance:   "\n\n[shared-finding-guidance]",
		ExecutionGuidance: "\n\n本线程的执行工具在独立远程沙箱中运行。当前环境：linux；节点：runner-alpha\n当前工作目录（默认 CWD）：\"/work/tasks/7/i101\"",
		GlobalNames:       []string{"mcp__browser__navigate"},
	}
	defB := DeferredInfo{
		FindingGuidance:   "\n\n[shared-finding-guidance]",
		ExecutionGuidance: "\n\n本线程的执行工具在独立远程沙箱中运行。当前环境：linux；节点：runner-beta\n当前工作目录（默认 CWD）：\"/work/tasks/7/i202\"",
		GlobalNames:       []string{"mcp__browser__navigate"},
	}

	sysA, boundA := buildWorkerSystemPrompt("127.0.0.1:8080", "/ca.pem", "/data", "/data/tasks/7/i101", "\n\n【操作约束】：禁止扫描 22 端口", intentA, assetsA, defA)
	sysB, boundB := buildWorkerSystemPrompt("127.0.0.1:8080", "/ca.pem", "/data", "/data/tasks/7/i202", "\n\n【操作约束】：仅测 443 端口", intentB, assetsB, defB)

	if boundA != 2 || boundB != 2 {
		t.Fatalf("unexpected DynamicBoundary: A=%d B=%d (want 2: static body + deferred tools block)", boundA, boundB)
	}
	prefixA := strings.Join(sysA[:boundA], "\n")
	prefixB := strings.Join(sysB[:boundB], "\n")
	if prefixA != prefixB {
		t.Fatalf("concurrent workers produced different cached static prefixes:\n---A---\n%s\n---B---\n%s", prefixA, prefixB)
	}
	for _, forbidden := range []string{"i101", "i202", "runner-alpha", "runner-beta", "a.example.com", "b.example.com", "禁止扫描", "仅测 443"} {
		if strings.Contains(prefixA, forbidden) {
			t.Fatalf("per-intent/dynamic token %q leaked into static cached prefix:\n%s", forbidden, prefixA)
		}
	}
	if !strings.Contains(prefixA, "[shared-finding-guidance]") || !strings.Contains(prefixA, "<available-deferred-tools>") {
		t.Fatalf("static prefix missing finding guidance or deferred tools block:\n%s", prefixA)
	}

	dynA := strings.Join(sysA[boundA:], "\n")
	dynB := strings.Join(sysB[boundB:], "\n")
	for _, want := range []string{"i101", "runner-alpha", "a.example.com/login", "意图 id: 101", "禁止扫描 22 端口", "本轮时间说明："} {
		if !strings.Contains(dynA, want) {
			t.Fatalf("worker A dynamic suffix missing %q:\n%s", want, dynA)
		}
	}
	for _, want := range []string{"i202", "runner-beta", "b.example.com/admin", "意图 id: 202", "仅测 443 端口", "本轮时间说明："} {
		if !strings.Contains(dynB, want) {
			t.Fatalf("worker B dynamic suffix missing %q:\n%s", want, dynB)
		}
	}
}

func TestWorkerPromptAssetsDeterministicRegardlessOfLastSeenAndOrder(t *testing.T) {
	status := 200
	a1First := &db.Asset{
		ID:           10,
		Type:         "service",
		URL:          "https://app.example.com",
		StatusCode:   &status,
		TaskIDs:      []int64{9, 3},
		Technologies: []string{"nginx", "go"},
		Extra:        map[string]any{"banner": "ok", "updated_at": "2026-11-24T10:00:00Z", "last_seen": "2026-11-24T10:00:00Z"},
		LastSeen:     "2026-11-24T10:00:00Z",
	}
	a2First := &db.Asset{
		ID:       20,
		Type:     "subdomain",
		Domain:   "api.example.com",
		TaskIDs:  []int64{3},
		Extra:    map[string]any{"updated_at": "2026-11-24T10:00:00Z"},
		LastSeen: "2026-11-24T10:00:01Z",
	}

	a1Later := &db.Asset{
		ID:           10,
		Type:         "service",
		URL:          "https://app.example.com",
		StatusCode:   &status,
		TaskIDs:      []int64{3, 9},
		Technologies: []string{"go", "nginx"},
		Extra:        map[string]any{"banner": "ok", "updated_at": "2026-11-24T12:34:56Z", "last_seen": "2026-11-24T12:34:56Z"},
		LastSeen:     "2026-11-24T12:34:56Z",
	}
	a2Later := &db.Asset{
		ID:       20,
		Type:     "subdomain",
		Domain:   "api.example.com",
		TaskIDs:  []int64{3},
		Extra:    nil, // only updated_at was present earlier → should serialize identically once stripped
		LastSeen: "2026-11-24T12:35:00Z",
	}

	b1, err := marshalWorkerPromptAssets([]*db.Asset{a2First, a1First})
	if err != nil {
		t.Fatal(err)
	}
	b2, err := marshalWorkerPromptAssets([]*db.Asset{a1Later, a2Later})
	if err != nil {
		t.Fatal(err)
	}
	if string(b1) != string(b2) {
		t.Fatalf("worker prompt assets drifted across last_seen/order mutations:\n1: %s\n2: %s", b1, b2)
	}
	if strings.Contains(string(b1), "last_seen") || strings.Contains(string(b1), "updated_at") {
		t.Fatalf("volatile timestamps survived serialization: %s", b1)
	}
	if !strings.Contains(string(b1), `"banner":"ok"`) {
		t.Fatalf("non-volatile extra field was dropped: %s", b1)
	}
	if strings.Index(string(b1), `"id":10`) > strings.Index(string(b1), `"id":20`) {
		t.Fatalf("assets were not sorted by id ASC: %s", b1)
	}
}

func TestEnableNoaForwardsModelContextLimitAndPreservesDynamicBoundary(t *testing.T) {
	opts := agentcore.Options{
		SystemPrompt:    []string{"static-role", "deferred-tools", "dynamic-per-intent"},
		DynamicBoundary: 2,
		Compaction:      &compaction.Config{ContextWindow: 64000},
	}
	sess := enableNoaSession(&opts, func() bool { return true }, t.TempDir(), "exp1-worker-i42", nil)
	if sess == nil {
		t.Fatal("expected noa session to be enabled")
	}
	if got := sess.Config().ModelContextLimit; got != 64000 {
		t.Fatalf("ModelContextLimit = %d, want 64000 (from opts.Compaction.ContextWindow)", got)
	}
	if opts.Compaction != nil {
		t.Fatal("opts.Compaction must be cleared when noa is enabled")
	}
	if opts.Compactor == nil {
		t.Fatal("opts.Compactor must be installed when noa is enabled")
	}
	if opts.DynamicBoundary != 3 || len(opts.SystemPrompt) != 4 {
		t.Fatalf("expected noa prompt spliced before dynamic segment: boundary=%d len=%d", opts.DynamicBoundary, len(opts.SystemPrompt))
	}
	if !strings.Contains(opts.SystemPrompt[2], noa.SystemPromptHeader) {
		t.Fatalf("expected noa resident prompt at index 2 (before boundary), got %q", opts.SystemPrompt[2])
	}
	if opts.SystemPrompt[3] != "dynamic-per-intent" {
		t.Fatalf("dynamic segment lost or moved before boundary: %q", opts.SystemPrompt[3])
	}
}

type recordingRequestProvider struct {
	reqs    []llm.CompletionRequest
	respond func(idx int, req llm.CompletionRequest) (llm.Message, string, llm.Usage, error)
}

func (p *recordingRequestProvider) Complete(_ context.Context, req llm.CompletionRequest) (llm.Message, string, llm.Usage, error) {
	idx := len(p.reqs)
	p.reqs = append(p.reqs, req)
	if p.respond != nil {
		return p.respond(idx, req)
	}
	return llm.Message{Role: llm.RoleAssistant, Content: []llm.ContentBlock{llm.TextBlock("ok")}}, "end_turn", llm.Usage{}, nil
}

func (p *recordingRequestProvider) Stream(ctx context.Context, req llm.CompletionRequest) iter.Seq2[llm.StreamEvent, error] {
	return func(yield func(llm.StreamEvent, error) bool) {
		msg, stop, usage, err := p.Complete(ctx, req)
		if err != nil {
			yield(llm.StreamEvent{}, err)
			return
		}
		for _, b := range msg.Content {
			switch b.Type {
			case llm.BlockText:
				if !yield(llm.StreamEvent{Type: llm.SETextDelta, Text: b.Text}, nil) {
					return
				}
			case llm.BlockToolUse:
				if !yield(llm.StreamEvent{Type: llm.SEToolUseStart, ToolID: b.ID, ToolName: b.Name}, nil) {
					return
				}
				if !yield(llm.StreamEvent{Type: llm.SEToolInputJSON, Text: string(b.Input)}, nil) {
					return
				}
			}
		}
		if yield(llm.StreamEvent{Type: llm.SEMessageDelta, StopReason: stop, Usage: usage}, nil) {
			yield(llm.StreamEvent{Type: llm.SEMessageStop}, nil)
		}
	}
}

func TestGoalsSetsDynamicBoundaryAndSeparatesClock(t *testing.T) {
	oldOverride := PromptOverride
	t.Cleanup(func() { PromptOverride = oldOverride })
	PromptOverride = func(key string) (string, bool) {
		if key == "goals" {
			return "Decompose goals cleanly. Clock={{.Now}}", true
		}
		return "", false
	}
	prov := &recordingRequestProvider{}
	_ = DecomposeGoalsWithProvider(t.Context(), prov, "/data", "find flag", "lab target", nil, nil, 0, true, 0, nil)
	if len(prov.reqs) != 1 {
		t.Fatalf("expected 1 completion request, got %d", len(prov.reqs))
	}
	req := prov.reqs[0]
	if req.DynamicBoundary != 1 || len(req.System) != 2 {
		t.Fatalf("goals prompt not split at DynamicBoundary: boundary=%d system=%v", req.DynamicBoundary, req.System)
	}
	if strings.Contains(req.System[0], dynamicTimeStart) || strings.Contains(req.System[0], time.Now().Format("2006-")) {
		t.Fatalf("clock leaked into cached goals static prefix: %q", req.System[0])
	}
	if !strings.Contains(req.System[1], "本轮时间说明：") {
		t.Fatalf("clock missing from goals dynamic segment: %q", req.System[1])
	}
}

func TestCompactorCompressSetsDynamicBoundary(t *testing.T) {
	prov := &recordingRequestProvider{
		respond: func(int, llm.CompletionRequest) (llm.Message, string, llm.Usage, error) {
			return llm.Message{Role: llm.RoleAssistant, Content: []llm.ContentBlock{llm.TextBlock("digest summary")}}, "end_turn", llm.Usage{}, nil
		},
	}
	c := NewCompactor(prov, "test-model")
	g := newColdGraph([]cgNode{{ID: 1, Kind: db.KindFact}, {ID: 2, Kind: db.KindFact}}, nil)
	nodes := map[int64]*db.Node{
		1: {ID: 1, Kind: db.KindFact, Payload: json.RawMessage(`{"summary":"fact 1"}`)},
		2: {ID: 2, Kind: db.KindFact, Payload: json.RawMessage(`{"summary":"fact 2"}`)},
	}
	body, err := c.compress(t.Context(), g, block{Members: []int64{1, 2}}, nodes)
	if err != nil || body != "digest summary" {
		t.Fatalf("compress failed: body=%q err=%v", body, err)
	}
	if len(prov.reqs) != 1 || prov.reqs[0].DynamicBoundary != len(prov.reqs[0].System) || prov.reqs[0].DynamicBoundary != 1 {
		t.Fatalf("compactor compress did not set DynamicBoundary=1: %+v", prov.reqs)
	}
}

func TestQuotaAwareHTTPClientTransportPoolSettings(t *testing.T) {
	client, err := quotaAwareHTTPClient("", "")
	if err != nil {
		t.Fatal(err)
	}
	qt, ok := client.Transport.(quotaAwareTransport)
	if !ok {
		t.Fatalf("unexpected transport type %T", client.Transport)
	}
	tr, ok := qt.base.(*http.Transport)
	if !ok {
		t.Fatalf("unexpected base transport type %T", qt.base)
	}
	if tr.MaxIdleConnsPerHost != 32 {
		t.Fatalf("MaxIdleConnsPerHost = %d, want 32", tr.MaxIdleConnsPerHost)
	}
	if tr.IdleConnTimeout != 60*time.Second {
		t.Fatalf("IdleConnTimeout = %v, want 60s", tr.IdleConnTimeout)
	}
	if tr.TLSHandshakeTimeout != 10*time.Second {
		t.Fatalf("TLSHandshakeTimeout = %v, want 10s", tr.TLSHandshakeTimeout)
	}
}

func TestPlannerResumesSendsIncrementalDeltaUnlocksSkillsAndRotates(t *testing.T) {
	dir := t.TempDir()
	tx := transcript.NewStore(filepath.Join(dir, "transcripts"))
	skillTool := actool.Build(actool.Spec{
		Name:   "Skill",
		Schema: obj(map[string]any{"name": str("skill name")}),
		Run: func(_ context.Context, in json.RawMessage, _ *actool.ToolContext) (actool.Result, error) {
			return actool.Text("skill loaded"), nil
		},
	})

	call := 0
	prov := &recordingRequestProvider{
		respond: func(_ int, _ llm.CompletionRequest) (llm.Message, string, llm.Usage, error) {
			call++
			if call == 1 {
				// Round 1, turn 1: invoke Skill("recon") so round 2 can prove seedUnlockFromHistory runs.
				return llm.Message{
					Role: llm.RoleAssistant,
					Content: []llm.ContentBlock{{
						Type:  llm.BlockToolUse,
						ID:    "toolu_skill_1",
						Name:  "Skill",
						Input: json.RawMessage(`{"name":"recon"}`),
					}},
				}, "tool_use", llm.Usage{}, nil
			}
			return llm.Message{
				Role:    llm.RoleAssistant,
				Content: []llm.ContentBlock{llm.TextBlock("planned")},
			}, "end_turn", llm.Usage{}, nil
		},
	}

	p := NewPlanner(prov, "test-model", dir, tx, 200000, 5)
	const expID int64 = 99

	baseOverview := map[string]any{
		"task":                map[string]any{"description": "full engagement desc", "goal": "capture flag"},
		"related_tasks":       []map[string]any{{"task_id": 1, "summary": "inherited huge blackboard"}},
		"cold_digests":        []map[string]any{{"id": 50, "body": "historical cold digest"}},
		"goals":               []map[string]any{{"id": 1, "state": "open", "text": "capture flag"}},
		"open_intents":        []map[string]any{{"id": 10, "summary": "scan port 80"}},
		"running_intents":     []map[string]any{},
		"frontier_open":       1,
		"findings_total":      0,
		"facts":               2,
		"recent_facts":        []map[string]any{{"id": 2, "summary": "http open"}},
		"recent_done_intents": []map[string]any{},
		"finding_list":        []map[string]any{},
		"coverage": map[string]any{
			"pct":         25.0,
			"tested":      1,
			"denominator": 4,
			"host_count":  1,
			"note":        "verbose coverage note only needed on baseline",
		},
	}

	var unlocked []string
	def := DeferredInfo{
		UnlockSkill: func(name string) { unlocked = append(unlocked, name) },
	}
	opts := agentcore.Options{
		Provider:       prov,
		SystemPrompt:   []string{"planner static prompt"},
		DynamicBoundary: 1,
		Tools:          []actool.CoreTool{skillTool},
		PermissionMode: permission.ModeBypass,
		MaxTurns:       5,
		Todos:          p.todoFor(expID),
		NonStreaming:   true,
	}

	// Round 1: fresh transcript → full graph_overview briefing.
	if _, err := p.runPlannerSession(t.Context(), expID, opts, def, "lead-r1", "", baseOverview, "", nil); err != nil {
		t.Fatalf("round 1 failed: %v", err)
	}
	if len(prov.reqs) != 2 {
		t.Fatalf("round 1 expected 2 model turns (tool + final), got %d", len(prov.reqs))
	}
	if len(prov.reqs[0].Messages) < 2 {
		t.Fatalf("round 1 expected [system-reminder, user], got %d messages", len(prov.reqs[0].Messages))
	}
	round1Msg0 := prov.reqs[0].Messages[0].Text()
	round1User := prov.reqs[0].Messages[1].Text()
	for _, want := range []string{"graph_overview 预取", "full engagement desc", "inherited huge blackboard", "historical cold digest"} {
		if !strings.Contains(round1User, want) {
			t.Fatalf("round 1 baseline missing %q:\n%s", want, round1User)
		}
	}
	if len(unlocked) != 0 {
		t.Fatalf("round 1 should not seed unlock from empty history, got %v", unlocked)
	}

	// Round 2: resumes exp99-planner, keeps Messages[0..1] byte-identical, unlocks prior Skill, sends compact delta.
	updatedOverview := map[string]any{
		"task":                map[string]any{"description": "full engagement desc", "goal": "capture flag"},
		"related_tasks":       []map[string]any{{"task_id": 1, "summary": "inherited huge blackboard"}},
		"cold_digests":        []map[string]any{{"id": 50, "body": "historical cold digest"}},
		"goals":               []map[string]any{{"id": 1, "state": "open", "text": "capture flag"}},
		"open_intents":        []map[string]any{},
		"running_intents":     []map[string]any{},
		"frontier_open":       0,
		"findings_total":      1,
		"facts":               3,
		"finding_list":        []map[string]any{{"id": 33, "summary": "sqli confirmed"}},
		"recent_facts":        []map[string]any{{"id": 3, "summary": "sqli dump ok"}},
		"recent_done_intents": []map[string]any{{"id": 10, "summary": "scan port 80", "state": "done"}},
		"coverage": map[string]any{
			"pct":         50.0,
			"tested":      2,
			"denominator": 4,
			"host_count":  1,
			"note":        "verbose coverage note only needed on baseline",
		},
	}
	if _, err := p.runPlannerSession(t.Context(), expID, opts, def, "lead-r2", "\n\n【trigger: intent #10 done】", updatedOverview, "", nil); err != nil {
		t.Fatalf("round 2 failed: %v", err)
	}
	if len(prov.reqs) != 3 {
		t.Fatalf("round 2 expected 1 additional model call (total 3), got %d", len(prov.reqs))
	}
	req2 := prov.reqs[2]
	if len(req2.Messages) <= 2 {
		t.Fatalf("round 2 did not resume prior transcript: messages=%d", len(req2.Messages))
	}
	if req2.Messages[0].Text() != round1Msg0 || req2.Messages[1].Text() != round1User {
		t.Fatalf("round 2 mutated baseline messages[0..1], breaking prompt cache prefix")
	}
	if len(unlocked) != 1 || unlocked[0] != "recon" {
		t.Fatalf("round 2 did not re-unlock prior skill via seedUnlockFromHistory: got %v", unlocked)
	}
	deltaMsg := req2.Messages[len(req2.Messages)-1].Text()
	for _, want := range []string{"本轮增量态势摘要", "graph_overview", "node_detail", "sqli confirmed", "trigger: intent #10 done"} {
		if !strings.Contains(deltaMsg, want) {
			t.Fatalf("round 2 incremental delta missing %q:\n%s", want, deltaMsg)
		}
	}
	for _, omitted := range []string{"inherited huge blackboard", "historical cold digest", "verbose coverage note only needed on baseline"} {
		if strings.Contains(deltaMsg, omitted) {
			t.Fatalf("round 2 incremental delta should omit heavy baseline field %q:\n%s", omitted, deltaMsg)
		}
	}

	// Round 3: after a compact boundary lands in exp99-planner, Planner rotates cleanly to exp99-planner-r1
	// and sends a fresh full graph_overview baseline.
	boundaryMsg := llm.BoundaryMessage(llm.BoundaryMeta{Trigger: "auto", PreTokens: 150000})
	if err := tx.Append(tx.MainPath(plannerSessionID(expID, 0)), transcript.Record{
		UUID: "b1", SessionID: plannerSessionID(expID, 0), Type: "message", Message: &boundaryMsg,
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := p.runPlannerSession(t.Context(), expID, opts, def, "lead-r3", "", updatedOverview, "", nil); err != nil {
		t.Fatalf("round 3 failed: %v", err)
	}
	if len(prov.reqs) != 4 {
		t.Fatalf("round 3 expected 1 additional model call (total 4), got %d", len(prov.reqs))
	}
	req3 := prov.reqs[3]
	if len(req3.Messages) != 2 {
		t.Fatalf("round 3 after compact boundary should rotate to a fresh session ([system-reminder, user]), got %d messages", len(req3.Messages))
	}
	if !strings.Contains(req3.Messages[1].Text(), "graph_overview 预取") {
		t.Fatalf("rotated planner session did not send fresh full baseline:\n%s", req3.Messages[1].Text())
	}
	if got := p.plannerEpoch(expID); got != 1 {
		t.Fatalf("planner epoch = %d, want 1 after rotation", got)
	}
}

func TestShouldRotatePlannerSessionBounds(t *testing.T) {
	if shouldRotatePlannerSession(nil) {
		t.Fatal("empty history must not rotate")
	}
	pair := []llm.Message{
		llm.UserText("u"),
		{Role: llm.RoleAssistant, Content: []llm.ContentBlock{llm.TextBlock("a")}},
	}
	if shouldRotatePlannerSession(pair) {
		t.Fatal("short complete history must resume, not rotate")
	}
	if !shouldRotatePlannerSession([]llm.Message{llm.UserText("crashed before reply")}) {
		t.Fatal("trailing user turn must rotate cleanly")
	}
	longHistory := make([]llm.Message, 0, plannerMaxSessionMessages)
	for len(longHistory) < plannerMaxSessionMessages {
		longHistory = append(longHistory, pair...)
	}
	if !shouldRotatePlannerSession(longHistory) {
		t.Fatalf("history reaching %d messages must rotate", plannerMaxSessionMessages)
	}
}
