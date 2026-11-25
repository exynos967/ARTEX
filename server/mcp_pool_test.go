package server

import (
	"context"
	"encoding/json"
	"errors"
	"iter"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/RC-CHN/ARTEX/db"
	"github.com/RC-CHN/ARTEX/norma/agentcore"
	"github.com/RC-CHN/ARTEX/norma/harness"
	"github.com/RC-CHN/ARTEX/norma/llm"
	"github.com/RC-CHN/ARTEX/norma/permission"
	"github.com/RC-CHN/ARTEX/norma/skill"
	actool "github.com/RC-CHN/ARTEX/norma/tool"
)

type fakeMCPClient struct {
	mu       sync.Mutex
	tools    []actool.CoreTool
	listErr  error
	listCnt  atomic.Int32
	closed   atomic.Int32
	onClose  func()
}

func (f *fakeMCPClient) Tools(ctx context.Context) ([]actool.CoreTool, error) {
	f.listCnt.Add(1)
	f.mu.Lock()
	err := f.listErr
	tools := f.tools
	f.mu.Unlock()
	if err != nil {
		return nil, err
	}
	return tools, nil
}

func (f *fakeMCPClient) Close() error {
	if f.closed.Add(1) == 1 && f.onClose != nil {
		f.onClose()
	}
	return nil
}

func makeFakePlaywrightTools(tag string, failFirstCall *atomic.Bool) []actool.CoreTool {
	return []actool.CoreTool{
		actool.Build(actool.Spec{
			Name:        "mcp__playwright__navigate",
			Description: "Navigate browser to URL (" + tag + ")",
			Schema: map[string]any{
				"type":       "object",
				"properties": map[string]any{"url": map[string]any{"type": "string"}},
				"required":   []any{"url"},
			},
			Permissions: func(context.Context, json.RawMessage, permission.Context) permission.Decision {
				return permission.Allowed()
			},
			Run: func(_ context.Context, in json.RawMessage, _ *actool.ToolContext) (actool.Result, error) {
				if failFirstCall != nil && failFirstCall.CompareAndSwap(true, false) {
					return actool.Errorf("Error: mcp: connection closed"), nil
				}
				var a struct {
					URL string `json:"url"`
				}
				_ = json.Unmarshal(in, &a)
				return actool.Text(tag + ":navigated:" + a.URL), nil
			},
		}),
		actool.Build(actool.Spec{
			Name:        "mcp__playwright__click",
			Description: "Click an element (" + tag + ")",
			Schema: map[string]any{
				"type":       "object",
				"properties": map[string]any{"selector": map[string]any{"type": "string"}},
				"required":   []any{"selector"},
			},
			Permissions: func(context.Context, json.RawMessage, permission.Context) permission.Decision {
				return permission.Allowed()
			},
			Run: func(_ context.Context, _ json.RawMessage, _ *actool.ToolContext) (actool.Result, error) {
				return actool.Text(tag + ":clicked"), nil
			},
		}),
	}
}

func fakeToolTurn(id, name, argsJSON string) []llm.StreamEvent {
	return []llm.StreamEvent{
		{Type: llm.SEToolUseStart, ToolID: id, ToolName: name},
		{Type: llm.SEToolInputJSON, Text: argsJSON},
		{Type: llm.SEMessageDelta, StopReason: "tool_use"},
		{Type: llm.SEMessageStop},
	}
}

func fakeTextTurn(text string) []llm.StreamEvent {
	return []llm.StreamEvent{
		{Type: llm.SETextDelta, Text: text},
		{Type: llm.SEMessageDelta, StopReason: "end_turn"},
		{Type: llm.SEMessageStop},
	}
}

func TestSkillGatedMCPNotSpawnedUntilSkillInvoked(t *testing.T) {
	var spawns atomic.Int32
	pool := newMCPPool(func(_ context.Context, m *db.MCPServer) (mcpClient, error) {
		spawns.Add(1)
		return &fakeMCPClient{tools: makeFakePlaywrightTools("live", nil)}, nil
	}, 5*time.Minute)
	defer pool.Close()

	// Also verify an agent with NO MCPs and NO deferred host tools does NOT receive
	// an UnlockSet (avoiding unnecessary SearchExtraTools/ExecuteExtraTool).
	_, emptyDef, emptyCleanup := assembleAgentAugment(context.Background(), "worker", nil, nil, nil, pool, nil, nil)
	defer emptyCleanup()
	if emptyDef.Unlock != nil {
		t.Fatalf("expected nil UnlockSet when agent has no MCPs or deferred host tools")
	}

	// Configure a skill-gated MCP ("playwright") with 0 global MCPs.
	skills := skill.NewRegistry(skill.Skill{
		Name:         "browser",
		Description:  "Use Playwright browser automation.",
		Instructions: "Use playwright tools to inspect the page.",
		MCPs:         []string{"playwright"},
	})
	servers := []*db.MCPServer{{
		ID:        1,
		Name:      "playwright",
		Transport: "stdio",
		Command:   "npx",
		Args:      json.RawMessage(`["@playwright/mcp"]`),
		Enabled:   true,
	}}

	extra, def, cleanup := assembleAgentAugment(context.Background(), "worker", skills, servers, map[int64]bool{}, pool, nil, nil)
	defer cleanup()

	// Assert 0 spawns during ToolAugment assembly!
	if got := spawns.Load(); got != 0 {
		t.Fatalf("expected 0 spawns during ToolAugment for skill-gated MCP, got %d", got)
	}
	if def.Unlock == nil {
		t.Fatal("expected non-nil UnlockSet when skill-gated MCPs exist")
	}
	if def.BindDeferred == nil {
		t.Fatal("expected non-nil BindDeferred when skill-gated MCPs exist")
	}
	if len(def.GlobalNames) != 0 {
		t.Fatalf("skill-gated MCP must not appear in GlobalNames, got %v", def.GlobalNames)
	}

	// Build a real agentcore.Session and bind dynamic deferred registration.
	turns := [][]llm.StreamEvent{
		fakeToolTurn("t1", "Skill", `{"name":"browser"}`),
		fakeToolTurn("t2", actool.SearchExtraToolsName, `{"query":"select:navigate"}`),
		fakeToolTurn("t3", actool.ExecuteExtraToolName, `{"tool_name":"mcp__playwright__navigate","params":{"url":"https://example.test"}}`),
		fakeTextTurn("all done"),
	}
	var capturedSchemas [][]llm.ToolSchema
	turnIdx := 0
	callModel := func(_ context.Context, req llm.CompletionRequest) iter.Seq2[llm.StreamEvent, error] {
		capturedSchemas = append(capturedSchemas, append([]llm.ToolSchema(nil), req.Tools...))
		evs := turns[turnIdx]
		turnIdx++
		return func(yield func(llm.StreamEvent, error) bool) {
			for _, e := range evs {
				if !yield(e, nil) {
					return
				}
			}
		}
	}

	sess := agentcore.NewSession(agentcore.Options{
		SystemPrompt:           []string{"sys"},
		Tools:                  extra,
		DeferredTools:          def.Deferred,
		UnlockSet:              def.Unlock,
		PermissionMode:         permission.ModeBypass,
		DisableBackgroundTasks: true,
		Deps:                   harness.QueryDeps{CallModel: callModel},
	})
	defer sess.Close()
	def.BindDeferred(sess.AddDeferredTool)

	// Still 0 spawns after session creation and binding!
	if got := spawns.Load(); got != 0 {
		t.Fatalf("expected 0 spawns after NewSession + BindDeferred, got %d", got)
	}

	var toolResults []string
	for ev, err := range sess.Prompt(context.Background(), "open page") {
		if err != nil {
			t.Fatalf("Prompt error: %v", err)
		}
		if ev.Kind == harness.KindToolResult && ev.ToolResult != nil {
			if ev.ToolResult.IsError {
				t.Fatalf("unexpected tool error: %+v", ev.ToolResult)
			}
			var txt strings.Builder
			for _, b := range ev.ToolResult.Content {
				txt.WriteString(b.Text)
			}
			toolResults = append(toolResults, txt.String())
		}
	}

	// Assert Playwright was spawned exactly ONCE when Skill("browser") ran, and
	// reused for ExecuteExtraTool.
	if got := spawns.Load(); got != 1 {
		t.Fatalf("expected exactly 1 spawn after Skill + ExecuteExtraTool, got %d", got)
	}
	if len(toolResults) != 3 {
		t.Fatalf("expected 3 tool results (Skill, Search, Execute), got %d: %v", len(toolResults), toolResults)
	}
	if !strings.Contains(toolResults[0], "mcp__playwright__navigate") {
		t.Fatalf("Skill result should reveal lazy MCP tool names:\n%s", toolResults[0])
	}
	if !strings.Contains(toolResults[1], "## mcp__playwright__navigate") || !strings.Contains(toolResults[1], "params schema") {
		t.Fatalf("SearchExtraTools did not discover lazily registered tool:\n%s", toolResults[1])
	}
	if toolResults[2] != "live:navigated:https://example.test" {
		t.Fatalf("ExecuteExtraTool returned unexpected result: %q", toolResults[2])
	}

	// Verify req.Tools stayed 100% immutable across ALL turns (zero prompt-cache bust!)
	// and never leaked mcp__playwright__* into model-visible schemas.
	if len(capturedSchemas) != 4 {
		t.Fatalf("expected 4 model turns, got %d", len(capturedSchemas))
	}
	for i, scs := range capturedSchemas {
		if !reflect.DeepEqual(scs, capturedSchemas[0]) {
			t.Fatalf("turn %d req.Tools mutated mid-session (prompt cache bust!):\nturn 0: %+v\nturn %d: %+v", i, capturedSchemas[0], i, scs)
		}
		for _, sc := range scs {
			if strings.HasPrefix(sc.Name, "mcp__playwright__") {
				t.Fatalf("deferred tool %q leaked into req.Tools on turn %d", sc.Name, i)
			}
		}
	}
}

func TestGlobalMCPMetadataCachedAndPooledAcrossRuns(t *testing.T) {
	var (
		mu          sync.Mutex
		now         = time.Date(2026, 11, 24, 12, 0, 0, 0, time.UTC)
		failConnect bool
		spawns      atomic.Int32
		failOnce    atomic.Bool
		lastClient  *fakeMCPClient
	)

	pool := newMCPPool(func(_ context.Context, m *db.MCPServer) (mcpClient, error) {
		mu.Lock()
		shouldFail := failConnect
		mu.Unlock()
		if shouldFail {
			return nil, errors.New("transient startup timeout")
		}
		n := spawns.Add(1)
		cl := &fakeMCPClient{tools: makeFakePlaywrightTools("conn"+string(rune('0'+n)), &failOnce)}
		mu.Lock()
		lastClient = cl
		mu.Unlock()
		return cl, nil
	}, 5*time.Minute)
	pool.now = func() time.Time {
		mu.Lock()
		defer mu.Unlock()
		return now
	}
	pool.metaTTL = 10 * time.Minute
	defer pool.Close()

	srv := &db.MCPServer{
		ID:        2,
		Name:      "playwright",
		Transport: "stdio",
		Command:   "node",
		Args:      json.RawMessage(`["server.js"]`),
		Env:       json.RawMessage(`{"B":"2","A":"1"}`),
		Enabled:   true,
	}

	// 5 consecutive agent runs: only 1 connect + 1 tools/list!
	var lastTools []actool.CoreTool
	for run := range 5 {
		ts, err := pool.DiscoverTools(context.Background(), srv)
		if err != nil {
			t.Fatalf("run %d DiscoverTools failed: %v", run, err)
		}
		if len(ts) != 2 {
			t.Fatalf("run %d expected 2 tools, got %d", run, len(ts))
		}
		lastTools = ts
	}
	if got := spawns.Load(); got != 1 {
		t.Fatalf("expected 1 connect across 5 consecutive runs, got %d", got)
	}
	if got := lastClient.listCnt.Load(); got != 1 {
		t.Fatalf("expected 1 tools/list across 5 consecutive runs, got %d", got)
	}

	// Invoking a lazy proxy tool reuses the existing pooled client (still 1 connect).
	res, err := lastTools[0].Call(context.Background(), json.RawMessage(`{"url":"https://ok"}`), nil)
	if err != nil || res.IsError || res.Flatten() != "conn1:navigated:https://ok" {
		t.Fatalf("pooled invoke failed: res=%+v err=%v", res, err)
	}
	if got := spawns.Load(); got != 1 {
		t.Fatalf("expected invoke to reuse pooled client (spawns=1), got %d", got)
	}

	// Simulate transient metadata refresh failure after metaTTL expires:
	// must fall back to same-fingerprint cached metadata without dropping tools!
	mu.Lock()
	now = now.Add(11 * time.Minute)
	failConnect = true
	lastClient.mu.Lock()
	lastClient.listErr = errors.New("temporary rpc error")
	lastClient.mu.Unlock()
	mu.Unlock()

	fallbackTools, err := pool.DiscoverTools(context.Background(), srv)
	if err != nil {
		t.Fatalf("expected stale metadata fallback on transient refresh failure, got error: %v", err)
	}
	if len(fallbackTools) != 2 || fallbackTools[0].Name() != "mcp__playwright__navigate" {
		t.Fatalf("stale fallback returned unexpected tools: %+v", fallbackTools)
	}

	// Re-enable connector and simulate a dead idle connection during invoke:
	// pool must transparently reconnect once and succeed.
	mu.Lock()
	failConnect = false
	mu.Unlock()
	// Fresh connect first so we have a live reused connection to simulate dying mid-call.
	if _, err := pool.DiscoverTools(context.Background(), srv); err != nil {
		t.Fatalf("rediscover failed: %v", err)
	}
	beforeReconnect := spawns.Load()
	failOnce.Store(true)
	res, err = fallbackTools[0].Call(context.Background(), json.RawMessage(`{"url":"https://after-reconnect"}`), nil)
	if err != nil || res.IsError || !strings.HasSuffix(res.Flatten(), ":navigated:https://after-reconnect") {
		t.Fatalf("expected transparent reconnect-once on dead connection, got res=%+v err=%v", res, err)
	}
	if spawns.Load() != beforeReconnect+1 {
		t.Fatalf("expected exactly 1 reconnect on dead call, before=%d after=%d", beforeReconnect, spawns.Load())
	}
}

func TestMCPPoolInvalidatesOnConfigChangeAndReapsIdle(t *testing.T) {
	var (
		mu      sync.Mutex
		clients []*fakeMCPClient
		spawns  atomic.Int32
	)

	pool := newMCPPool(func(_ context.Context, m *db.MCPServer) (mcpClient, error) {
		n := spawns.Add(1)
		cl := &fakeMCPClient{tools: makeFakePlaywrightTools("v"+string(rune('0'+n)), nil)}
		mu.Lock()
		clients = append(clients, cl)
		mu.Unlock()
		return cl, nil
	}, 50*time.Millisecond)
	pool.reapInterval = 15 * time.Millisecond
	defer pool.Close()

	srvV1 := &db.MCPServer{
		ID:        3,
		Name:      "playwright",
		Transport: "stdio",
		Command:   "node",
		Args:      json.RawMessage(`["v1.js"]`),
		Env:       json.RawMessage(`{"HEADLESS":"1"}`),
		Enabled:   true,
	}

	// Connect v1.
	toolsV1, err := pool.DiscoverTools(context.Background(), srvV1)
	if err != nil || len(toolsV1) != 2 {
		t.Fatalf("v1 discover failed: tools=%d err=%v", len(toolsV1), err)
	}
	if spawns.Load() != 1 {
		t.Fatalf("expected 1 spawn for v1, got %d", spawns.Load())
	}
	mu.Lock()
	c1 := clients[0]
	mu.Unlock()
	if c1.closed.Load() != 0 {
		t.Fatalf("v1 client should still be open before config change")
	}

	// Change Args -> fingerprint changes -> v1 client evicted & closed, v2 connected!
	srvV2 := cloneMCPServer(srvV1)
	srvV2.Args = json.RawMessage(`["v2.js"]`)

	toolsV2, err := pool.DiscoverTools(context.Background(), srvV2)
	if err != nil || len(toolsV2) != 2 {
		t.Fatalf("v2 discover failed: tools=%d err=%v", len(toolsV2), err)
	}
	if c1.closed.Load() != 1 {
		t.Fatalf("expected v1 client to be closed on config change, closed=%d", c1.closed.Load())
	}
	if spawns.Load() != 2 {
		t.Fatalf("expected 2nd spawn for v2, got %d", spawns.Load())
	}
	if !strings.Contains(toolsV2[0].Description(), "(v2)") {
		t.Fatalf("expected fresh v2 metadata after config change, got %q", toolsV2[0].Description())
	}

	// Wait for idleTTL (50ms) to elapse -> v2 client must be reaped & closed automatically!
	mu.Lock()
	c2 := clients[1]
	mu.Unlock()
	deadline := time.Now().Add(2 * time.Second)
	for c2.closed.Load() == 0 && time.Now().Before(deadline) {
		time.Sleep(15 * time.Millisecond)
	}
	if c2.closed.Load() != 1 {
		t.Fatalf("expected idle v2 client to be reaped automatically after idleTTL, closed=%d", c2.closed.Load())
	}
}
