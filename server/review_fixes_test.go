package server

import (
	"archive/zip"
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/RC-CHN/ARTEX/agent"
	"github.com/RC-CHN/ARTEX/db"
	"github.com/RC-CHN/ARTEX/norma/llm"
	"github.com/RC-CHN/ARTEX/norma/skill"
	actool "github.com/RC-CHN/ARTEX/norma/tool"
	"github.com/RC-CHN/ARTEX/sidequestion"
	"github.com/golang-jwt/jwt/v5"
)

func TestWorkspaceSymlinkAndBackslashContainment(t *testing.T) {
	root := t.TempDir()
	wsDir := filepath.Join(root, "ws")
	outsideDir := filepath.Join(root, "outside")
	if err := os.MkdirAll(filepath.Join(wsDir, ".resource-library"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(outsideDir, 0o755); err != nil {
		t.Fatal(err)
	}
	secretFile := filepath.Join(outsideDir, "secret.txt")
	if err := os.WriteFile(secretFile, []byte("top-secret"), 0o644); err != nil {
		t.Fatal(err)
	}
	safeFile := filepath.Join(wsDir, "safe.txt")
	if err := os.WriteFile(safeFile, []byte("ok"), 0o644); err != nil {
		t.Fatal(err)
	}

	s := &Server{m: &Manager{dir: wsDir}}

	// Windows-style backslash traversal into .resource-library must be rejected on every OS.
	for _, bad := range []string{
		`\.resource-library`,
		`\.resource-library\secret`,
		`sub\..\.resource-library\x`,
		".resource-library/versions",
	} {
		if got, ok := s.wsResolve(bad); ok {
			t.Fatalf("wsResolve(%q) = %q, want rejection", bad, got)
		}
	}

	// Normal file inside workspace succeeds.
	if got, ok := s.wsResolve("safe.txt"); !ok || got != safeFile {
		t.Fatalf("wsResolve(safe.txt) = (%q, %v), want (%q, true)", got, ok, safeFile)
	}

	// Symlink pointing outside workspace (file, dir, and dangling) must all be rejected.
	linkFile := filepath.Join(wsDir, "escape-file")
	if err := os.Symlink(secretFile, linkFile); err != nil {
		t.Skipf("os.Symlink unavailable on this host: %v", err)
	}
	if err := os.Symlink(outsideDir, filepath.Join(wsDir, "escape-dir")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(outsideDir, "does-not-exist"), filepath.Join(wsDir, "dangling-escape")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(safeFile, filepath.Join(wsDir, "internal-link")); err != nil {
		t.Fatal(err)
	}

	for _, escape := range []string{"escape-file", "escape-dir", "escape-dir/secret.txt", "escape-dir/new.txt", "dangling-escape"} {
		if got, ok := s.wsResolve(escape); ok {
			t.Fatalf("wsResolve(%q) escaped workspace to %q", escape, got)
		}
	}
	if _, ok := s.wsResolve("internal-link"); !ok {
		t.Fatal("wsResolve(internal-link) should allow symlink pointing inside workspace")
	}
}

func TestRenderTemplateSinglePassNoCommandInjectionAndFailClosedProxy(t *testing.T) {
	params := map[string]any{
		"a": "{b}",
		"b": "'; id #",
	}
	const want = "tool '{b}' ''\\''; id #'"
	for i := 0; i < 100; i++ {
		got := renderTemplate("tool {a} {b}", params, shellQuote)
		if got != want {
			t.Fatalf("iteration %d: renderTemplate = %q, want %q", i, got, want)
		}
	}

	// Fail closed when a non-empty HTTP tool proxy is invalid.
	var hit atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hit.Add(1)
		w.WriteHeader(200)
	}))
	defer srv.Close()

	s := &Server{}
	if _, err := s.httpProxyTransport(httpExec{Proxy: "ftp://127.0.0.1:21"}); err == nil {
		t.Fatal("expected error for unsupported proxy scheme")
	}
	execRaw, _ := json.Marshal(httpExec{
		Method: "GET",
		URL:    srv.URL,
		Proxy:  "ftp://127.0.0.1:21",
	})
	res, err := s.runHTTPTool(t.Context(), execRaw, map[string]any{}, &actool.ToolContext{})
	if err != nil {
		t.Fatalf("runHTTPTool err=%v", err)
	}
	if !res.IsError {
		t.Fatalf("expected error result on invalid proxy, got %+v", res)
	}
	if hit.Load() != 0 {
		t.Fatalf("invalid proxy fell back to direct request (%d hits)", hit.Load())
	}
}

func TestStoredCredentialExfiltrationPrevention(t *testing.T) {
	if !sameNormalizedOrigin("HTTPS://API.OpenAI.com:443/v1", "https://api.openai.com/v1/chat/completions") {
		t.Fatal("expected normalized default-port HTTPS origins to match")
	}
	if !sameNormalizedOrigin("http://example.com:80/a", "http://EXAMPLE.COM/b") {
		t.Fatal("expected normalized default-port HTTP origins to match")
	}
	for _, pair := range [][2]string{
		{"https://api.openai.com/v1", "http://api.openai.com/v1"},
		{"https://api.openai.com/v1", "https://evil.example.com/v1"},
		{"https://api.openai.com/v1", "https://api.openai.com:8443/v1"},
		{"https://api.openai.com/v1", "https://user@api.openai.com/v1"},
		{"https://api.openai.com/v1", "not-a-url"},
	} {
		if sameNormalizedOrigin(pair[0], pair[1]) {
			t.Fatalf("sameNormalizedOrigin(%q, %q) = true, want false", pair[0], pair[1])
		}
	}

	var attackerHits atomic.Int32
	attacker := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attackerHits.Add(1)
		w.WriteHeader(200)
	}))
	defer attacker.Close()

	s := &Server{
		llmOn: true,
		llmCfg: agent.Config{
			Format:  llm.FormatOpenAI,
			BaseURL: "https://api.openai.com/v1",
			APIKey:  "sk-stored-secret",
			Model:   "gpt-4o",
			Proxy:   "",
		},
	}

	// testLLM: redirecting base_url while reusing stored API key -> 400.
	rec := httptest.NewRecorder()
	body := fmt.Sprintf(`{"provider":"openai","model":"gpt-4o","base_url":%q}`, attacker.URL)
	s.testLLM(rec, httptest.NewRequest(http.MethodPost, "/api/llm/test", strings.NewReader(body)))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("testLLM redirect base_url status=%d want 400 body=%s", rec.Code, rec.Body.String())
	}

	// testLLM: overriding proxy while reusing stored API key -> 400.
	rec = httptest.NewRecorder()
	body = `{"provider":"openai","model":"gpt-4o","base_url":"https://api.openai.com/v1","proxy":"http://127.0.0.1:9999"}`
	s.testLLM(rec, httptest.NewRequest(http.MethodPost, "/api/llm/test", strings.NewReader(body)))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("testLLM override proxy status=%d want 400 body=%s", rec.Code, rec.Body.String())
	}

	// pgListModels: redirecting base_url while reusing stored API key -> 400.
	rec = httptest.NewRecorder()
	body = fmt.Sprintf(`{"provider":"openai","base_url":%q}`, attacker.URL)
	s.pgListModels(rec, httptest.NewRequest(http.MethodPost, "/api/llm/models", strings.NewReader(body)))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("pgListModels redirect base_url status=%d want 400 body=%s", rec.Code, rec.Body.String())
	}

	// pgListModels: overriding proxy while reusing stored API key -> 400.
	rec = httptest.NewRecorder()
	body = `{"provider":"openai","base_url":"https://api.openai.com/v1","proxy":"http://127.0.0.1:9999"}`
	s.pgListModels(rec, httptest.NewRequest(http.MethodPost, "/api/llm/models", strings.NewReader(body)))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("pgListModels override proxy status=%d want 400 body=%s", rec.Code, rec.Body.String())
	}

	// pgListModels: invalid non-empty proxy with fresh key must fail closed with 400.
	rec = httptest.NewRecorder()
	body = fmt.Sprintf(`{"provider":"openai","base_url":%q,"api_key":"sk-fresh","proxy":"ftp://127.0.0.1:21"}`, attacker.URL)
	s.pgListModels(rec, httptest.NewRequest(http.MethodPost, "/api/llm/models", strings.NewReader(body)))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("pgListModels invalid proxy status=%d want 400 body=%s", rec.Code, rec.Body.String())
	}

	if attackerHits.Load() != 0 {
		t.Fatalf("attacker server received %d requests; stored credentials or direct fallback leaked", attackerHits.Load())
	}
}

func TestSideQuestionsLRUCapTerminalSSEAndShutdown503(t *testing.T) {
	// 1. Hard LRU cap on s.side.latest & inactive worker retention window.
	s, store, cfg := newUnitSideServer(t, unitStreamProvider{}, time.Hour, 2*time.Second, 5*time.Second)
	model := sideModel(cfg, 0, "unit")

	activeParent := sidequestion.Parent{ConversationID: 1}
	s.markSideActive(activeParent)
	s.publishSideSnapshot(sidequestion.Snapshot{
		Parent: activeParent, RunID: 1, Version: 1, Model: model,
		Request: llm.CompletionRequest{Messages: []llm.Message{llm.UserText("active conv")}},
	})
	// Publish 60 inactive worker terminal snapshots -> inactive worker cap (32) applies.
	for i := int64(1); i <= 60; i++ {
		s.publishSideSnapshot(sidequestion.Snapshot{
			Parent: sidequestion.Parent{TaskID: 9, ExplorationID: 90, IntentID: i},
			RunID:  1, Version: 1, Terminal: true, Model: model,
			Request: llm.CompletionRequest{Messages: []llm.Message{llm.UserText(fmt.Sprintf("worker-%d", i))}},
		})
	}
	s.side.mu.Lock()
	workerCount := 0
	for _, snap := range s.side.latest {
		if snap.Parent.IntentID > 0 {
			workerCount++
		}
	}
	_, activeStillPresent := s.side.latest[activeParent.Key()]
	s.side.mu.Unlock()
	if workerCount > maxSideInactiveWorkerLatest {
		t.Fatalf("inactive worker snapshots=%d exceed cap %d", workerCount, maxSideInactiveWorkerLatest)
	}
	if !activeStillPresent {
		t.Fatal("active conversation snapshot was evicted by inactive workers")
	}

	// Publish 200 inactive conversations -> global cap (128) enforced.
	for i := int64(100); i < 300; i++ {
		s.publishSideSnapshot(sidequestion.Snapshot{
			Parent: sidequestion.Parent{ConversationID: i},
			RunID:  1, Version: 1, Model: model,
			Request: llm.CompletionRequest{Messages: []llm.Message{llm.UserText("conv")}},
		})
	}
	s.side.mu.Lock()
	totalLatest := len(s.side.latest)
	_, activeStillPresent = s.side.latest[activeParent.Key()]
	s.side.mu.Unlock()
	if totalLatest > maxSideLatestSnapshots {
		t.Fatalf("len(s.side.latest)=%d exceeds cap %d", totalLatest, maxSideLatestSnapshots)
	}
	if !activeStillPresent {
		t.Fatal("active conversation snapshot was evicted before non-active entries")
	}

	// 2. prepareDrainTaskSideQuestions preserves s.side.latest until forgetTaskSideQuestions.
	pTask := sidequestion.Parent{TaskID: 77, ExplorationID: 770}
	s.publishSideSnapshot(sidequestion.Snapshot{
		Parent: pTask, RunID: 1, Version: 1, Model: model,
		Request: llm.CompletionRequest{Messages: []llm.Message{llm.UserText("rollback-safe")}},
	})
	if err := s.prepareDrainTaskSideQuestions(t.Context(), "77"); err != nil {
		t.Fatalf("prepareDrainTaskSideQuestions: %v", err)
	}
	if snap, err := s.sideSnapshot(t.Context(), pTask); err != nil || snap == nil {
		t.Fatalf("prepareDrainTaskSideQuestions dropped in-memory latest before commit: (%v, %v)", snap, err)
	}
	s.forgetTaskSideQuestions("77")
	s.side.mu.Lock()
	_, stillThere := s.side.latest[pTask.Key()]
	s.side.mu.Unlock()
	if stillThere {
		t.Fatal("forgetTaskSideQuestions did not clear task snapshot")
	}

	// 3. SSE terminal delivery even when terminal event has lower Sequence than streamed seq.
	lowSeqID := "req-low-seq-term"
	store.mu.Lock()
	store.requests[lowSeqID] = sidequestion.Exchange{
		ID: lowSeqID, SessionKey: activeParent.Key(), Status: "running", Sequence: 2, Answer: "db",
	}
	store.mu.Unlock()
	s.side.hub.publish(sidequestion.Exchange{
		ID: lowSeqID, SessionKey: activeParent.Key(), Status: "running", Sequence: 10, Answer: "live-10",
	})

	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/side-questions/{requestID}/events", s.sideEvents)
	ts := httptest.NewServer(mux)
	defer ts.Close()

	resp, err := http.Get(ts.URL + "/api/side-questions/" + lowSeqID + "/events")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	eventsCh := make(chan sidequestion.Exchange, 8)
	go func() {
		sc := bufio.NewScanner(resp.Body)
		for sc.Scan() {
			if strings.HasPrefix(sc.Text(), "data: ") {
				var ex sidequestion.Exchange
				if json.Unmarshal([]byte(strings.TrimPrefix(sc.Text(), "data: ")), &ex) == nil {
					eventsCh <- ex
				}
			}
		}
		close(eventsCh)
	}()
	// Consume initial live snapshot (seq=10).
	select {
	case first := <-eventsCh:
		if first.Sequence != 10 {
			t.Fatalf("expected initial live seq=10, got %+v", first)
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for initial snapshot")
	}
	// Publish terminal event with lower sequence (3 < 10) -> must still be delivered!
	s.side.hub.finish(sidequestion.Exchange{
		ID: lowSeqID, SessionKey: activeParent.Key(), Status: "cancelled", Sequence: 3, Answer: "stopped",
	})
	sawTerminal := false
	timeout := time.After(time.Second)
	for !sawTerminal {
		select {
		case ex, ok := <-eventsCh:
			if !ok {
				t.Fatal("SSE stream closed without emitting lower-sequence terminal snapshot")
			}
			if ex.Status == "cancelled" {
				sawTerminal = true
			}
		case <-timeout:
			t.Fatal("timed out waiting for lower-sequence terminal event")
		}
	}

	// 4. Shutdown: when s.closing == true (s.background returns false), POST returns 503 and cancels DB row.
	pShut := sidequestion.Parent{ConversationID: 888}
	s.publishSideSnapshot(sidequestion.Snapshot{
		Parent: pShut, RunID: 1, Version: 1, Model: model,
		Request: llm.CompletionRequest{Messages: []llm.Message{llm.UserText("shutting down")}},
	})
	s.backgroundMu.Lock()
	s.closing = true
	s.backgroundMu.Unlock()

	pw := httptest.NewRecorder()
	s.handleSideQuestions(pw, httptest.NewRequest(http.MethodPost, "/api/conversations/888/side-questions", bytes.NewBufferString(`{"question":"still alive?","client_request_id":"shut-1"}`)), pShut)
	if pw.Code != http.StatusServiceUnavailable {
		t.Fatalf("POST during shutdown status=%d want 503 body=%s", pw.Code, pw.Body.String())
	}
	cur, err := store.CurrentSideRequest(t.Context(), pShut.Key())
	if err != nil || cur != nil {
		t.Fatalf("shutdown POST left orphaned running request: cur=%+v err=%v", cur, err)
	}
}

func TestSchedulerGoalsNoBacklogReplayAndOutOfOrderTimeouts(t *testing.T) {
	store := newFakeSchedulerStore()
	firedByAgent := map[string][]int64{}
	recordFire := func(agentKey, _, _ string, taskID int64, _ bool, _, _ string) {
		firedByAgent[agentKey] = append(firedByAgent[agentKey], taskID)
	}
	sc := &Scheduler{store: store, fire: recordFire}
	sc.init()

	// 1. Goals met while 0 on_goal_met triggers enabled must NOT replay when trigger is enabled later.
	store.triggers = nil
	sc.step() // marks goal_triggers_active="0" with 0 MetGoals queries
	if store.calls["MetGoals"] != 1 { // only init() called it
		t.Fatalf("expected 0 MetGoals calls during idle step, total=%d", store.calls["MetGoals"])
	}
	store.metGoals = []db.TaskEvent{{NodeID: 10, TaskID: 1, Summary: "historical goal"}}
	store.triggers = []*db.AgentTrigger{{ID: 1, AgentKey: "goal-agent", Enabled: true, OnGoalMet: true}}
	sc.step() // 0 -> >0 transition seeds #10 without firing
	if got := firedByAgent["goal-agent"]; len(got) != 0 {
		t.Fatalf("newly enabled goal trigger replayed historical met goals: %v", got)
	}
	// Subsequent new met goal DOES fire!
	store.metGoals = append(store.metGoals, db.TaskEvent{NodeID: 11, TaskID: 2, Summary: "new live goal"})
	sc.step()
	if got := firedByAgent["goal-agent"]; !reflect.DeepEqual(got, []int64{2}) {
		t.Fatalf("expected live goal task 2 to fire once, got %v", got)
	}

	// 2. Out-of-order task timeouts: task #101 times out first, then task #100 -> BOTH fire!
	toStore := newFakeSchedulerStore()
	var timedOut []db.TaskEvent
	customStore := &timeoutTestSchedulerStore{
		fakeSchedulerStore: toStore,
		timedOutFn:         func() []db.TaskEvent { return timedOut },
	}
	sc2 := &Scheduler{store: customStore, fire: recordFire}
	toStore.maxTimeoutID = 50
	sc2.init()

	toTrigger := []*db.AgentTrigger{{ID: 2, AgentKey: "to-agent", Enabled: true, OnTaskTimeout: true}}
	timedOut = []db.TaskEvent{{NodeID: 101, TaskID: 101, TaskDesc: "t101"}}
	sc2.fireTaskTimeouts(toTrigger)
	if got := firedByAgent["to-agent"]; !reflect.DeepEqual(got, []int64{101}) {
		t.Fatalf("first timeout #101 did not fire: %v", got)
	}
	// Now older task #100 times out AFTER #101!
	timedOut = []db.TaskEvent{
		{NodeID: 100, TaskID: 100, TaskDesc: "t100"},
		{NodeID: 101, TaskID: 101, TaskDesc: "t101"},
	}
	sc2.fireTaskTimeouts(toTrigger)
	sc2.fireTaskTimeouts(toTrigger) // repeat tick must not double-fire
	if got := firedByAgent["to-agent"]; !reflect.DeepEqual(got, []int64{101, 100}) {
		t.Fatalf("out-of-order timeout #100 missed or double-fired: got %v want [101 100]", got)
	}
}

type timeoutTestSchedulerStore struct {
	*fakeSchedulerStore
	timedOutFn func() []db.TaskEvent
}

func (s *timeoutTestSchedulerStore) TimedOutTasksSince(lastID int64) ([]db.TaskEvent, error) {
	s.bump("TimedOutTasksSince")
	var out []db.TaskEvent
	for _, ev := range s.timedOutFn() {
		if ev.TaskID > lastID {
			out = append(out, ev)
		}
	}
	return out, nil
}

func TestMCPPoolSingleflightCancellationIsolationAndLazyErrorNotice(t *testing.T) {
	dialStarted := make(chan struct{})
	releaseDial := make(chan struct{})
	var spawns atomic.Int32

	pool := newMCPPool(func(ctx context.Context, m *db.MCPServer) (mcpClient, error) {
		if spawns.Add(1) == 1 {
			close(dialStarted)
		}
		select {
		case <-releaseDial:
			return &fakeMCPClient{tools: makeFakePlaywrightTools("shared", nil)}, nil
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}, 5*time.Minute)
	defer pool.Close()

	srv := &db.MCPServer{ID: 9, Name: "pw", Transport: "stdio", Command: "node", Enabled: true}
	ctxA, cancelA := context.WithCancel(t.Context())
	errChA := make(chan error, 1)
	go func() {
		_, err := pool.DiscoverTools(ctxA, srv)
		errChA <- err
	}()
	<-dialStarted

	errChB := make(chan error, 1)
	toolsChB := make(chan []actool.CoreTool, 1)
	go func() {
		ts, err := pool.DiscoverTools(t.Context(), srv)
		toolsChB <- ts
		errChB <- err
	}()

	// Give caller B a moment to join the singleflight wait, then cancel caller A.
	time.Sleep(25 * time.Millisecond)
	cancelA()
	if err := <-errChA; !errors.Is(err, context.Canceled) {
		t.Fatalf("caller A err=%v, want context.Canceled", err)
	}

	// Release dial: caller B must still succeed!
	close(releaseDial)
	if err := <-errChB; err != nil {
		t.Fatalf("caller B poisoned by caller A cancellation: %v", err)
	}
	if ts := <-toolsChB; len(ts) != 2 {
		t.Fatalf("caller B got %d tools, want 2", len(ts))
	}
	if got := spawns.Load(); got != 1 {
		t.Fatalf("spawns=%d want 1", got)
	}

	// Verify assembly surfaces diagnostic notice when lazy skill-gated MCP fails to load.
	failPool := newMCPPool(func(context.Context, *db.MCPServer) (mcpClient, error) {
		return nil, errors.New("connection refused")
	}, time.Minute)
	defer failPool.Close()

	skills := skill.NewRegistry(skill.Skill{
		Name: "browser", Description: "browser skill", Instructions: "use browser", MCPs: []string{"broken-mcp"},
	})
	servers := []*db.MCPServer{{ID: 1, Name: "broken-mcp", Transport: "http", URL: "http://127.0.0.1:1", Enabled: true}}
	extra, _, cleanup := assembleAgentAugment(t.Context(), "worker", skills, servers, map[int64]bool{}, failPool, nil, nil)
	defer cleanup()

	var skillTool actool.CoreTool
	for _, tl := range extra {
		if tl.Name() == "Skill" {
			skillTool = tl
		}
	}
	if skillTool == nil {
		t.Fatal("Skill tool missing")
	}
	res, err := skillTool.Call(t.Context(), json.RawMessage(`{"name":"browser"}`), nil)
	if err != nil {
		t.Fatalf("Skill call err: %v", err)
	}
	if !strings.Contains(res.Flatten(), "[MCP 加载失败:") || !strings.Contains(res.Flatten(), "connection refused") {
		t.Fatalf("expected MCP load failure diagnostic in Skill output, got:\n%s", res.Flatten())
	}
}

func TestChatAttachmentsValidationAndDefensiveCompose(t *testing.T) {
	base := t.TempDir()
	uploads := filepath.Join(base, "uploads")
	if err := os.MkdirAll(uploads, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(uploads, "report.txt"), []byte("ok"), 0o644); err != nil {
		t.Fatal(err)
	}
	outside := filepath.Join(t.TempDir(), "secret.txt")
	if err := os.WriteFile(outside, []byte("secret"), 0o644); err != nil {
		t.Fatal(err)
	}

	if err := validateAttachments(base, []chatAttachment{{Name: "report.txt", Path: "uploads/report.txt", Size: 2}}); err != nil {
		t.Fatalf("valid attachment rejected: %v", err)
	}

	badPaths := []string{
		"",
		"uploads",
		"uploads/",
		"../secret.txt",
		"uploads/../../etc/passwd",
		"/etc/passwd",
		"other/file.txt",
		"uploads/./report.txt",
	}
	if runtime.GOOS == "windows" {
		badPaths = append(badPaths, `C:\Windows\win.ini`, `C:uploads/report.txt`)
	}
	for _, p := range badPaths {
		if err := validateAttachments(base, []chatAttachment{{Path: p}}); err == nil {
			t.Fatalf("expected invalid attachment path %q to be rejected", p)
		}
	}

	linkPath := filepath.Join(uploads, "link.txt")
	if err := os.Symlink(outside, linkPath); err == nil {
		if err := validateAttachments(base, []chatAttachment{{Path: "uploads/link.txt"}}); err == nil {
			t.Fatal("symlink escaping uploads/ was not rejected")
		}
	}

	composed := composeAgentMessage("hello", []chatAttachment{
		{Path: "../outside.txt", Size: 10},
		{Path: "uploads/report.txt", Size: 2},
	}, base)
	if strings.Contains(composed, "outside.txt") {
		t.Fatalf("composeAgentMessage leaked invalid attachment path:\n%s", composed)
	}
	if !strings.Contains(composed, "report.txt") {
		t.Fatalf("composeAgentMessage dropped valid attachment:\n%s", composed)
	}
}

func TestLogSinkMonotonicSeqFinalFlushAndRestart(t *testing.T) {
	s := &logSinkT{cap: 100, subs: map[chan LogLine]struct{}{}, out: &bytes.Buffer{}}
	// Emit 2 pre-DB startup logs BEFORE setLogWriter restores DB history.
	_, _ = s.Write([]byte("[boot] startup 1\n"))
	_, _ = s.Write([]byte("[boot] startup 2\n"))

	var inserted atomic.Int64
	writer := &mockLogWriter{
		recent: []*db.DBLog{
			{ID: 1, CreatedAt: time.Now().Add(-2 * time.Minute), Level: "info", Tag: "old", Text: "[old] 1"},
			{ID: 2, CreatedAt: time.Now().Add(-1 * time.Minute), Level: "info", Tag: "old", Text: "[old] 2"},
		},
		nextID:  10,
		onBatch: func(n int) { inserted.Add(int64(n)) },
	}

	ctx1, cancel1 := context.WithCancel(t.Context())
	done1 := s.setLogWriter(ctx1, writer, logWriterOptions{
		batchMax:     64,
		flushWindow:  time.Hour, // force shutdown drain to be the flusher!
		writeTimeout: time.Second,
		errOut:       &syncBuffer{},
	})

	lines, cursor := s.recent(0, 100)
	if len(lines) != 4 || cursor != 4 {
		t.Fatalf("lines=%d cursor=%d want 4/4", len(lines), cursor)
	}
	for i, l := range lines {
		wantSeq := int64(i + 1)
		if l.Seq != wantSeq {
			t.Fatalf("ring[%d].Seq=%d want strictly monotonic %d", i, l.Seq, wantSeq)
		}
	}

	// Write buffered logs and immediately cancel ctx -> shutdown drain must flush them!
	_, _ = s.Write([]byte("[drain] shutdown line 1\n"))
	_, _ = s.Write([]byte("[drain] shutdown line 2\n"))
	cancel1()
	select {
	case <-done1:
	case <-time.After(2 * time.Second):
		t.Fatal("writer 1 did not stop")
	}
	if inserted.Load() != 2 {
		t.Fatalf("shutdown final flush inserted %d lines, want 2", inserted.Load())
	}

	// In-process restart: calling setLogWriter again must work after prior stop.
	ctx2, cancel2 := context.WithCancel(t.Context())
	done2 := s.setLogWriter(ctx2, writer, logWriterOptions{
		batchMax:     64,
		flushWindow:  20 * time.Millisecond,
		writeTimeout: time.Second,
		errOut:       &syncBuffer{},
	})
	if done2 == nil {
		t.Fatal("setLogWriter refused in-process restart after prior stop")
	}
	_, _ = s.Write([]byte("[restart] second lifecycle\n"))
	waitForCondition(t, time.Second, "restarted writer flushed", func() bool {
		return inserted.Load() == 3
	})
	cancel2()
	<-done2
}

func TestSkillFrontmatterSanitizationAndSymlinkContainment(t *testing.T) {
	skillRoot := t.TempDir()
	s := &Server{skillDir: skillRoot}

	// YAML injection attempt in description & mcps via fsCreateSkill.
	rec := httptest.NewRecorder()
	payload := `{"name":"safe-skill","description":"desc line\nmcps: [evil-mcp]\nlicense: hacked","license":"MIT\nfoo: bar","mcps":["legit-mcp\nevil: 1"]}`
	s.fsCreateSkill(rec, httptest.NewRequest(http.MethodPost, "/api/skills", strings.NewReader(payload)))
	if rec.Code != http.StatusCreated {
		t.Fatalf("fsCreateSkill status=%d body=%s", rec.Code, rec.Body.String())
	}
	reg, err := skill.LoadDir(skillRoot)
	if err != nil {
		t.Fatalf("skill.LoadDir: %v", err)
	}
	sk, ok := reg.Get("safe-skill")
	if !ok {
		t.Fatal("created skill not loaded")
	}
	if strings.ContainsAny(sk.Description, "\r\n") {
		t.Fatalf("description retained newline: %q", sk.Description)
	}
	for _, m := range sk.MCPs {
		if m == "evil-mcp" {
			t.Fatalf("YAML injection added evil-mcp: %v", sk.MCPs)
		}
	}

	// rewriteSkillFrontmatter must also strip newlines & prevent YAML key injection.
	orig := []byte("---\nname: safe-skill\ndescription: old\n---\nbody\n")
	injected := "new\nmcps: [pwned]"
	rewritten, err := rewriteSkillFrontmatter(orig, nil, &injected, nil, nil)
	if err != nil {
		t.Fatalf("rewriteSkillFrontmatter: %v", err)
	}
	if strings.Contains(string(rewritten), "\nmcps:") {
		t.Fatalf("rewriteSkillFrontmatter allowed YAML key injection:\n%s", rewritten)
	}

	// Symlink containment in fsReadFile / fsWriteFile / fsDeletePath.
	outside := filepath.Join(t.TempDir(), "outside.txt")
	if err := os.WriteFile(outside, []byte("secret"), 0o644); err != nil {
		t.Fatal(err)
	}
	linkPath := filepath.Join(skillRoot, "safe-skill", "evil.txt")
	if err := os.Symlink(outside, linkPath); err == nil {
		req := httptest.NewRequest(http.MethodGet, "/api/skills/safe-skill/files/evil.txt", nil)
		req.SetPathValue("name", "safe-skill")
		req.SetPathValue("file", "evil.txt")
		rw := httptest.NewRecorder()
		s.fsReadFile(rw, req)
		if rw.Code != http.StatusBadRequest {
			t.Fatalf("fsReadFile via escaping symlink status=%d want 400", rw.Code)
		}

		wreq := httptest.NewRequest(http.MethodPut, "/api/skills/safe-skill/files/evil.txt", strings.NewReader(`{"content":"overwrite"}`))
		wreq.SetPathValue("name", "safe-skill")
		wreq.SetPathValue("file", "evil.txt")
		ww := httptest.NewRecorder()
		s.fsWriteFile(ww, wreq)
		if ww.Code != http.StatusBadRequest {
			t.Fatalf("fsWriteFile via escaping symlink status=%d want 400", ww.Code)
		}
		if raw, _ := os.ReadFile(outside); string(raw) != "secret" {
			t.Fatalf("outside file was overwritten via skill symlink: %q", string(raw))
		}
	}
}

func TestAuthJWTNotBeforeQueryTokenRestrictionAndCORS(t *testing.T) {
	key := []byte("0123456789abcdef0123456789abcdef")
	now := time.Now()
	oldTok, err := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.RegisteredClaims{
		Subject:   "ARTEX",
		IssuedAt:  jwt.NewNumericDate(now.Add(-10 * time.Second)),
		ExpiresAt: jwt.NewNumericDate(now.Add(time.Hour)),
	}).SignedString(key)
	if err != nil {
		t.Fatal(err)
	}
	newTok, err := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.RegisteredClaims{
		Subject:   "ARTEX",
		IssuedAt:  jwt.NewNumericDate(now),
		ExpiresAt: jwt.NewNumericDate(now.Add(time.Hour)),
	}).SignedString(key)
	if err != nil {
		t.Fatal(err)
	}

	cutoff := now.Unix()
	if verifyJWTWithNotBefore(oldTok, key, cutoff) {
		t.Fatal("old JWT with iat < notBefore must be rejected")
	}
	if !verifyJWTWithNotBefore(newTok, key, cutoff) {
		t.Fatal("new JWT with iat >= notBefore must be accepted")
	}

	s := &Server{jwtKey: key}
	protected := cors(s.requireAuth(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})))

	// Normal API routes must reject ?token= query param.
	for _, tc := range []struct{ method, path string }{
		{http.MethodGet, "/api/tasks?token=" + newTok},
		{http.MethodPost, "/api/logs/stream?token=" + newTok},
		{http.MethodGet, "/api/workspace/read?path=a&token=" + newTok},
	} {
		rec := httptest.NewRecorder()
		protected.ServeHTTP(rec, httptest.NewRequest(tc.method, tc.path, nil))
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("%s %s with query token status=%d want 401", tc.method, tc.path, rec.Code)
		}
	}

	// SSE & download endpoints accept GET ?token=.
	for _, p := range []string{
		"/api/logs/stream?token=" + newTok,
		"/api/exploration/activity/stream?task=1&token=" + newTok,
		"/api/side-questions/req-1/events?token=" + newTok,
		"/api/update/stream?token=" + newTok,
		"/api/workspace/download?path=a.txt&token=" + newTok,
		"/api/exploration/findings/export?token=" + newTok,
	} {
		rec := httptest.NewRecorder()
		protected.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, p, nil))
		if rec.Code != http.StatusOK {
			t.Fatalf("GET %s status=%d want 200", p, rec.Code)
		}
	}

	// CORS headers must advertise PATCH and Authorization.
	optRec := httptest.NewRecorder()
	protected.ServeHTTP(optRec, httptest.NewRequest(http.MethodOptions, "/api/tasks/1", nil))
	if !strings.Contains(optRec.Header().Get("Access-Control-Allow-Methods"), "PATCH") {
		t.Fatalf("CORS Allow-Methods missing PATCH: %q", optRec.Header().Get("Access-Control-Allow-Methods"))
	}
	if !strings.Contains(optRec.Header().Get("Access-Control-Allow-Headers"), "Authorization") {
		t.Fatalf("CORS Allow-Headers missing Authorization: %q", optRec.Header().Get("Access-Control-Allow-Headers"))
	}
}

func TestArchivePathValidationRejectsRootAndVolume(t *testing.T) {
	dataDir := t.TempDir()
	archiveRoot := taskArchiveRoot(dataDir)
	if err := validateArchivePath(dataDir, archiveRoot); err == nil {
		t.Fatal("validateArchivePath accepted archive root directory itself")
	}
	if err := validateArchivePath(dataDir, filepath.Join(dataDir, "outside.tar.gz")); err == nil {
		t.Fatal("validateArchivePath accepted path outside archive root")
	}
	if err := validateArchivePath(dataDir, filepath.Join(archiveRoot, "1-10.tar.gz")); err != nil {
		t.Fatalf("validateArchivePath rejected valid archive file: %v", err)
	}

	payloadRoot := t.TempDir()
	for _, bad := range []string{".", "..", "../escape.ndjson"} {
		if _, err := resolveArchivePayloadPath(payloadRoot, bad); err == nil {
			t.Fatalf("resolveArchivePayloadPath(%q) should fail", bad)
		}
	}
	if runtime.GOOS == "windows" {
		if _, err := resolveArchivePayloadPath(payloadRoot, `C:escape.ndjson`); err == nil {
			t.Fatal("resolveArchivePayloadPath should reject Windows volume-relative path")
		}
	}
}

func TestCompactorQuiescenceAndDecodeBodyCap(t *testing.T) {
	// Verify evictTaskAgents closes and joins the task's Compactor cleanly.
	s := &Server{
		taskAgents: map[string]*taskAgentBundle{
			"42": {comp: agent.NewCompactor(nil, "test-model")},
		},
	}
	s.evictTaskAgents("42")
	s.taskAgentMu.Lock()
	_, exists := s.taskAgents["42"]
	s.taskAgentMu.Unlock()
	if exists {
		t.Fatal("evictTaskAgents did not remove task bundle")
	}

	// Verify decodeBody enforces maxDecodeBodyBytes.
	oversized := `{"x":"` + strings.Repeat("a", maxDecodeBodyBytes+1024) + `"}`
	req := httptest.NewRequest(http.MethodPost, "/api/test", strings.NewReader(oversized))
	rec := httptest.NewRecorder()
	var dst map[string]string
	err := decodeBody(rec, req, &dst)
	var maxErr *http.MaxBytesError
	if !errors.As(err, &maxErr) {
		t.Fatalf("decodeBody oversized: got err=%v, want *http.MaxBytesError", err)
	}
}

func TestEnginePauseResumeConsistencyUnderConcurrency(t *testing.T) {
	e := NewEngine(nil)
	var wg sync.WaitGroup
	task := newTestTask("55", "running")
	for i := 0; i < 20; i++ {
		wg.Add(2)
		go func() {
			defer wg.Done()
			e.Pause("55", agent.AbortPausedByUser)
			_ = e.compactionContextFor(context.Background(), "55")
		}()
		go func() {
			defer wg.Done()
			e.Resume(task)
			_ = e.execContextFor(context.Background(), "55")
		}()
	}
	wg.Wait()
}

func TestSkillUploadRejectsOversizedEntryAndInvalidateProfChat(t *testing.T) {
	// 1. A zip entry expanding past maxSkillFileBytes must be rejected (HTTP 400)
	// and never installed into skillDir.
	dir := t.TempDir()
	oversized := strings.Repeat("A", maxSkillFileBytes+1024)
	data := buildZip(t,
		zipFile{name: "big-skill/SKILL.md", body: "---\nname: big-skill\ndescription: x\n---\n", method: zip.Deflate},
		zipFile{name: "big-skill/blob.bin", body: oversized, method: zip.Deflate},
	)
	rr, _ := uploadZip(t, dir, "big-skill.zip", data)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("fsUploadSkill oversized entry status=%d want 400 body=%s", rr.Code, rr.Body.String())
	}
	if _, err := os.Stat(filepath.Join(dir, "big-skill")); !os.IsNotExist(err) {
		t.Fatalf("oversized skill was unexpectedly installed: err=%v", err)
	}

	// 2. invalidateProfChatAgents clears cached per-profile chat agents.
	s := &Server{
		profChatAgents: map[int64]*agent.ChatAgent{7: {}},
	}
	s.invalidateProfChatAgents()
	s.profMu.Lock()
	remaining := len(s.profChatAgents)
	s.profMu.Unlock()
	if remaining != 0 {
		t.Fatalf("invalidateProfChatAgents left %d cached entries", remaining)
	}
}
