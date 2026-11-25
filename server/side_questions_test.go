package server

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"iter"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/RC-CHN/ARTEX/agent"
	"github.com/RC-CHN/ARTEX/db"
	"github.com/RC-CHN/ARTEX/norma/harness"
	"github.com/RC-CHN/ARTEX/norma/llm"
	"github.com/RC-CHN/ARTEX/norma/transcript"
	"github.com/RC-CHN/ARTEX/sidequestion"
)

type sideHTTPProvider struct {
	started chan llm.CompletionRequest
	release chan struct{}
	summary func(context.Context, llm.CompletionRequest) (llm.Message, llm.Usage, error)
}

func (p *sideHTTPProvider) Stream(ctx context.Context, req llm.CompletionRequest) iter.Seq2[llm.StreamEvent, error] {
	return func(y func(llm.StreamEvent, error) bool) {
		p.started <- req
		if !y(llm.StreamEvent{Type: llm.SEMessageStart, Usage: llm.Usage{InputTokens: 19}}, nil) {
			return
		}
		if !y(llm.StreamEvent{Type: llm.SETextDelta, Text: "partial answer"}, nil) {
			return
		}
		select {
		case <-p.release:
			y(llm.StreamEvent{Type: llm.SEMessageStop}, nil)
		case <-ctx.Done():
			y(llm.StreamEvent{}, ctx.Err())
		}
	}
}
func (p *sideHTTPProvider) Complete(ctx context.Context, req llm.CompletionRequest) (llm.Message, string, llm.Usage, error) {
	if req.Thinking == "disabled" && p.summary != nil {
		msg, usage, err := p.summary(ctx, req)
		return msg, "end_turn", usage, err
	}
	for _, err := range p.Stream(ctx, req) {
		if err != nil {
			return llm.Message{}, "", llm.Usage{}, err
		}
	}
	return llm.Message{Role: llm.RoleAssistant, Content: []llm.ContentBlock{llm.TextBlock("atomic answer")}}, "end_turn", llm.Usage{InputTokens: 19}, nil
}

func TestSideHTTPPreparationCancellationAndClear(t *testing.T) {
	for _, clear := range []bool{false, true} {
		t.Run(fmt.Sprint(clear), func(t *testing.T) {
			f := newSideHTTPFixture(t)
			p, path := f.conversation(t)
			snap := f.checkpoint(t, p)
			for i := 0; i < 21; i++ {
				e, _, err := f.m.pg.StartSideRequest(t.Context(), snap, fmt.Sprint(i), "past question")
				if err != nil {
					t.Fatal(err)
				}
				e.Answer = "old answer"
				e.Sequence = 1
				e.Status = "completed"
				if _, err = f.m.pg.UpdateSideRequest(t.Context(), *e); err != nil {
					t.Fatal(err)
				}
			}
			started := make(chan struct{})
			f.provider.summary = func(ctx context.Context, req llm.CompletionRequest) (llm.Message, llm.Usage, error) {
				if len(req.Tools) != 0 {
					t.Error("summary has tools")
				}
				close(started)
				<-ctx.Done()
				return llm.UserText("late summary"), llm.Usage{InputTokens: 17}, nil
			}
			e := decodeSide(t, f.call(t, "POST", path, map[string]string{"question": "follow-up", "client_request_id": "new"}, 202))
			select {
			case <-started:
			case <-time.After(time.Second):
				t.Fatal("summary did not start")
			}
			row, err := f.m.pg.SideRequest(t.Context(), e.ID)
			if err != nil || row.Context.Phase != "summarizing_history" {
				t.Fatalf("phase not persisted: %+v %v", row, err)
			}
			// A blocked summary must not hold the global admission/clear mutex.
			other, otherPath := f.conversation(t)
			f.checkpoint(t, other)
			f.call(t, "POST", otherPath, map[string]string{"question": "other session", "client_request_id": "independent"}, 202)
			f.s.side.mu.Lock()
			done := f.s.side.runs[e.ID].done
			f.s.side.mu.Unlock()
			if clear {
				f.call(t, "DELETE", path, nil, 200)
			} else {
				f.call(t, "POST", "/api/side-questions/"+e.ID+"/cancel", nil, 200)
			}
			select {
			case <-done:
			case <-time.After(time.Second):
				t.Fatal("summary cancellation did not settle")
			}
			row, err = f.m.pg.SideRequest(t.Context(), e.ID)
			if err != nil {
				t.Fatal(err)
			}
			if clear {
				if row != nil {
					t.Fatal("cleared request reappeared")
				}
			} else if row.Status != "cancelled" || row.Usage.InputTokens != 17 {
				t.Fatalf("cancel usage: %+v", row)
			}
			var memory string
			if err = f.m.pg.QueryRow(`SELECT memory::text FROM side_question_sessions WHERE session_key=$1`, p.Key()).Scan(&memory); err != nil || memory != "{}" {
				t.Fatalf("late summary saved: %s %v", memory, err)
			}
		})
	}
}

type sideHTTPFixture struct {
	s        *Server
	m        *Manager
	provider *sideHTTPProvider
	handler  http.Handler
	token    string
}

func newSideHTTPFixture(t *testing.T) *sideHTTPFixture {
	t.Helper()
	m, err := NewManager(t.TempDir(), "")
	if err != nil {
		t.Skipf("postgres unavailable (%v) — skipping", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	s := &Server{m: m, engine: NewEngine(m), ctx: ctx, jwtKey: []byte("btw-test-signing-key-only"), chatBusy: map[string]bool{}}
	s.initSideQuestions()
	p := &sideHTTPProvider{started: make(chan llm.CompletionRequest, 16), release: make(chan struct{})}
	cfg := agent.Config{Format: llm.FormatOpenAI, BaseURL: "http://fixture.invalid", Model: "fixture", Stream: true}
	s.cfgMu.Lock()
	s.llmCfg = cfg
	s.llmOn = true
	s.llmDirect = bindSideProvider(p, cfg, 0, "fixture")
	s.cfgMu.Unlock()
	token, err := signJWT(s.jwtKey)
	if err != nil {
		t.Fatal(err)
	}
	f := &sideHTTPFixture{s: s, m: m, provider: p, handler: s.Handler(), token: token}
	t.Cleanup(func() {
		cancel()
		for _, done := range s.cancelSideWhere(func(sidequestion.Parent) bool { return true }) {
			<-done
		}
		<-s.side.done
		s.flushSideSnapshots()
		m.Close()
	})
	return f
}
func (f *sideHTTPFixture) call(t *testing.T, method, path string, body any, want int) *httptest.ResponseRecorder {
	t.Helper()
	raw, _ := json.Marshal(body)
	req := httptest.NewRequest(method, path, bytes.NewReader(raw))
	req.Header.Set("Authorization", "Bearer "+f.token)
	w := httptest.NewRecorder()
	f.handler.ServeHTTP(w, req)
	if w.Code != want {
		t.Fatalf("%s %s: status=%d want=%d body=%s", method, path, w.Code, want, w.Body.String())
	}
	return w
}
func (f *sideHTTPFixture) conversation(t *testing.T) (sidequestion.Parent, string) {
	t.Helper()
	c, err := f.m.pg.CreateConversation("mainagent", "side HTTP", nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = f.m.pg.DeleteConversation(c.ID) })
	return sidequestion.Parent{ConversationID: c.ID}, fmt.Sprintf("/api/conversations/%d/side-questions", c.ID)
}
func (f *sideHTTPFixture) checkpoint(t *testing.T, p sidequestion.Parent) sidequestion.Snapshot {
	t.Helper()
	snap := sidequestion.Snapshot{Parent: p, RunID: time.Now().UnixNano(), Version: 1, CapturedAt: time.Now().UTC(), Model: sideModel(f.s.llmCfg, 0, "fixture"), Request: llm.CompletionRequest{MaxTokens: 128, Messages: []llm.Message{llm.UserText("main context marker")}}}
	if err := f.m.pg.SaveSideSnapshot(t.Context(), snap); err != nil {
		t.Fatal(err)
	}
	return snap
}
func decodeSide(t *testing.T, w *httptest.ResponseRecorder) sidequestion.Exchange {
	t.Helper()
	var e sidequestion.Exchange
	if err := json.Unmarshal(w.Body.Bytes(), &e); err != nil {
		t.Fatal(err)
	}
	return e
}
func waitSide(t *testing.T, d *db.DB, id, status string) *sidequestion.Exchange {
	t.Helper()
	until := time.Now().Add(3 * time.Second)
	for time.Now().Before(until) {
		e, err := d.SideRequest(t.Context(), id)
		if err != nil {
			t.Fatal(err)
		}
		if e != nil && e.Status == status {
			return e
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("side %s did not reach %s", id, status)
	return nil
}

func TestSideHTTPBusyIsolationClearAndReconnect(t *testing.T) {
	f := newSideHTTPFixture(t)
	p, path := f.conversation(t)
	f.call(t, "POST", path, map[string]string{"question": "old session", "client_request_id": "old"}, 409)
	f.checkpoint(t, p)
	// Main busy status must not reject the side request.
	f.s.chatMu.Lock()
	f.s.chatBusy[fmt.Sprintf("conv-%d", p.ConversationID)] = true
	f.s.chatMu.Unlock()
	e := decodeSide(t, f.call(t, "POST", path, map[string]string{"question": "question", "client_request_id": "one"}, 202))
	select {
	case req := <-f.provider.started:
		if !strings.Contains(req.Messages[0].Text(), "main context marker") {
			t.Fatal("missing checkpoint")
		}
	case <-time.After(time.Second):
		t.Fatal("side blocked by main busy")
	}
	again := decodeSide(t, f.call(t, "POST", path, map[string]string{"question": "question", "client_request_id": "one"}, 200))
	if again.ID != e.ID {
		t.Fatal("duplicate request re-executed")
	}
	f.call(t, "POST", path, map[string]string{"question": "another", "client_request_id": "two"}, 409)
	// SSE reconnect always starts with a cumulative snapshot even with Last-Event-ID.
	httpServer := httptest.NewServer(f.handler)
	defer httpServer.Close()
	for i := 0; i < 2; i++ {
		req, _ := http.NewRequest("GET", httpServer.URL+"/api/side-questions/"+e.ID+"/events", nil)
		req.Header.Set("Authorization", "Bearer "+f.token)
		req.Header.Set("Last-Event-ID", "999")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		scanner := bufio.NewScanner(resp.Body)
		seen := false
		for scanner.Scan() {
			if strings.HasPrefix(scanner.Text(), "data: ") {
				seen = strings.Contains(scanner.Text(), e.ID)
				break
			}
		}
		resp.Body.Close()
		if err := scanner.Err(); err != nil {
			t.Fatal(err)
		}
		if !seen {
			t.Fatal("reconnect did not return cumulative request")
		}
	}
	f.call(t, "POST", "/api/side-questions/"+e.ID+"/cancel", nil, 200)
	done := waitSide(t, f.m.pg, e.ID, "cancelled")
	if done.Answer != "partial answer" || done.Usage.InputTokens != 19 {
		t.Fatalf("cancel lost partial/usage: %+v", done)
	}
	f.s.chatMu.Lock()
	mainBusy := f.s.chatBusy[fmt.Sprintf("conv-%d", p.ConversationID)]
	f.s.chatMu.Unlock()
	if !mainBusy {
		t.Fatal("side cancellation stopped main")
	}
	f.call(t, "DELETE", path, nil, 200)
	if history, err := f.m.pg.SideHistory(t.Context(), p.Key(), 0, 20); err != nil || len(history) != 0 {
		t.Fatalf("clear %+v %v", history, err)
	}
	if snap, err := f.m.pg.SideSnapshot(t.Context(), p.Key()); err != nil || snap == nil {
		t.Fatal("clear lost main snapshot")
	}
	var count int
	if err := f.m.pg.QueryRow(`SELECT count(*) FROM conversation_activities WHERE conversation_id=$1`, p.ConversationID).Scan(&count); err != nil || count != 0 {
		t.Fatalf("side contaminated main activity %d %v", count, err)
	}
	f.s.cfgMu.Lock()
	f.s.llmCfg.Model = "changed"
	f.s.cfgMu.Unlock()
	f.call(t, "GET", path, nil, 200)
	f.call(t, "POST", path, map[string]string{"question": "changed config", "client_request_id": "new"}, 409)
}

func TestSideHTTPGlobalLimitTaskWorkerAndDeletion(t *testing.T) {
	f := newSideHTTPFixture(t)
	var requests []sidequestion.Exchange
	for i := 0; i < 20; i++ {
		p, path := f.conversation(t)
		f.checkpoint(t, p)
		want := 202
		if i >= 4 {
			want = 429
		}
		w := f.call(t, "POST", path, map[string]string{"question": "blocked", "client_request_id": "id"}, want)
		if want == 202 {
			requests = append(requests, decodeSide(t, w))
		}
	}
	for _, e := range requests {
		f.call(t, "POST", "/api/side-questions/"+e.ID+"/cancel", nil, 200)
		waitSide(t, f.m.pg, e.ID, "cancelled")
	}
	close(f.provider.release)
	task, err := f.m.CreateTask("side route task", "context", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	id, _ := strconv.ParseInt(task.ID, 10, 64)
	t.Cleanup(func() { _ = f.m.pg.DeleteTask(id) })
	iid, err := task.Store.AddNode(db.KindIntent, map[string]any{"summary": "own worker"}, 1, "paused", "planner", nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, intent := range []int64{0, iid} {
		p := sidequestion.Parent{TaskID: id, ExplorationID: task.ExpID, IntentID: intent}
		f.checkpoint(t, p)
		path := "/api/tasks/" + task.ID + "/chat/side-questions"
		if intent > 0 {
			path = fmt.Sprintf("/api/tasks/%s/intents/%d/side-questions", task.ID, intent)
		}
		e := decodeSide(t, f.call(t, "POST", path, map[string]string{"question": "which context", "client_request_id": "own"}, 202))
		waitSide(t, f.m.pg, e.ID, "completed")
	}
	f.call(t, "GET", fmt.Sprintf("/api/tasks/%s/intents/%d/side-questions", task.ID, iid+1000000), nil, 404)
	if _, err := f.s.applyIntentControl(t.Context(), task, iid, "cancel", "cleanup", ""); err != nil {
		t.Fatal(err)
	}
	if snap, err := f.m.pg.SideSnapshot(t.Context(), (sidequestion.Parent{TaskID: id, ExplorationID: task.ExpID, IntentID: iid}).Key()); err != nil || snap != nil {
		t.Fatal("stopped intent side snapshot remains")
	}
}

func TestSideCheckpointPersistsBeforeAdmissionAndRestart(t *testing.T) {
	f := newSideHTTPFixture(t)
	p, path := f.conversation(t)
	bound := bindSideProvider(f.provider, f.s.llmCfg, 0, "fixture")
	ctx, deps := sidequestion.Attach(f.s.ctx, p, harness.QueryDeps{}, bound)
	mainCtx, stopMain := context.WithCancel(ctx)
	done := make(chan struct{})
	go func() {
		defer close(done)
		for range deps.CallModel(mainCtx, llm.CompletionRequest{Messages: []llm.Message{llm.UserText("live checkpoint")}, MaxTokens: 128}) {
		}
	}()
	select {
	case <-f.provider.started:
	case <-time.After(time.Second):
		t.Fatal("main never started")
	}
	e := decodeSide(t, f.call(t, "POST", path, map[string]string{"question": "side", "client_request_id": "live"}, 202))
	snap, err := f.m.pg.SideSnapshot(t.Context(), p.Key())
	if err != nil || snap == nil || snap.Request.Messages[0].Text() != "live checkpoint" {
		t.Fatalf("admission checkpoint not durable %+v %v", snap, err)
	}
	stopMain()
	<-done
	f.call(t, "POST", "/api/side-questions/"+e.ID+"/cancel", nil, 200)
	waitSide(t, f.m.pg, e.ID, "cancelled")
	// Simulate an abrupt process exit: persisted running row survives, memory doesn't.
	orphan, _, err := f.m.pg.StartSideRequest(t.Context(), *snap, "orphan", "restart")
	if err != nil {
		t.Fatal(err)
	}
	orphan.Answer = "saved before crash"
	orphan.Sequence = 1
	if _, err = f.m.pg.UpdateSideRequest(t.Context(), *orphan); err != nil {
		t.Fatal(err)
	}
	ctx2, cancel := context.WithCancel(t.Context())
	defer cancel()
	restarted := &Server{m: f.m, ctx: ctx2, llmCfg: f.s.llmCfg, llmDirect: bound, llmOn: true}
	restarted.initSideQuestions()
	if got := waitSide(t, f.m.pg, orphan.ID, "interrupted"); got.Answer != "saved before crash" {
		t.Fatal("restart discarded partial answer")
	}
	restored, err := restarted.sideSnapshot(t.Context(), p)
	if err != nil || restored == nil {
		t.Fatal("restart missing snapshot")
	}
	if _, err = restarted.sideProvider(restored.Model); err != nil {
		t.Fatal(err)
	}
	if req, err := sidequestion.BuildRequest(*restored, nil, "continue after restart"); err != nil || req.Messages[0].Text() != "live checkpoint" {
		t.Fatal("restart cannot ask from stored context")
	}
	// All routes pass the same authentication middleware.
	w := httptest.NewRecorder()
	f.handler.ServeHTTP(w, httptest.NewRequest("GET", path, nil))
	if w.Code != 401 {
		t.Fatalf("unauthenticated side route: %d", w.Code)
	}
}

func TestSideRejectsDeletedOrChangedCachedProfile(t *testing.T) {
	f := newSideHTTPFixture(t)
	p := &db.LLMProfile{Name: "btw-cached-profile", Format: "openai", BaseURL: "http://fixture.invalid", APIKey: "test-only", Model: "fixture", Streaming: true}
	id, err := f.m.pg.SaveProfile(p)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = f.m.pg.DeleteProfile(id) })
	cfg, ok := f.s.loadProfileConfig(id)
	if !ok {
		t.Fatal("profile unavailable")
	}
	f.s.provByProfile = map[int64]*provEntry{id: {prov: f.provider, cfg: cfg}}
	model := sideModel(cfg, id, p.Name)
	if _, err = f.s.sideProvider(model); err != nil {
		t.Fatal(err)
	}
	if _, err = f.m.pg.Exec(`UPDATE llm_profiles SET model='changed' WHERE id=$1`, id); err != nil {
		t.Fatal(err)
	}
	if _, err = f.s.sideProvider(model); err == nil {
		t.Fatal("cached profile bypassed model identity check")
	}
	if err = f.m.pg.DeleteProfile(id); err != nil {
		t.Fatal(err)
	}
	if _, err = f.s.sideProvider(model); err == nil {
		t.Fatal("deleted profile remained usable from cache")
	}
}

func TestSideTaskDrainPersistsBeforeArchive(t *testing.T) {
	f := newSideHTTPFixture(t)
	task, err := f.m.CreateTask("side archive drain", "context", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	id, _ := strconv.ParseInt(task.ID, 10, 64)
	t.Cleanup(func() { _ = f.m.pg.DeleteTask(id) })
	p := sidequestion.Parent{TaskID: id, ExplorationID: task.ExpID}
	f.checkpoint(t, p)
	path := "/api/tasks/" + task.ID + "/chat/side-questions"
	e := decodeSide(t, f.call(t, "POST", path, map[string]string{"question": "answer before archive", "client_request_id": "drain"}, 202))
	select {
	case <-f.provider.started:
	case <-time.After(time.Second):
		t.Fatal("side never started")
	}
	// The real archive entry point closes this same admission barrier first.
	if !f.s.beginTaskDelete(task.ID) {
		t.Fatal("cannot close task admission")
	}
	defer f.s.abortTaskDelete(task.ID)
	f.call(t, "POST", path, map[string]string{"question": "too late", "client_request_id": "late"}, 409)
	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
	defer cancel()
	if err := f.s.drainTaskSideQuestions(ctx, task.ID); err != nil {
		t.Fatal(err)
	}
	row, err := f.m.pg.SideRequest(t.Context(), e.ID)
	if err != nil || row == nil || row.Status != "cancelled" || row.Answer != "partial answer" || row.Usage.InputTokens != 19 {
		t.Fatalf("drain returned before final persistence: %+v %v", row, err)
	}
	archive, err := f.m.pg.SnapshotTaskArchive(id)
	if err != nil {
		t.Fatal(err)
	}
	var rows []sidequestion.Exchange
	if err := json.Unmarshal(archive.Tables["side_question_requests"], &rows); err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 || rows[0].Status != "cancelled" || rows[0].Usage.InputTokens != 19 {
		t.Fatalf("archive lost drained side answer/usage: %+v", rows)
	}
}

func TestSideRestoredWorkerRuntimePublishesNewCheckpoint(t *testing.T) {
	f := newSideHTTPFixture(t)
	task, err := f.m.CreateTask("restore side publisher", "context", nil, 3600, 0)
	if err != nil {
		t.Fatal(err)
	}
	id, _ := strconv.ParseInt(task.ID, 10, 64)
	t.Cleanup(func() { _ = f.m.pg.DeleteTask(id) })
	if err := f.m.pg.SetPaused(id, true); err != nil {
		t.Fatal(err)
	}
	iid, err := task.Store.AddNode(db.KindIntent, map[string]any{"summary": "restored worker"}, 1, "paused", "planner", nil)
	if err != nil {
		t.Fatal(err)
	}
	// Exercise the production startup path, including the deadline coordinator
	// which registers the shared runtime before the worker loops.
	f.s.restoreTaskRuntimes()
	t.Cleanup(func() {
		for _, task := range f.m.List() {
			f.s.engine.StopTask(task.ID)
		}
	})
	f.s.engine.runtimeMu.Lock()
	runtime := f.s.engine.runtimes[task.ID]
	f.s.engine.runtimeMu.Unlock()
	if runtime == nil {
		t.Fatal("restored task runtime missing")
	}
	p := sidequestion.Parent{TaskID: id, ExplorationID: task.ExpID, IntentID: iid}
	close(f.provider.release)
	bound := bindSideProvider(f.provider, f.s.llmCfg, 0, "fixture")
	ctx, deps := sidequestion.Attach(runtime.ctx, p, harness.QueryDeps{}, bound)
	_, _, _, err = deps.CallModelSync(ctx, llm.CompletionRequest{Messages: []llm.Message{llm.UserText("after restart context")}})
	if err != nil {
		t.Fatal(err)
	}
	liveSnap, err := f.s.sideSnapshot(t.Context(), p)
	if err != nil || liveSnap == nil || liveSnap.Request.Messages[0].Text() != "after restart context" {
		t.Fatalf("restored runtime lost in-memory checkpoint publisher: %+v %v", liveSnap, err)
	}
	f.s.flushSideSnapshots()
	if dbSnap, err := f.m.pg.SideSnapshot(t.Context(), p.Key()); err != nil || dbSnap != nil {
		t.Fatalf("inactive /btw session eagerly persisted to PG: %+v %v", dbSnap, err)
	}
	f.call(t, "GET", fmt.Sprintf("/api/tasks/%s/intents/%d/side-questions", task.ID, iid), nil, 200)
	snap, err := f.m.pg.SideSnapshot(t.Context(), p.Key())
	if err != nil || snap == nil || snap.Request.Messages[0].Text() != "after restart context" {
		t.Fatalf("on-demand /btw open did not persist checkpoint: %+v %v", snap, err)
	}
}

// memSideStore is an in-memory sideStore for fast, deterministic unit tests
// that do not require an external PostgreSQL server.
type memSideStore struct {
	mu            sync.Mutex
	snapshots     map[string]sidequestion.Snapshot
	requests      map[string]sidequestion.Exchange
	generations   map[string]int64
	memories      map[string]sidequestion.Memory
	nextOrdinal   int64
	nextID        int64
	saveSnapCalls int
	saveSnapErr   error
	updateCalls   int
	getReqCalls   int
}

func newMemSideStore() *memSideStore {
	return &memSideStore{
		snapshots:   map[string]sidequestion.Snapshot{},
		requests:    map[string]sidequestion.Exchange{},
		generations: map[string]int64{},
		memories:    map[string]sidequestion.Memory{},
	}
}

func (m *memSideStore) InterruptSideRequests(context.Context) error { return nil }

func (m *memSideStore) SaveSideSnapshot(_ context.Context, s sidequestion.Snapshot) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.saveSnapCalls++
	if m.saveSnapErr != nil {
		return m.saveSnapErr
	}
	key := s.Parent.Key()
	if cur, ok := m.snapshots[key]; ok {
		if cur.RunID > s.RunID || (cur.RunID == s.RunID && cur.Version >= s.Version) {
			return nil
		}
	}
	m.snapshots[key] = s
	if _, ok := m.generations[key]; !ok {
		m.generations[key] = 1
	}
	return nil
}

func (m *memSideStore) SideSnapshot(_ context.Context, key string) (*sidequestion.Snapshot, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	s, ok := m.snapshots[key]
	if !ok {
		return nil, nil
	}
	cp := s
	return &cp, nil
}

func (m *memSideStore) ExistingSideRequest(_ context.Context, key, client string) (*sidequestion.Exchange, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	gen := m.generations[key]
	for _, e := range m.requests {
		if e.SessionKey == key && e.ClientID == client && e.Generation == gen {
			cp := e
			return &cp, nil
		}
	}
	return nil, nil
}

func (m *memSideStore) SideRequest(_ context.Context, id string) (*sidequestion.Exchange, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.getReqCalls++
	e, ok := m.requests[id]
	if !ok {
		return nil, nil
	}
	cp := e
	return &cp, nil
}

func (m *memSideStore) CurrentSideRequest(_ context.Context, key string) (*sidequestion.Exchange, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, e := range m.requests {
		if e.SessionKey == key && e.Running() {
			cp := e
			return &cp, nil
		}
	}
	return nil, nil
}

func (m *memSideStore) SideHistory(_ context.Context, key string, before int64, limit int) ([]sidequestion.Exchange, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := []sidequestion.Exchange{}
	for _, e := range m.requests {
		if e.SessionKey == key && (before == 0 || e.Ordinal < before) {
			out = append(out, e)
		}
	}
	if len(out) > limit && limit > 0 {
		out = out[:limit]
	}
	return out, nil
}

func (m *memSideStore) StartSideRequest(_ context.Context, s sidequestion.Snapshot, clientID, question string) (*sidequestion.Exchange, bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	key := s.Parent.Key()
	if _, ok := m.snapshots[key]; !ok {
		return nil, false, db.ErrSideParentGone
	}
	gen := m.generations[key]
	for _, e := range m.requests {
		if e.SessionKey == key && e.Generation == gen && e.ClientID == clientID {
			if e.Question != question {
				return nil, false, errors.New("同一请求 ID 不能用于不同问题")
			}
			cp := e
			return &cp, false, nil
		}
	}
	for _, e := range m.requests {
		if e.SessionKey == key && e.Running() {
			return nil, false, db.ErrSideBusy
		}
	}
	m.nextID++
	m.nextOrdinal++
	e := sidequestion.Exchange{
		ID:         fmt.Sprintf("req-%d", m.nextID),
		SessionKey: key,
		ClientID:   clientID,
		Generation: gen,
		Question:   question,
		Status:     "running",
		Model:      s.Model,
		SnapshotAt: s.CapturedAt,
		CreatedAt:  time.Now().UTC(),
		Ordinal:    m.nextOrdinal,
	}
	m.requests[e.ID] = e
	cp := e
	return &cp, true, nil
}

func (m *memSideStore) UpdateSideRequest(_ context.Context, e sidequestion.Exchange) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.updateCalls++
	cur, ok := m.requests[e.ID]
	if !ok || !cur.Running() || cur.Sequence >= e.Sequence || m.generations[cur.SessionKey] != cur.Generation {
		return false, nil
	}
	m.requests[e.ID] = e
	return true, nil
}

func (m *memSideStore) ClearSideHistory(_ context.Context, key string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.generations[key]++
	delete(m.memories, key)
	for id, e := range m.requests {
		if e.SessionKey == key {
			delete(m.requests, id)
		}
	}
	return nil
}

func (m *memSideStore) SideMemory(_ context.Context, e sidequestion.Exchange) (sidequestion.Memory, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	cur, ok := m.requests[e.ID]
	if !ok || !cur.Running() || m.generations[e.SessionKey] != e.Generation {
		return sidequestion.Memory{}, db.ErrSideParentGone
	}
	return m.memories[e.SessionKey], nil
}

func (m *memSideStore) SideReplayPage(_ context.Context, e sidequestion.Exchange, after int64) ([]sidequestion.Exchange, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []sidequestion.Exchange
	for _, item := range m.requests {
		if item.SessionKey == e.SessionKey && item.Generation == e.Generation && item.Status == "completed" && item.Ordinal > after && item.Ordinal < e.Ordinal {
			out = append(out, item)
		}
	}
	return out, nil
}

func (m *memSideStore) SaveSideMemory(_ context.Context, e sidequestion.Exchange, memory sidequestion.Memory) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	cur, ok := m.requests[e.ID]
	if !ok || !cur.Running() || m.generations[e.SessionKey] != e.Generation {
		return db.ErrSideParentGone
	}
	m.memories[e.SessionKey] = memory
	return nil
}

func newUnitSideServer(t *testing.T, prov llm.Provider, flushEvery, saveEvery, fallbackPoll time.Duration) (*Server, *memSideStore, agent.Config) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	store := newMemSideStore()
	cfg := agent.Config{Format: llm.FormatOpenAI, BaseURL: "http://unit.invalid", Model: "unit-model", Stream: true}
	s := &Server{
		ctx:       ctx,
		llmCfg:    cfg,
		llmOn:     true,
		llmDirect: prov,
		chatBusy:  map[string]bool{},
	}
	s.initSideQuestionsWithStore(store, flushEvery, saveEvery, fallbackPoll)
	t.Cleanup(func() {
		cancel()
		for _, ch := range s.cancelSideWhere(func(sidequestion.Parent) bool { return true }) {
			<-ch
		}
		<-s.side.done
	})
	return s, store, cfg
}

type unitStreamProvider struct {
	stream   func(context.Context, llm.CompletionRequest) iter.Seq2[llm.StreamEvent, error]
	complete func(context.Context, llm.CompletionRequest) (llm.Message, string, llm.Usage, error)
}

func (p unitStreamProvider) Stream(ctx context.Context, r llm.CompletionRequest) iter.Seq2[llm.StreamEvent, error] {
	if p.stream != nil {
		return p.stream(ctx, r)
	}
	return func(y func(llm.StreamEvent, error) bool) {
		y(llm.StreamEvent{Type: llm.SETextDelta, Text: "ok"}, nil)
		y(llm.StreamEvent{Type: llm.SEMessageStop}, nil)
	}
}

func (p unitStreamProvider) Complete(ctx context.Context, r llm.CompletionRequest) (llm.Message, string, llm.Usage, error) {
	if p.complete != nil {
		return p.complete(ctx, r)
	}
	return llm.Message{Role: llm.RoleAssistant, Content: []llm.ContentBlock{llm.TextBlock("ok")}}, "end_turn", llm.Usage{}, nil
}

func TestSideLazySnapshotPersistenceAndOnDemandFlush(t *testing.T) {
	s, store, cfg := newUnitSideServer(t, unitStreamProvider{}, 30*time.Second, 2*time.Second, 5*time.Second)
	p := sidequestion.Parent{ConversationID: 101}
	model := sideModel(cfg, 0, "unit")

	// Publish mid-turn and terminal checkpoints for a session that never used /btw.
	s.publishSideSnapshot(sidequestion.Snapshot{
		Parent: p, SessionID: "conv-101", RunID: 1, Version: 1, CapturedAt: time.Now().UTC(), Model: model,
		Request: llm.CompletionRequest{Messages: []llm.Message{llm.UserText("turn 1")}},
	})
	s.publishSideSnapshot(sidequestion.Snapshot{
		Parent: p, SessionID: "conv-101", RunID: 1, Version: 2, CapturedAt: time.Now().UTC(), Model: model, Terminal: true,
		Request: llm.CompletionRequest{Messages: []llm.Message{llm.UserText("turn 1 done")}},
	})

	// Served immediately from memory with zero DB writes.
	got, err := s.sideSnapshot(t.Context(), p)
	if err != nil || got == nil || got.Request.Messages[0].Text() != "turn 1 done" {
		t.Fatalf("live in-memory snapshot unavailable: %+v %v", got, err)
	}
	s.flushSideSnapshots()
	store.mu.Lock()
	saves := store.saveSnapCalls
	store.mu.Unlock()
	if saves != 0 {
		t.Fatalf("inactive /btw session wrote %d times to DB, want 0", saves)
	}

	// Opening /btw (GET) persists the live snapshot on-demand once; repeated GETs dedup.
	for i := 0; i < 2; i++ {
		w := httptest.NewRecorder()
		req := httptest.NewRequest("GET", "/api/conversations/101/side-questions", nil)
		s.handleSideQuestions(w, req, p)
		if w.Code != 200 {
			t.Fatalf("GET status=%d body=%s", w.Code, w.Body.String())
		}
	}
	store.mu.Lock()
	saves = store.saveSnapCalls
	store.mu.Unlock()
	if saves != 1 {
		t.Fatalf("on-demand GET persistence calls=%d, want 1", saves)
	}

	// Session still has no /btw history/POST, so subsequent turns stay in-memory only.
	s.publishSideSnapshot(sidequestion.Snapshot{
		Parent: p, SessionID: "conv-101", RunID: 1, Version: 3, CapturedAt: time.Now().UTC(), Model: model, Terminal: true,
		Request: llm.CompletionRequest{Messages: []llm.Message{llm.UserText("turn 2 done")}},
	})
	s.flushSideSnapshots()
	store.mu.Lock()
	saves = store.saveSnapCalls
	store.mu.Unlock()
	if saves != 1 {
		t.Fatalf("still-inactive session flushed eagerly: saves=%d want 1", saves)
	}

	// Submitting POST activates /btw for this session and persists latest snapshot.
	postBody := bytes.NewBufferString(`{"question":"status?","client_request_id":"req-1"}`)
	pw := httptest.NewRecorder()
	s.handleSideQuestions(pw, httptest.NewRequest("POST", "/api/conversations/101/side-questions", postBody), p)
	if pw.Code != 202 {
		t.Fatalf("POST status=%d body=%s", pw.Code, pw.Body.String())
	}
	e := decodeSide(t, pw)
	// Wait for unit side run to settle.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		row, _ := store.SideRequest(t.Context(), e.ID)
		if row != nil && !row.Running() {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}

	// Now that /btw is active, a terminal snapshot triggers background persistence automatically.
	s.publishSideSnapshot(sidequestion.Snapshot{
		Parent: p, SessionID: "conv-101", RunID: 2, Version: 1, CapturedAt: time.Now().UTC(), Model: model, Terminal: true,
		Request: llm.CompletionRequest{Messages: []llm.Message{llm.UserText("turn 3 active")}},
	})
	deadline = time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		saved, _ := store.SideSnapshot(t.Context(), p.Key())
		if saved != nil && saved.RunID == 2 && saved.Version == 1 {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("active /btw session terminal checkpoint was not persisted by background flusher")
}

func TestSideSnapshotFlushRetryCapAndCleanup(t *testing.T) {
	s, store, cfg := newUnitSideServer(t, unitStreamProvider{}, time.Hour, 2*time.Second, 5*time.Second)
	model := sideModel(cfg, 0, "unit")

	// 1. Retry cap: after 3 failed flushes, snapshot is dropped from both pending and latest.
	p1 := sidequestion.Parent{TaskID: 50, ExplorationID: 500}
	key1 := p1.Key()
	s.markSideActive(p1)
	s.publishSideSnapshot(sidequestion.Snapshot{
		Parent: p1, RunID: 1, Version: 1, CapturedAt: time.Now().UTC(), Model: model,
		Request: llm.CompletionRequest{Messages: []llm.Message{llm.UserText("huge snapshot")}},
	})
	store.mu.Lock()
	store.saveSnapErr = errors.New("db offline")
	store.mu.Unlock()

	for attempt := 1; attempt <= 2; attempt++ {
		failed := s.flushSideSnapshots()
		if len(failed) != 1 {
			t.Fatalf("attempt %d: expected 1 failed parent, got %v", attempt, failed)
		}
		s.side.mu.Lock()
		pend, hasPend := s.side.pending[key1]
		_, hasLatest := s.side.latest[key1]
		s.side.mu.Unlock()
		if !hasPend || pend.attempts != attempt || !hasLatest {
			t.Fatalf("attempt %d: expected pending(attempts=%d) & latest, got hasPend=%v attempts=%d hasLatest=%v", attempt, attempt, hasPend, pend.attempts, hasLatest)
		}
	}

	// Attempt 3: drainTaskSideQuestions must still detect the failure, while memory is freed.
	if err := s.drainTaskSideQuestions(t.Context(), "50"); err == nil {
		t.Fatal("drainTaskSideQuestions ignored final retry failure")
	}
	s.side.mu.Lock()
	_, hasPend := s.side.pending[key1]
	_, hasLatest := s.side.latest[key1]
	s.side.mu.Unlock()
	if hasPend || hasLatest {
		t.Fatalf("snapshot remained pinned after %d failed retries: pending=%v latest=%v", sideSnapshotMaxRetries, hasPend, hasLatest)
	}
	store.mu.Lock()
	callsAfterDrop := store.saveSnapCalls
	store.saveSnapErr = nil
	store.mu.Unlock()
	s.flushSideSnapshots()
	store.mu.Lock()
	if store.saveSnapCalls != callsAfterDrop {
		t.Fatalf("dropped snapshot retried again: %d -> %d", callsAfterDrop, store.saveSnapCalls)
	}
	store.mu.Unlock()

	// 2. drainTaskSideQuestions on success persists active snapshot and purges all maps for that task only.
	pTask := sidequestion.Parent{TaskID: 60, ExplorationID: 600}
	pOther := sidequestion.Parent{ConversationID: 70}
	s.markSideActive(pTask)
	s.markSideActive(pOther)
	s.publishSideSnapshot(sidequestion.Snapshot{Parent: pTask, RunID: 1, Version: 1, Model: model, Request: llm.CompletionRequest{Messages: []llm.Message{llm.UserText("task-60")}}})
	s.publishSideSnapshot(sidequestion.Snapshot{Parent: pOther, RunID: 1, Version: 1, Model: model, Request: llm.CompletionRequest{Messages: []llm.Message{llm.UserText("conv-70")}}})

	if err := s.drainTaskSideQuestions(t.Context(), "60"); err != nil {
		t.Fatalf("drainTaskSideQuestions: %v", err)
	}
	saved, _ := store.SideSnapshot(t.Context(), pTask.Key())
	if saved == nil || saved.Request.Messages[0].Text() != "task-60" {
		t.Fatalf("drained task snapshot not persisted: %+v", saved)
	}
	s.side.mu.Lock()
	_, tLatest := s.side.latest[pTask.Key()]
	_, tPending := s.side.pending[pTask.Key()]
	_, tSeen := s.side.seen[pTask.Key()]
	_, tActive := s.side.active[pTask.Key()]
	_, oActive := s.side.active[pOther.Key()]
	s.side.mu.Unlock()
	if tLatest || tPending || tSeen || tActive {
		t.Fatalf("drainTaskSideQuestions leaked state: latest=%v pending=%v seen=%v active=%v", tLatest, tPending, tSeen, tActive)
	}
	if !oActive {
		t.Fatal("drainTaskSideQuestions accidentally purged unrelated conversation")
	}

	// 3. cancelSideWhere purges latest, pending, seen, active for matched parent.
	s.publishSideSnapshot(sidequestion.Snapshot{Parent: pOther, RunID: 2, Version: 1, Model: model, Request: llm.CompletionRequest{Messages: []llm.Message{llm.UserText("conv-70-v2")}}})
	s.cancelSideWhere(func(p sidequestion.Parent) bool { return p.ConversationID == 70 })
	s.side.mu.Lock()
	_, cLatest := s.side.latest[pOther.Key()]
	_, cPending := s.side.pending[pOther.Key()]
	_, cSeen := s.side.seen[pOther.Key()]
	_, cActive := s.side.active[pOther.Key()]
	s.side.mu.Unlock()
	if cLatest || cPending || cSeen || cActive {
		t.Fatalf("cancelSideWhere leaked state: latest=%v pending=%v seen=%v active=%v", cLatest, cPending, cSeen, cActive)
	}

	// 4. DELETE clears in-memory state and notifies subscribed SSE clients with cleared.
	pDel := sidequestion.Parent{ConversationID: 80}
	s.markSideActive(pDel)
	s.publishSideSnapshot(sidequestion.Snapshot{Parent: pDel, RunID: 1, Version: 1, Model: model, Request: llm.CompletionRequest{Messages: []llm.Message{llm.UserText("conv-80")}}})
	subCh, _, unsub := s.side.hub.subscribe("req-del")
	defer unsub()
	s.side.hub.bindSession("req-del", pDel.Key())

	dw := httptest.NewRecorder()
	s.handleSideQuestions(dw, httptest.NewRequest("DELETE", "/api/conversations/80/side-questions", nil), pDel)
	if dw.Code != 200 {
		t.Fatalf("DELETE status=%d body=%s", dw.Code, dw.Body.String())
	}
	s.side.mu.Lock()
	_, dLatest := s.side.latest[pDel.Key()]
	_, dPending := s.side.pending[pDel.Key()]
	_, dSeen := s.side.seen[pDel.Key()]
	_, dActive := s.side.active[pDel.Key()]
	s.side.mu.Unlock()
	if dLatest || dPending || dSeen || dActive {
		t.Fatalf("DELETE leaked state: latest=%v pending=%v seen=%v active=%v", dLatest, dPending, dSeen, dActive)
	}
	select {
	case ev := <-subCh:
		if !ev.cleared {
			t.Fatalf("expected cleared event, got %+v", ev)
		}
	case <-time.After(time.Second):
		t.Fatal("DELETE did not broadcast cleared event to SSE subscriber")
	}
}

func TestSideParentSessionIDAndPromptCacheKey(t *testing.T) {
	cases := []struct {
		name      string
		parent    sidequestion.Parent
		sessionID string
		want      string
	}{
		{
			name:      "explicit-parent-session-id",
			parent:    sidequestion.Parent{TaskID: 5, ExplorationID: 42},
			sessionID: "exp42-main-s3",
			want:      "exp42-main-s3",
		},
		{
			name:   "fallback-conversation",
			parent: sidequestion.Parent{ConversationID: 77},
			want:   "conv-77",
		},
		{
			name:   "fallback-task-main",
			parent: sidequestion.Parent{TaskID: 5, ExplorationID: 9},
			want:   "exp9-main",
		},
		{
			name:   "fallback-task-worker",
			parent: sidequestion.Parent{TaskID: 5, ExplorationID: 9, IntentID: 12},
			want:   "exp9-worker-i12",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var gotTxSID, gotCacheCtx, gotCacheReq string
			prov := unitStreamProvider{
				stream: func(ctx context.Context, req llm.CompletionRequest) iter.Seq2[llm.StreamEvent, error] {
					gotTxSID = transcript.SessionIDFrom(ctx)
					gotCacheCtx = llm.PromptCacheKeyFrom(ctx)
					gotCacheReq = req.PromptCacheKey
					return func(y func(llm.StreamEvent, error) bool) {
						y(llm.StreamEvent{Type: llm.SETextDelta, Text: "cached"}, nil)
						y(llm.StreamEvent{Type: llm.SEMessageStop}, nil)
					}
				},
			}
			s, store, cfg := newUnitSideServer(t, prov, time.Hour, 2*time.Second, 5*time.Second)
			snap := sidequestion.Snapshot{
				Parent:     tc.parent,
				SessionID:  tc.sessionID,
				RunID:      1,
				Version:    1,
				CapturedAt: time.Now().UTC(),
				Model:      sideModel(cfg, 0, "unit"),
				Request:    llm.CompletionRequest{MaxTokens: 128, Messages: []llm.Message{llm.UserText("parent context")}},
			}
			if err := store.SaveSideSnapshot(t.Context(), snap); err != nil {
				t.Fatal(err)
			}
			e, _, err := store.StartSideRequest(t.Context(), snap, "cid-1", "why?")
			if err != nil {
				t.Fatal(err)
			}
			runCtx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
			s.side.mu.Lock()
			s.side.runs[e.ID] = sideRun{key: tc.parent.Key(), parent: tc.parent, cancel: cancel, done: make(chan struct{})}
			s.side.mu.Unlock()
			s.runSide(runCtx, cancel, *e, tc.parent, prov, snap, "why?")

			if gotTxSID != tc.want || gotCacheCtx != tc.want || gotCacheReq != tc.want {
				t.Fatalf("parent cache routing mismatch: transcript=%q ctxKey=%q reqKey=%q want=%q", gotTxSID, gotCacheCtx, gotCacheReq, tc.want)
			}
		})
	}
}

type failingFlushWriter struct {
	header      http.Header
	failAfter   int
	writes      int
	statusCode  int
}

func (w *failingFlushWriter) Header() http.Header {
	if w.header == nil {
		w.header = http.Header{}
	}
	return w.header
}
func (w *failingFlushWriter) WriteHeader(code int) { w.statusCode = code }
func (w *failingFlushWriter) Flush()               {}
func (w *failingFlushWriter) Write(p []byte) (int, error) {
	w.writes++
	if w.writes > w.failAfter {
		return 0, errors.New("broken pipe")
	}
	return len(p), nil
}

func TestSideEventsPubSubImmediatePushThrottleAndWriteError(t *testing.T) {
	deltaGate := make(chan struct{})
	releaseEnd := make(chan struct{})
	prov := unitStreamProvider{
		stream: func(ctx context.Context, _ llm.CompletionRequest) iter.Seq2[llm.StreamEvent, error] {
			return func(y func(llm.StreamEvent, error) bool) {
				<-deltaGate
				y(llm.StreamEvent{Type: llm.SEMessageStart, Usage: llm.Usage{InputTokens: 15}}, nil)
				for i := 0; i < 10; i++ {
					y(llm.StreamEvent{Type: llm.SETextDelta, Text: fmt.Sprintf("chunk%d ", i)}, nil)
					time.Sleep(2 * time.Millisecond)
				}
				<-releaseEnd
				y(llm.StreamEvent{Type: llm.SEMessageStop}, nil)
			}
		},
	}

	// 2s DB write throttle + 5s fallback poll: SSE must still push immediately via sideHub!
	s, store, cfg := newUnitSideServer(t, prov, time.Hour, 2*time.Second, 5*time.Second)
	p := sidequestion.Parent{ConversationID: 202}
	snap := sidequestion.Snapshot{
		Parent:     p,
		SessionID:  "conv-202",
		RunID:      1,
		Version:    1,
		CapturedAt: time.Now().UTC(),
		Model:      sideModel(cfg, 0, "unit"),
		Request:    llm.CompletionRequest{MaxTokens: 128, Messages: []llm.Message{llm.UserText("ctx")}},
	}
	s.publishSideSnapshot(snap)

	pw := httptest.NewRecorder()
	s.handleSideQuestions(pw, httptest.NewRequest("POST", "/api/conversations/202/side-questions", bytes.NewBufferString(`{"question":"stream?","client_request_id":"s1"}`)), p)
	if pw.Code != 202 {
		t.Fatalf("POST status=%d body=%s", pw.Code, pw.Body.String())
	}
	e := decodeSide(t, pw)

	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/side-questions/{requestID}/events", s.sideEvents)
	ts := httptest.NewServer(mux)
	defer ts.Close()

	resp, err := http.Get(ts.URL + "/api/side-questions/" + e.ID + "/events")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	received := make(chan sidequestion.Exchange, 64)
	scanDone := make(chan error, 1)
	go func() {
		sc := bufio.NewScanner(resp.Body)
		for sc.Scan() {
			line := sc.Text()
			if strings.HasPrefix(line, "data: ") {
				var ex sidequestion.Exchange
				if err := json.Unmarshal([]byte(strings.TrimPrefix(line, "data: ")), &ex); err == nil {
					received <- ex
				}
			}
		}
		scanDone <- sc.Err()
	}()

	// Initial snapshot arrives immediately.
	select {
	case first := <-received:
		if first.ID != e.ID {
			t.Fatalf("unexpected initial snapshot: %+v", first)
		}
	case <-time.After(time.Second):
		t.Fatal("initial SSE snapshot timed out")
	}

	// Release streaming deltas; verify immediate push well under the 5s fallback poll.
	start := time.Now()
	close(deltaGate)
	sawDelta := false
	for !sawDelta {
		select {
		case ex := <-received:
			if strings.Contains(ex.Answer, "chunk9") {
				sawDelta = true
			}
		case <-time.After(1 * time.Second):
			t.Fatal("streaming delta was not pushed immediately via sideHub")
		}
	}
	if time.Since(start) >= 2*time.Second {
		t.Fatalf("delta push took too long (%v), expected event-driven pub/sub", time.Since(start))
	}

	// While DB progress writes are throttled (<2s), a newly connected SSE client
	// still gets the freshest in-memory snapshot immediately!
	recResp, err := http.Get(ts.URL + "/api/side-questions/" + e.ID + "/events")
	if err != nil {
		t.Fatal(err)
	}
	recSc := bufio.NewScanner(recResp.Body)
	var reconnected sidequestion.Exchange
	for recSc.Scan() {
		if strings.HasPrefix(recSc.Text(), "data: ") {
			_ = json.Unmarshal([]byte(strings.TrimPrefix(recSc.Text(), "data: ")), &reconnected)
			break
		}
	}
	recResp.Body.Close()
	if !strings.Contains(reconnected.Answer, "chunk9") {
		t.Fatalf("reconnect missed live in-memory snapshot: %+v", reconnected)
	}

	// Complete stream; verify terminal state arrives immediately and closes stream.
	close(releaseEnd)
	sawDone := false
	for !sawDone {
		select {
		case ex := <-received:
			if ex.Status == "completed" {
				sawDone = true
			}
		case <-time.After(1 * time.Second):
			t.Fatal("terminal completed event did not arrive immediately")
		}
	}
	select {
	case err := <-scanDone:
		if err != nil {
			t.Fatalf("SSE scanner error: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("SSE connection did not close on terminal state")
	}

	// Verify DB progress writes were throttled (phase changes + terminal only, NOT 10 delta writes!).
	store.mu.Lock()
	updates := store.updateCalls
	store.mu.Unlock()
	if updates > 4 {
		t.Fatalf("expected throttled DB writes (<=4 for phases+terminal), got %d", updates)
	}

	// Verify write error in sideEvents aborts cleanly and unsubscribes from hub.
	runningRow := sidequestion.Exchange{ID: "req-write-err", SessionKey: p.Key(), Status: "running", Sequence: 1}
	store.mu.Lock()
	store.requests[runningRow.ID] = runningRow
	store.mu.Unlock()

	fw := &failingFlushWriter{failAfter: 1} // initial write succeeds, next write fails
	reqCtx, cancelReq := context.WithCancel(t.Context())
	defer cancelReq()
	req := httptest.NewRequest("GET", "/api/side-questions/req-write-err/events", nil).WithContext(reqCtx)
	req.SetPathValue("requestID", runningRow.ID)
	handlerDone := make(chan struct{})
	go func() {
		defer close(handlerDone)
		s.sideEvents(fw, req)
	}()
	// Wait until subscribed, then publish a newer event that triggers Write error.
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		s.side.hub.mu.Lock()
		n := len(s.side.hub.subs[runningRow.ID])
		s.side.hub.mu.Unlock()
		if n == 1 {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	runningRow.Sequence = 2
	runningRow.Answer = "trigger write error"
	s.side.hub.publish(runningRow)
	select {
	case <-handlerDone:
	case <-time.After(time.Second):
		t.Fatal("sideEvents did not abort cleanly on write error")
	}
	s.side.hub.mu.Lock()
	leaked := len(s.side.hub.subs[runningRow.ID])
	s.side.hub.mu.Unlock()
	if leaked != 0 {
		t.Fatalf("sideEvents leaked %d hub subscriber(s) after write error", leaked)
	}

	// Verify sideHub coalescing never blocks publisher and preserves terminal event for slow subscriber.
	slowCh, _, slowUnsub := s.side.hub.subscribe("req-slow")
	defer slowUnsub()
	for i := int64(1); i <= 20; i++ {
		s.side.hub.publish(sidequestion.Exchange{ID: "req-slow", Status: "running", Sequence: i, Answer: fmt.Sprintf("v%d", i)})
	}
	s.side.hub.finish(sidequestion.Exchange{ID: "req-slow", Status: "completed", Sequence: 21, Answer: "final"})
	select {
	case ev := <-slowCh:
		if ev.exchange.Status != "completed" || ev.exchange.Sequence != 21 || ev.exchange.Answer != "final" {
			t.Fatalf("slow subscriber lost terminal event: %+v", ev)
		}
	case <-time.After(time.Second):
		t.Fatal("slow subscriber received nothing")
	}
}
