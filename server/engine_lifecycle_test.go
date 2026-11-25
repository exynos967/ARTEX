package server

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/RC-CHN/ARTEX/agent"
	"github.com/RC-CHN/ARTEX/db"
	"github.com/RC-CHN/ARTEX/selfupdate"
)

func waitForCondition(t *testing.T, timeout time.Duration, desc string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(15 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", desc)
}

func newTestTask(id, status string) *Task {
	return &Task{
		ID:     id,
		Status: status,
		notify: make(chan struct{}, 1),
	}
}

func TestEngineWorkerLoopSkipsResolverWhenPausedOrTerminal(t *testing.T) {
	task := newTestTask("101", "running")
	m := &Manager{tasks: map[string]*Task{task.ID: task}}
	e := NewEngine(m)
	e.debounce = 10 * time.Millisecond

	var resolveCalls atomic.Int64
	e.SetAuthoritativeAgentResolver(func(*Task) (*agent.Planner, *agent.Worker) {
		resolveCalls.Add(1)
		return nil, nil
	})

	// Pause before starting: neither workerLoop nor plannerLoop should call snapshotFor.
	e.Pause(task.ID, agent.AbortPausedByUser)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	e.Run(ctx, task)
	task.Notify()

	time.Sleep(120 * time.Millisecond)
	if got := resolveCalls.Load(); got != 0 {
		t.Fatalf("paused task called resolver %d times, want 0", got)
	}
	e.StopTask(task.ID)
}

func TestEngineTerminalTaskSelfCleansGoroutinesStateAndAgents(t *testing.T) {
	for _, terminal := range []string{"done", "failed", "timeout"} {
		t.Run(terminal, func(t *testing.T) {
			task := newTestTask("201", "running")
			m := &Manager{tasks: map[string]*Task{task.ID: task}}
			e := NewEngine(m)
			e.debounce = 10 * time.Millisecond
			s := &Server{
				m:          m,
				engine:     e,
				taskAgents: map[string]*taskAgentBundle{task.ID: {}},
			}
			e.SetOnTaskStop(s.evictTaskAgents)
			e.SetAuthoritativeAgentResolver(func(*Task) (*agent.Planner, *agent.Worker) {
				return nil, nil
			})

			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			e.Run(ctx, task)
			if !e.Started(task.ID) {
				t.Fatal("expected engine to mark running task as started")
			}

			// Seed per-task maps and exec context to prove every entry is cleaned.
			_ = e.execContextFor(ctx, task.ID)
			e.bumpDrop(task.ID)
			e.nextPlannerRound(task.ID)
			e.BeginLLMCall(task.ID)
			e.EndLLMCall(task.ID)

			// Transition task to terminal state and notify planner so cleanup triggers immediately.
			task.updateLifecycle(func(st *taskLifecycleState) { st.Status = terminal })
			task.Notify()

			waitForCondition(t, 3*time.Second, "terminal task cleanup", func() bool {
				if e.Started(task.ID) {
					return false
				}
				e.runtimeMu.Lock()
				rt := e.runtimes[task.ID]
				draining := len(e.draining[task.ID])
				e.runtimeMu.Unlock()
				if rt != nil || draining != 0 {
					return false
				}
				s.taskAgentMu.Lock()
				_, hasBundle := s.taskAgents[task.ID]
				s.taskAgentMu.Unlock()
				return !hasBundle
			})

			e.execMu.Lock()
			_, hasExecCtx := e.execCtx[task.ID]
			_, hasExecCancel := e.execCancel[task.ID]
			e.execMu.Unlock()
			if hasExecCtx || hasExecCancel {
				t.Fatalf("execCtx/execCancel leaked after terminal cleanup: ctx=%v cancel=%v", hasExecCtx, hasExecCancel)
			}

			for name, sm := range map[string]*syncMapLike{
				"started":      {&e.started},
				"lastAct":      {&e.lastAct},
				"llmCalls":     {&e.llmCalls},
				"paused":       {&e.paused},
				"dropCnt":      {&e.dropCnt},
				"plannerRound": {&e.plannerRound},
				"settling":     {&e.settling},
				"deadline":     {&e.deadline},
				"stamped":      {&e.stamped},
				"inflight":     {&e.inflight},
				"coordStarted": {&e.coordStarted},
			} {
				if _, ok := sm.Load(task.ID); ok {
					t.Errorf("sync.Map %s leaked entry for task %s", name, task.ID)
				}
			}

			// StopTask must remain safe and idempotent after self-cleanup.
			e.StopTask(task.ID)
		})
	}
}

type syncMapLike struct {
	m interface{ Load(any) (any, bool) }
}

func (s *syncMapLike) Load(k any) (any, bool) { return s.m.Load(k) }

func TestEngineTerminalSelfCleanupWaitsForInflight(t *testing.T) {
	task := newTestTask("202", "running")
	m := &Manager{tasks: map[string]*Task{task.ID: task}}
	e := NewEngine(m)
	e.debounce = 10 * time.Millisecond
	e.SetAuthoritativeAgentResolver(func(*Task) (*agent.Planner, *agent.Worker) {
		return nil, nil
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	e.Run(ctx, task)

	if !e.beginTaskOperation(task.ID) {
		t.Fatal("failed to register inflight operation")
	}
	task.updateLifecycle(func(st *taskLifecycleState) { st.Status = "done" })
	task.Notify()

	// While inflight > 0, terminal self-cleanup must NOT tear down the runtime.
	time.Sleep(150 * time.Millisecond)
	if !e.Started(task.ID) {
		t.Fatal("terminal cleanup tore down runtime while an operation was still in flight")
	}

	e.decInflight(task.ID)
	task.Notify()
	waitForCondition(t, 3*time.Second, "post-inflight terminal cleanup", func() bool {
		return !e.Started(task.ID)
	})
}

func TestSetActiveSkipsTerminalTask(t *testing.T) {
	task := newTestTask("301", "done")
	m := &Manager{tasks: map[string]*Task{task.ID: task}}
	e := NewEngine(m)
	s := &Server{
		m:      m,
		engine: e,
		ctx:    context.Background(),
	}

	req := httptest.NewRequest(http.MethodPost, "/api/tasks/active", strings.NewReader(`{"id":"301"}`))
	rec := httptest.NewRecorder()
	s.setActive(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("setActive status = %d, want 200 (body=%s)", rec.Code, rec.Body.String())
	}
	if e.Started(task.ID) {
		t.Fatal("setActive must not start Engine loops for a terminal task")
	}
	if active := m.ActiveTask(); active == nil || active.ID != task.ID {
		t.Fatalf("active task = %v, want %s", active, task.ID)
	}

	// Direct Engine.Run on an already terminal task is also a no-op.
	e.Run(context.Background(), task)
	if e.Started(task.ID) {
		t.Fatal("Engine.Run must skip already-terminal tasks")
	}
}

func TestEmitActivityStripsDetailFromBroadcast(t *testing.T) {
	task := newTestTask("401", "running")
	e := NewEngine(nil)
	var persisted db.Activity
	e.appendActivityFn = func(_ *Task, r db.Activity) (int64, error) {
		persisted = r
		return 77, nil
	}

	ch, unsub := e.Broadcaster().Subscribe(task.ID)
	defer unsub()

	hugeDetail := strings.Repeat("D", 16*1024)
	returned := e.emitActivity(task, db.Activity{
		Worker:  "worker",
		Kind:    "tool_result",
		Summary: "ran scan",
		Detail:  hugeDetail,
	})

	if returned.ID != 77 || returned.Detail != hugeDetail {
		t.Fatalf("returned activity must retain full Detail and ID: id=%d detailLen=%d", returned.ID, len(returned.Detail))
	}
	if persisted.Detail != hugeDetail {
		t.Fatalf("persisted activity Detail length = %d, want %d", len(persisted.Detail), len(hugeDetail))
	}
	select {
	case got := <-ch:
		if got.ID != 77 {
			t.Fatalf("broadcast ID = %d, want 77", got.ID)
		}
		if got.Detail != "" {
			t.Fatalf("broadcast Detail was not stripped: len=%d", len(got.Detail))
		}
		if got.Summary != "ran scan" {
			t.Fatalf("broadcast Summary = %q, want %q", got.Summary, "ran scan")
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for broadcast activity")
	}
}

type failingFlusherWriter struct {
	hdr       http.Header
	failAfter int
	writes    int
}

func (f *failingFlusherWriter) Header() http.Header {
	if f.hdr == nil {
		f.hdr = http.Header{}
	}
	return f.hdr
}

func (f *failingFlusherWriter) WriteHeader(int) {}
func (f *failingFlusherWriter) Flush()          {}

func (f *failingFlusherWriter) Write(p []byte) (int, error) {
	f.writes++
	if f.writes > f.failAfter {
		return 0, errors.New("broken pipe")
	}
	return len(p), nil
}

func TestStreamLogsEmitsIDHonorsLastEventIDAndAbortsOnWriteError(t *testing.T) {
	// Seed two distinct log entries in logSink.
	_, _ = logSink.Write([]byte("[test] sse-log-one\n"))
	_, _ = logSink.Write([]byte("[test] sse-log-two\n"))
	lines, _ := logSink.recent(0, 10)
	if len(lines) < 2 {
		t.Fatalf("expected at least 2 log lines, got %d", len(lines))
	}
	firstSeq := lines[len(lines)-2].Seq
	secondSeq := lines[len(lines)-1].Seq

	s := &Server{}

	// 1. Reconnect with Last-Event-ID=firstSeq must skip firstSeq and emit id: <secondSeq>.
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	srv := httptest.NewServer(http.HandlerFunc(s.streamLogs))
	defer srv.Close()

	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, srv.URL+"?since=0", nil)
	req.Header.Set("Last-Event-ID", fmt.Sprintf("%d", firstSeq))
	resp, err := srv.Client().Do(req)
	if err != nil {
		t.Fatalf("GET streamLogs: %v", err)
	}
	defer resp.Body.Close()

	sc := bufio.NewScanner(resp.Body)
	var idLine, dataLine string
	for sc.Scan() {
		line := sc.Text()
		if strings.HasPrefix(line, "id: ") {
			idLine = line
		}
		if strings.HasPrefix(line, "data: ") {
			dataLine = line
			cancel()
			break
		}
	}
	wantID := fmt.Sprintf("id: %d", secondSeq)
	if idLine != wantID {
		t.Fatalf("SSE id line = %q, want %q (data=%q)", idLine, wantID, dataLine)
	}
	if !strings.Contains(dataLine, "sse-log-two") {
		t.Fatalf("Last-Event-ID was not honored; got %q", dataLine)
	}

	// 2. Write error during streamLogs must return immediately instead of hanging.
	fw := &failingFlusherWriter{failAfter: 0}
	req2 := httptest.NewRequest(http.MethodGet, "/api/logs/stream?since=0", nil)
	done := make(chan struct{})
	go func() {
		defer close(done)
		s.streamLogs(fw, req2)
	}()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("streamLogs did not abort on write error")
	}
}

func TestUpdateStreamAbortsOnWriteErrorAndCancel(t *testing.T) {
	s := &Server{}
	updHub.publish(selfupdate.PhaseIdle, -1, "idle")

	fw := &failingFlusherWriter{failAfter: 0}
	req := httptest.NewRequest(http.MethodGet, "/api/update/stream", nil)
	done := make(chan struct{})
	go func() {
		defer close(done)
		s.updateStream(fw, req)
	}()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("updateStream did not abort on write error")
	}

	// Cancelled context returns immediately without writing.
	cctx, cancel := context.WithCancel(context.Background())
	cancel()
	fw2 := &failingFlusherWriter{failAfter: 10}
	req2 := httptest.NewRequest(http.MethodGet, "/api/update/stream", nil).WithContext(cctx)
	s.updateStream(fw2, req2)
	if fw2.writes != 0 {
		t.Fatalf("updateStream wrote %d times after context cancelled", fw2.writes)
	}
}

func TestEndpointLimitClamps(t *testing.T) {
	// Activity limit: [1, 500].
	if got := clampActivityLimit(-10); got != 1 {
		t.Errorf("clampActivityLimit(-10) = %d, want 1", got)
	}
	if got := clampActivityLimit(0); got != 1 {
		t.Errorf("clampActivityLimit(0) = %d, want 1", got)
	}
	if got := clampActivityLimit(250); got != 250 {
		t.Errorf("clampActivityLimit(250) = %d, want 250", got)
	}
	if got := clampActivityLimit(9999); got != 500 {
		t.Errorf("clampActivityLimit(9999) = %d, want 500", got)
	}

	// Commands / LLM records page & size: page >= 0, size in [1, 200].
	p, sz := clampCommandPageParams(url.Values{})
	if p != 0 || sz != 50 {
		t.Errorf("default clampCommandPageParams = (%d,%d), want (0,50)", p, sz)
	}
	p, sz = clampCommandPageParams(url.Values{"page": {"-5"}, "size": {"0"}})
	if p != 0 || sz != 1 {
		t.Errorf("low clampCommandPageParams = (%d,%d), want (0,1)", p, sz)
	}
	p, sz = clampCommandPageParams(url.Values{"page": {"3"}, "size": {"9999"}})
	if p != 3 || sz != 200 {
		t.Errorf("high clampCommandPageParams = (%d,%d), want (3,200)", p, sz)
	}

	// Legacy unpaginated task intercepts cap at 500 while preserving total.
	empty, total := capLegacyIntercepts(nil, maxLegacyTaskIntercepts)
	if empty == nil || len(empty) != 0 || total != 0 {
		t.Fatalf("nil intercepts: len=%d total=%d nil=%v", len(empty), total, empty == nil)
	}
	many := make([]db.InterceptApprovalRow, 650)
	capped, total := capLegacyIntercepts(many, maxLegacyTaskIntercepts)
	if len(capped) != 500 || total != 650 {
		t.Fatalf("capLegacyIntercepts(650) = (len=%d, total=%d), want (500, 650)", len(capped), total)
	}
}
