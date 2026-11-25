package server

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/RC-CHN/ARTEX/agent"
	"github.com/RC-CHN/ARTEX/db"
	"github.com/RC-CHN/ARTEX/notify"
)

func TestLogWriterReleasesQueueOnStop(t *testing.T) {
	pool, err := sql.Open("pgx", "postgres://unused.invalid/test")
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	s := &logSinkT{cap: 1}
	done := s.SetDB(ctx, &db.DB{DB: pool})
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("writer did not stop")
	}
	if s.dbCh != nil {
		t.Fatal("stopped writer retained its queue")
	}
}

func TestLogCapturePreview(t *testing.T) {
	for _, tc := range []struct {
		name      string
		text      string
		truncated bool
	}{
		{"short", "[pg] ready", false},
		{"at limit", strings.Repeat("a", 8192), false},
		{"long multibyte", "[pg] " + strings.Repeat("界", 8192), true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var terminal bytes.Buffer
			s := &logSinkT{cap: 1, out: &terminal, subs: map[chan LogLine]struct{}{}, dbCh: make(chan dbWriteReq, 1)}
			stream, stop := s.subscribe()
			defer stop()
			p := []byte(tc.text + "\n")
			n, err := s.Write(p)
			if err != nil || n != len(p) || !bytes.Equal(terminal.Bytes(), p) {
				t.Fatal("terminal passthrough changed")
			}
			lines, _ := s.recent(0, 1)
			if len(lines) != 1 {
				t.Fatalf("captured %d lines", len(lines))
			}
			line := lines[0]
			if line != (<-s.dbCh).ll || line != <-stream {
				t.Fatal("preview differs between consumers")
			}
			if len(line.Text) > 8192 || !utf8.ValidString(line.Text) {
				t.Fatalf("invalid log preview: %d bytes", len(line.Text))
			}
			if tc.truncated {
				if !strings.HasSuffix(line.Text, " [truncated]") || line.Tag != "pg" {
					t.Fatal("missing truncation marker or tag")
				}
			} else if line.Text != tc.text {
				t.Fatal("short log changed")
			}
		})
	}
}

type mockLogWriter struct {
	mu      sync.Mutex
	recent  []*db.DBLog
	nextID  int64
	batches [][]db.LogBatchEntry
	err     error
	onBatch func(n int)
}

func (m *mockLogWriter) RecentLogsContext(ctx context.Context, _ int) ([]*db.DBLog, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]*db.DBLog, len(m.recent))
	copy(out, m.recent)
	return out, nil
}

func (m *mockLogWriter) InsertLogsBatchContext(ctx context.Context, entries []db.LogBatchEntry) ([]int64, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.err != nil {
		return nil, m.err
	}
	cp := make([]db.LogBatchEntry, len(entries))
	copy(cp, entries)
	m.batches = append(m.batches, cp)
	ids := make([]int64, len(entries))
	for i := range entries {
		m.nextID++
		ids[i] = m.nextID
	}
	if m.onBatch != nil {
		m.onBatch(len(entries))
	}
	return ids, nil
}

func (m *mockLogWriter) setErr(err error) {
	m.mu.Lock()
	m.err = err
	m.mu.Unlock()
}

func (m *mockLogWriter) batchSizes() []int {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]int, len(m.batches))
	for i, b := range m.batches {
		out[i] = len(b)
	}
	return out
}

type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

func TestLogSinkMicroBatchBurstAndDBIDStamp(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	var totalInserted atomic.Int64
	writer := &mockLogWriter{
		recent: []*db.DBLog{
			{ID: 7, CreatedAt: time.Now(), Level: "info", Tag: "boot", Text: "[boot] restored"},
		},
		nextID: 100,
		onBatch: func(n int) {
			totalInserted.Add(int64(n))
		},
	}

	s := &logSinkT{cap: 200, subs: map[chan LogLine]struct{}{}, out: &bytes.Buffer{}}
	done := s.setLogWriter(ctx, writer, logWriterOptions{
		batchMax:     64,
		flushWindow:  40 * time.Millisecond,
		writeTimeout: time.Second,
		backoffBase:  20 * time.Millisecond,
		backoffMax:   80 * time.Millisecond,
		errOut:       &syncBuffer{},
	})

	for i := 0; i < 100; i++ {
		_, _ = s.Write([]byte(fmt.Sprintf("[burst] message %d\n", i)))
	}

	waitForCondition(t, 2*time.Second, "100 burst logs flushed", func() bool {
		return totalInserted.Load() == 100
	})

	sizes := writer.batchSizes()
	if len(sizes) != 2 || sizes[0] != 64 || sizes[1] != 36 {
		t.Fatalf("batch sizes=%v want [64 36]", sizes)
	}

	lines, _ := s.recent(0, 200)
	if len(lines) != 101 {
		t.Fatalf("ring lines=%d want 101 (1 restored + 100 burst)", len(lines))
	}
	if lines[0].DBID != 7 {
		t.Fatalf("restored line DBID=%d want 7", lines[0].DBID)
	}
	for i := 1; i <= 100; i++ {
		wantID := int64(100 + i)
		if lines[i].DBID != wantID {
			t.Fatalf("line %d DBID=%d want %d", i, lines[i].DBID, wantID)
		}
	}

	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("writer did not stop")
	}
}

func TestLogSinkSingleLogFlushesOnTimer(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	var flushed atomic.Int32
	writer := &mockLogWriter{
		nextID:  500,
		onBatch: func(int) { flushed.Add(1) },
	}
	s := &logSinkT{cap: 16, subs: map[chan LogLine]struct{}{}, out: &bytes.Buffer{}}
	done := s.setLogWriter(ctx, writer, logWriterOptions{
		batchMax:     64,
		flushWindow:  25 * time.Millisecond,
		writeTimeout: time.Second,
		errOut:       &syncBuffer{},
	})

	_, _ = s.Write([]byte("[single] timer flush\n"))
	waitForCondition(t, time.Second, "single log flushed by timer", func() bool {
		return flushed.Load() == 1
	})

	sizes := writer.batchSizes()
	if len(sizes) != 1 || sizes[0] != 1 {
		t.Fatalf("batch sizes=%v want [1]", sizes)
	}
	lines, _ := s.recent(0, 16)
	if len(lines) != 1 || lines[0].DBID != 501 {
		t.Fatalf("unexpected ring line after timer flush: %+v", lines)
	}

	cancel()
	<-done
}

func TestLogSinkCircuitBreakerExponentialBackoffAndRecovery(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	errBuf := &syncBuffer{}
	var succeeded atomic.Int32
	writer := &mockLogWriter{
		err:     errors.New("db unavailable"),
		nextID:  900,
		onBatch: func(int) { succeeded.Add(1) },
	}
	s := &logSinkT{cap: 64, subs: map[chan LogLine]struct{}{}, out: &bytes.Buffer{}}
	done := s.setLogWriter(ctx, writer, logWriterOptions{
		batchMax:     4,
		flushWindow:  10 * time.Millisecond,
		writeTimeout: time.Second,
		backoffBase:  25 * time.Millisecond,
		backoffMax:   100 * time.Millisecond,
		errOut:       errBuf,
	})

	// Trigger first failure (backoff 25ms) and verify heavy writes never block while circuit is open.
	_, _ = s.Write([]byte("[cb] first\n"))
	waitForCondition(t, time.Second, "first backoff log", func() bool {
		return strings.Contains(errBuf.String(), "backoff 25ms")
	})

	writeDone := make(chan struct{})
	go func() {
		defer close(writeDone)
		for i := 0; i < 300; i++ {
			_, _ = s.Write([]byte(fmt.Sprintf("[cb] burst %d\n", i)))
		}
	}()
	select {
	case <-writeDone:
	case <-time.After(time.Second):
		t.Fatal("Write blocked while circuit breaker was open")
	}

	// Drive two more failure probes to verify exponential backoff 25ms -> 50ms -> 100ms (capped).
	waitForCondition(t, 2*time.Second, "exponential backoff steps", func() bool {
		_, _ = s.Write([]byte("[cb] probe\n"))
		out := errBuf.String()
		return strings.Contains(out, "backoff 50ms") && strings.Contains(out, "backoff 100ms")
	})

	// Recover DB: next probe succeeds and stamps DBID, resetting backoff.
	writer.setErr(nil)
	waitForCondition(t, 2*time.Second, "recovery batch succeeds", func() bool {
		_, _ = s.Write([]byte("[cb] recovered\n"))
		return succeeded.Load() >= 1
	})

	lines, _ := s.recent(0, 64)
	stamped := false
	for _, l := range lines {
		if l.DBID >= 901 {
			stamped = true
			break
		}
	}
	if !stamped {
		t.Fatal("expected DBID stamped after circuit breaker recovery")
	}

	cancel()
	<-done
}

func TestLogSinkRingCompactionZeroesTail(t *testing.T) {
	s := &logSinkT{cap: 4, subs: map[chan LogLine]struct{}{}, out: &bytes.Buffer{}}
	for i := 1; i <= 10; i++ {
		_, _ = s.Write([]byte(fmt.Sprintf("[ring] line-%d\n", i)))
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.ring) != 4 {
		t.Fatalf("len(s.ring)=%d want 4", len(s.ring))
	}
	for i, want := range []string{"[ring] line-7", "[ring] line-8", "[ring] line-9", "[ring] line-10"} {
		if s.ring[i].Text != want {
			t.Fatalf("ring[%d].Text=%q want %q", i, s.ring[i].Text, want)
		}
	}
	backing := s.ring[:cap(s.ring)]
	for i := len(s.ring); i < len(backing); i++ {
		if backing[i] != (LogLine{}) {
			t.Fatalf("vacated backing slot %d not zeroed: %+v", i, backing[i])
		}
	}
}

func TestNotifierRenderBatchBulkAssetLookup(t *testing.T) {
	var calls atomic.Int32
	var gotIDs []int64
	n := &Notifier{
		buckets: map[int64]*notifyBucket{},
		assetNamesBatchFn: func(_ context.Context, ids []int64) (map[int64]string, error) {
			calls.Add(1)
			gotIDs = append([]int64(nil), ids...)
			return map[int64]string{
				10: "https://a.example.com",
				20: "b.example.com",
				30: "10.0.0.1",
			}, nil
		},
	}

	makeDelivery := func(id, findingID int64, assetIDs []int64) *db.NotificationDelivery {
		raw, _ := json.Marshal(notify.Snapshot{
			Kind:      notify.EventFindingCreated,
			FindingID: findingID,
			Name:      fmt.Sprintf("finding-%d", findingID),
			VulnClass: "SQLi",
			Severity:  "high",
			AssetIDs:  assetIDs,
		})
		return &db.NotificationDelivery{
			ID:        id,
			FindingID: findingID,
			EventKind: notify.EventFindingCreated,
			Snapshot:  raw,
		}
	}

	deliveries := make([]*db.NotificationDelivery, 0, 20)
	for i := 0; i < 19; i++ {
		assets := []int64{10, 999, 20, 10}
		if i%2 == 1 {
			assets = []int64{30, 20}
		}
		deliveries = append(deliveries, makeDelivery(int64(i+1), int64(100+i), assets))
	}
	// Inject one corrupt snapshot in the middle to verify 1:1 included<->items alignment.
	deliveries = append(deliveries, &db.NotificationDelivery{
		ID:       999,
		Snapshot: json.RawMessage(`{invalid`),
	})

	msg, included, err := n.renderBatch(t.Context(), deliveries, "https://artex.example.com", 30)
	if err != nil {
		t.Fatalf("renderBatch err=%v", err)
	}
	if calls.Load() != 1 {
		t.Fatalf("assetNamesBatchFn calls=%d want 1 (eliminates N+1)", calls.Load())
	}
	if len(gotIDs) != 4 {
		t.Fatalf("unique requested asset IDs=%v want 4 unique IDs [10 999 20 30]", gotIDs)
	}
	if len(msg.Items) != 19 || len(included) != 19 {
		t.Fatalf("items=%d included=%d want 19/19", len(msg.Items), len(included))
	}
	for i, item := range msg.Items {
		if item.FindingID != included[i].FindingID {
			t.Fatalf("index %d mismatch: item=%d included=%d", i, item.FindingID, included[i].FindingID)
		}
		wantURL := fmt.Sprintf("https://artex.example.com/function/findings/detail?id=%d", item.FindingID)
		if item.DetailURL != wantURL {
			t.Fatalf("DetailURL=%q want %q", item.DetailURL, wantURL)
		}
		if i%2 == 0 {
			if strings.Join(item.Assets, ",") != "https://a.example.com,b.example.com" {
				t.Fatalf("item %d assets=%v", i, item.Assets)
			}
		} else if strings.Join(item.Assets, ",") != "10.0.0.1,b.example.com" {
			t.Fatalf("item %d assets=%v", i, item.Assets)
		}
	}

	// Bulk lookup error degrades gracefully without dropping the notification batch.
	nErr := &Notifier{
		buckets: map[int64]*notifyBucket{},
		assetNamesBatchFn: func(context.Context, []int64) (map[int64]string, error) {
			return nil, errors.New("temporary pg error")
		},
	}
	msg2, inc2, err := nErr.renderBatch(t.Context(), deliveries[:2], "", 15)
	if err != nil || len(msg2.Items) != 2 || len(inc2) != 2 || len(msg2.Items[0].Assets) != 0 {
		t.Fatalf("degraded batch = (%+v, %d, %v)", msg2, len(inc2), err)
	}
}

func TestUsageAggregateTaskTokensSinglePass(t *testing.T) {
	if !strings.Contains(taskTokenStatsQuery, "FROM activity a") ||
		!strings.Contains(taskTokenStatsQuery, "LEFT JOIN exploration_nodes n") {
		t.Fatalf("unexpected taskTokenStatsQuery: %s", taskTokenStatsQuery)
	}

	// Empty buckets -> non-nil slices and zero total.
	emptyW, emptyS, emptyTot := aggregateTaskTokenRows(nil)
	if emptyW == nil || emptyS == nil || len(emptyW) != 0 || len(emptyS) != 0 || emptyTot != (db.TokenUsage{}) {
		t.Fatalf("empty aggregate = (%v, %v, %+v)", emptyW, emptyS, emptyTot)
	}

	buckets := []taskTokenBucket{
		{Worker: "mainagent", Session: "main:0", InputTokens: 11, OutputTokens: 12, CacheReadTokens: 13, CacheWriteTokens: 14},
		{Worker: "mainagent", Session: "main:1", InputTokens: 5, OutputTokens: 6, CacheReadTokens: 7, CacheWriteTokens: 8},
		{Worker: "planner", Session: "plan", InputTokens: 21, OutputTokens: 22, CacheReadTokens: 23, CacheWriteTokens: 24},
		// Multiple workers retrying the same intent merge into one intent:42 session.
		{Worker: "work#1", Session: "intent:42", InputTokens: 100, OutputTokens: 200, CacheReadTokens: 300, CacheWriteTokens: 400},
		{Worker: "work#2", Session: "intent:42", InputTokens: 50, OutputTokens: 60, CacheReadTokens: 70, CacheWriteTokens: 80},
		// Non-intent rows remain in workers + total, but are excluded from sessions.
		{Worker: "work#fact", Session: "", InputTokens: 31, OutputTokens: 32, CacheReadTokens: 33, CacheWriteTokens: 34},
	}

	workers, sessions, total := aggregateTaskTokenRows(buckets)
	if len(workers) != 5 {
		t.Fatalf("workers=%+v want 5 entries", workers)
	}
	// Sorted alphabetically: mainagent, planner, work#1, work#2, work#fact.
	if workers[0].Worker != "mainagent" || workers[0].InputTokens != 16 || workers[0].OutputTokens != 18 {
		t.Fatalf("mainagent worker=%+v want input=16 output=18", workers[0])
	}
	if workers[4].Worker != "work#fact" || workers[4].InputTokens != 31 {
		t.Fatalf("work#fact worker=%+v", workers[4])
	}

	if len(sessions) != 4 {
		t.Fatalf("sessions=%+v want 4 entries (intent:42, main:0, main:1, plan)", sessions)
	}
	if sessions[0].Session != "intent:42" || sessions[0].InputTokens != 150 || sessions[0].OutputTokens != 260 {
		t.Fatalf("merged intent session=%+v want input=150 output=260", sessions[0])
	}
	if sessions[1].Session != "main:0" || sessions[2].Session != "main:1" || sessions[3].Session != "plan" {
		t.Fatalf("unexpected session ordering: %+v", sessions)
	}

	if total.InputTokens != 218 || total.OutputTokens != 332 ||
		total.CacheReadTokens != 446 || total.CacheWriteTokens != 560 {
		t.Fatalf("total=%+v want 218/332/446/560", total)
	}
}

func TestEngineWorkerLoopIdleAndBudgetBackoffWithWake(t *testing.T) {
	t.Run("budget_blocked_backs_off_and_wakes_on_task_notify", func(t *testing.T) {
		task := newTestTask("401", "running")
		m := &Manager{tasks: map[string]*Task{task.ID: task}}
		e := NewEngine(m)
		e.debounce = 5 * time.Millisecond
		e.workerIdleBase = 20 * time.Millisecond
		e.workerIdleMax = 80 * time.Millisecond
		e.workerBudgetWait = 400 * time.Millisecond

		var probes atomic.Int32
		e.workerStepHookFn = func(context.Context, *Task, string, *agent.Worker) workerStepOutcome {
			probes.Add(1)
			return workerStepBudgetBlocked
		}
		// Non-nil worker so workerLoop enters runWorkerStepOutcome; planner is nil so plannerLoop stays light.
		e.SetAuthoritativeAgentResolver(func(*Task) (*agent.Planner, *agent.Worker) {
			return nil, &agent.Worker{}
		})

		ctx, cancel := context.WithCancel(t.Context())
		defer cancel()
		e.Run(ctx, task)
		defer e.StopTask(task.ID)

		waitForCondition(t, time.Second, "first budget-blocked probe", func() bool {
			return probes.Load() >= 1
		})
		// While sleeping on the 400ms budgetWait, probes should stay quiet for 120ms.
		before := probes.Load()
		time.Sleep(120 * time.Millisecond)
		if after := probes.Load(); after != before {
			t.Fatalf("budget-blocked worker polled too eagerly: before=%d after=%d", before, after)
		}

		// task.Notify() wakes plannerLoop which relays broadcastWake to sleeping workers immediately.
		wakeAt := time.Now()
		task.Notify()
		waitForCondition(t, 200*time.Millisecond, "worker woken immediately by task.Notify", func() bool {
			return probes.Load() > before
		})
		if elapsed := time.Since(wakeAt); elapsed >= 200*time.Millisecond {
			t.Fatalf("worker wake took %v, want <200ms", elapsed)
		}
	})

	t.Run("idle_worker_backs_off_progressively_and_wakes_immediately", func(t *testing.T) {
		task := newTestTask("402", "running")
		m := &Manager{tasks: map[string]*Task{task.ID: task}}
		e := NewEngine(m)
		e.debounce = 5 * time.Millisecond
		e.workerIdleBase = 20 * time.Millisecond
		e.workerIdleMax = 160 * time.Millisecond
		e.workerBudgetWait = 500 * time.Millisecond

		var mu sync.Mutex
		var stamps []time.Time
		e.workerStepHookFn = func(context.Context, *Task, string, *agent.Worker) workerStepOutcome {
			mu.Lock()
			stamps = append(stamps, time.Now())
			mu.Unlock()
			return workerStepIdle
		}
		e.SetAuthoritativeAgentResolver(func(*Task) (*agent.Planner, *agent.Worker) {
			return nil, &agent.Worker{}
		})

		ctx, cancel := context.WithCancel(t.Context())
		defer cancel()
		e.Run(ctx, task)
		defer e.StopTask(task.ID)

		waitForCondition(t, 2*time.Second, "4 idle probes", func() bool {
			mu.Lock()
			defer mu.Unlock()
			return len(stamps) >= 4
		})

		mu.Lock()
		firstGap := stamps[1].Sub(stamps[0])
		thirdGap := stamps[3].Sub(stamps[2])
		countBeforeWake := len(stamps)
		mu.Unlock()

		// Backoff sequence is 20ms -> 40ms -> 80ms -> 160ms, so gap[2] must be notably larger than gap[0].
		if thirdGap <= firstGap {
			t.Fatalf("idle backoff did not grow: firstGap=%v thirdGap=%v", firstGap, thirdGap)
		}

		// Broadcast wake cuts the 160ms wait short immediately.
		e.wakeWorkers(task.ID)
		waitForCondition(t, 120*time.Millisecond, "idle worker woken by broadcast", func() bool {
			mu.Lock()
			defer mu.Unlock()
			return len(stamps) > countBeforeWake
		})
	})
}
