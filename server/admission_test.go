package server

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/RC-CHN/ARTEX/agent"
)

func TestAdmissionBlocksWhenFullReleasesAndCancels(t *testing.T) {
	// Nil receiver must be a safe no-op for zero-value test Servers.
	var nilAdm *runAdmission
	relNil, err := nilAdm.Acquire(context.Background())
	if err != nil {
		t.Fatalf("nil Acquire failed: %v", err)
	}
	relNil()
	if relTry, ok := nilAdm.TryAcquire(); !ok {
		t.Fatal("nil TryAcquire should succeed")
	} else {
		relTry()
	}
	if inFlight, capacity := nilAdm.Stats(); inFlight != 0 || capacity != 0 {
		t.Fatalf("nil Stats = (%d,%d), want (0,0)", inFlight, capacity)
	}

	adm := newRunAdmission(2)
	rel1, err := adm.Acquire(context.Background())
	if err != nil {
		t.Fatalf("acquire 1: %v", err)
	}
	rel2, ok := adm.TryAcquire()
	if !ok {
		t.Fatal("TryAcquire 2 should succeed")
	}
	if inFlight, capacity := adm.Stats(); inFlight != 2 || capacity != 2 {
		t.Fatalf("Stats when full = (%d,%d), want (2,2)", inFlight, capacity)
	}
	if _, ok := adm.TryAcquire(); ok {
		t.Fatal("TryAcquire should fail when full")
	}

	// Acquire must block when full and abort promptly on ctx.Done().
	cancelCtx, cancel := context.WithCancel(context.Background())
	waitErr := make(chan error, 1)
	go func() {
		_, err := adm.Acquire(cancelCtx)
		waitErr <- err
	}()
	select {
	case err := <-waitErr:
		t.Fatalf("Acquire returned early while full: %v", err)
	case <-time.After(30 * time.Millisecond):
	}
	cancel()
	select {
	case err := <-waitErr:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("cancelled Acquire err=%v, want context.Canceled", err)
		}
	case <-time.After(time.Second):
		t.Fatal("Acquire did not cancel promptly")
	}

	// Acquire must wake once a slot is released; repeated release must be idempotent.
	acquired3 := make(chan func(), 1)
	go func() {
		rel, err := adm.Acquire(context.Background())
		if err != nil {
			t.Errorf("acquire 3: %v", err)
			return
		}
		acquired3 <- rel
	}()
	time.Sleep(20 * time.Millisecond)
	rel1()
	rel1() // idempotent double release must NOT free a second slot

	var rel3 func()
	select {
	case rel3 = <-acquired3:
	case <-time.After(time.Second):
		t.Fatal("blocked waiter was not admitted after release")
	}
	if inFlight, _ := adm.Stats(); inFlight != 2 {
		t.Fatalf("inFlight after idempotent double release = %d, want 2", inFlight)
	}

	rel2()
	rel3()
	if inFlight, capacity := adm.Stats(); inFlight != 0 || capacity != 2 {
		t.Fatalf("Stats after draining = (%d,%d), want (0,2)", inFlight, capacity)
	}

	// Pre-cancelled context must fail deterministically even when slots are open.
	doneCtx, doneCancel := context.WithCancel(context.Background())
	doneCancel()
	if _, err := adm.Acquire(doneCtx); !errors.Is(err, context.Canceled) {
		t.Fatalf("pre-cancelled Acquire err=%v, want context.Canceled", err)
	}
}

func TestAdmissionEnvBounds(t *testing.T) {
	cases := []struct {
		raw  string
		want int
	}{
		{"", defaultMaxConcurrentAgentRuns},
		{"not-a-number", defaultMaxConcurrentAgentRuns},
		{"0", minConcurrentAgentRuns},
		{"1", minConcurrentAgentRuns},
		{"2", 2},
		{"24", 24},
		{"64", 64},
		{"999", maxConcurrentAgentRuns},
	}
	for _, tc := range cases {
		t.Setenv(envMaxConcurrentAgentRuns, tc.raw)
		if got := maxConcurrentAgentRunsFromEnv(); got != tc.want {
			t.Fatalf("ARTEX_MAX_CONCURRENT_AGENT_RUNS=%q -> %d, want %d", tc.raw, got, tc.want)
		}
	}
}

func TestTriggerMaxParallelBounds(t *testing.T) {
	cases := []struct {
		cfg  triggerBehavior
		want int
	}{
		{triggerBehavior{runMode: "serial", maxParallel: 0}, 1},
		{triggerBehavior{runMode: "serial", maxParallel: 999}, 1},
		{triggerBehavior{runMode: "parallel", maxParallel: 0}, defaultTriggerMaxParallel},
		{triggerBehavior{runMode: "parallel", maxParallel: -3}, defaultTriggerMaxParallel},
		{triggerBehavior{runMode: "parallel", maxParallel: 3}, 3},
		{triggerBehavior{runMode: "parallel", maxParallel: maxTriggerMaxParallel}, maxTriggerMaxParallel},
		{triggerBehavior{runMode: "parallel", maxParallel: 999}, maxTriggerMaxParallel},
	}
	for _, tc := range cases {
		if got := triggerMaxParallel(tc.cfg); got != tc.want {
			t.Fatalf("triggerMaxParallel(%+v) = %d, want %d", tc.cfg, got, tc.want)
		}
	}

	if _, err := validateTriggerMaxParallel(-1); err == nil {
		t.Fatal("validateTriggerMaxParallel(-1) must fail")
	}
	if got, err := validateTriggerMaxParallel(0); err != nil || got != 0 {
		t.Fatalf("validateTriggerMaxParallel(0) = (%d, %v), want (0, nil)", got, err)
	}
	if got, err := validateTriggerMaxParallel(999); err != nil || got != maxTriggerMaxParallel {
		t.Fatalf("validateTriggerMaxParallel(999) = (%d, %v), want (%d, nil)", got, err, maxTriggerMaxParallel)
	}
}

func TestTriggerQueueBoundedAndZerosBackingArray(t *testing.T) {
	s := &Server{
		triggerQ:      map[string][]triggeredRun{},
		triggerActive: map[string]int{},
		triggerCfg:    map[string]triggerBehavior{},
	}
	const key = "bounded_agent"
	cfg := triggerBehavior{runMode: "parallel", mergeMode: "none", maxParallel: 4}

	total := maxTriggerQueuePerAgent + 20
	for i := 0; i < total; i++ {
		s.enqueueTriggeredRunLocked(key, cfg, triggeredRun{
			agentKey: key,
			title:    fmt.Sprintf("title-%d", i),
			message:  fmt.Sprintf("payload-%d", i),
			taskID:   int64(i + 1),
			taskDesc: "large task description",
			taskGoal: "large task goal",
		})
	}

	q := s.triggerQ[key]
	if len(q) != maxTriggerQueuePerAgent {
		t.Fatalf("triggerQ len = %d, want %d", len(q), maxTriggerQueuePerAgent)
	}
	// Oldest 20 items were evicted; head should be item 20 and tail should be total-1.
	if q[0].title != "title-20" || q[len(q)-1].title != fmt.Sprintf("title-%d", total-1) {
		t.Fatalf("queue window mismatch: head=%q tail=%q", q[0].title, q[len(q)-1].title)
	}

	// Keep a view onto the underlying backing array before popping.
	backing := q[:len(q)]
	first := s.nextTriggerRun(key, cfg)
	if first.title != "title-20" {
		t.Fatalf("popped title = %q, want title-20", first.title)
	}
	if backing[0] != (triggeredRun{}) {
		t.Fatalf("popped backing-array slot was not zeroed: %+v", backing[0])
	}

	// Drain the rest and ensure every backing-array slot is zeroed and map entry deleted.
	for len(s.triggerQ[key]) > 0 {
		_ = s.nextTriggerRun(key, cfg)
	}
	if _, exists := s.triggerQ[key]; exists {
		t.Fatal("empty triggerQ entry was not deleted from map")
	}
	for i, slot := range backing {
		if slot != (triggeredRun{}) {
			t.Fatalf("backing slot %d was not zeroed after drain: %+v", i, slot)
		}
	}

	// Verify mergeMode='all' and mergeMode='by_task' also zero backing slots and clean map.
	for _, mode := range []string{"all", "by_task"} {
		mcfg := triggerBehavior{runMode: "serial", mergeMode: mode}
		s.enqueueTriggeredRunLocked(key, mcfg, triggeredRun{agentKey: key, title: "a", message: "m1", taskID: 7, taskDesc: "d", taskGoal: "g", mergeable: true})
		s.enqueueTriggeredRunLocked(key, mcfg, triggeredRun{agentKey: key, title: "b", message: "m2", taskID: 7, taskDesc: "d", taskGoal: "g", mergeable: true})
		snap := s.triggerQ[key][:len(s.triggerQ[key])]
		merged := s.nextTriggerRun(key, mcfg)
		if !strings.Contains(merged.message, "m1") || !strings.Contains(merged.message, "m2") {
			t.Fatalf("mode %s merge lost payloads: %q", mode, merged.message)
		}
		if _, exists := s.triggerQ[key]; exists {
			t.Fatalf("mode %s left empty slice in triggerQ map", mode)
		}
		for i, slot := range snap {
			if slot != (triggeredRun{}) {
				t.Fatalf("mode %s backing slot %d not zeroed: %+v", mode, i, slot)
			}
		}
	}
}

func TestWorkersAndConcurrencyCeilings(t *testing.T) {
	m := &Manager{}
	if err := m.SetWorkers(0); err == nil {
		t.Fatal("SetWorkers(0) must be rejected")
	}
	if err := m.SetWorkers(-5); err == nil {
		t.Fatal("SetWorkers(-5) must be rejected")
	}
	if err := m.SetWorkers(maxWorkersPerTask + 1); err == nil {
		t.Fatalf("SetWorkers(%d) must be rejected", maxWorkersPerTask+1)
	}
	if got := m.Workers(); got != defaultWorkers {
		t.Fatalf("default Workers() = %d, want %d", got, defaultWorkers)
	}

	enabled, limit := m.ConcurrencyLimit()
	if !enabled || limit != defaultConcurrencyLimit {
		t.Fatalf("default ConcurrencyLimit() = (%v, %d), want (true, %d)", enabled, limit, defaultConcurrencyLimit)
	}
	if err := m.SetConcurrency(true, maxConcurrencyLimit+1); err == nil {
		t.Fatalf("SetConcurrency(true, %d) must be rejected", maxConcurrencyLimit+1)
	}

	// Verify putSettings rejects over-cap workers and task_concurrency_limit with 400.
	s := &Server{m: m}
	for _, body := range []string{
		fmt.Sprintf(`{"workers":%d}`, maxWorkersPerTask+1),
		`{"workers":0}`,
		fmt.Sprintf(`{"task_concurrency_limit":%d}`, maxConcurrencyLimit+1),
		`{"task_concurrency_limit":0}`,
	} {
		rec := httptest.NewRecorder()
		s.putSettings(rec, httptest.NewRequest(http.MethodPut, "/api/settings", strings.NewReader(body)))
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("putSettings(%s) status = %d, want 400 (body=%s)", body, rec.Code, rec.Body.String())
		}
	}
}

func TestEngineCompactionContextCancelledOnStopAndPause(t *testing.T) {
	m := &Manager{tasks: map[string]*Task{}}
	e := NewEngine(m)
	parent, cancelParent := context.WithCancel(context.Background())
	defer cancelParent()

	c1 := e.compactionContextFor(parent, "1")
	if c1.Err() != nil {
		t.Fatalf("fresh compaction context already cancelled: %v", c1.Err())
	}
	e.Pause("1", agent.AbortPausedByUser)
	if c1.Err() == nil {
		t.Fatal("Pause did not cancel task compaction context")
	}

	e.Resume(&Task{ID: "1", notify: make(chan struct{}, 1)})
	c2 := e.compactionContextFor(parent, "1")
	if c2.Err() != nil {
		t.Fatalf("compaction context after Resume already cancelled: %v", c2.Err())
	}
	e.StopTask("1")
	if c2.Err() == nil {
		t.Fatal("StopTask did not cancel task compaction context")
	}
}
