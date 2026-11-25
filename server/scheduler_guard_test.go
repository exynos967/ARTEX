package server

import (
	"errors"
	"testing"

	"github.com/RC-CHN/ARTEX/db"
)

type fakeSchedulerStore struct {
	triggers        []*db.AgentTrigger
	triggersErr     error
	state           map[string]string
	setStateCalls   int
	maxFindingID    int64
	maxToolResultID int64
	maxTimeoutID    int64
	maxTaskID       int64
	metGoals        []db.TaskEvent

	calls map[string]int
}

func newFakeSchedulerStore() *fakeSchedulerStore {
	return &fakeSchedulerStore{
		state: map[string]string{},
		calls: map[string]int{},
	}
}

func (f *fakeSchedulerStore) bump(name string) { f.calls[name]++ }

func (f *fakeSchedulerStore) ListEnabledTriggers() ([]*db.AgentTrigger, error) {
	f.bump("ListEnabledTriggers")
	return f.triggers, f.triggersErr
}

func (f *fakeSchedulerStore) GetSchedState(key string) (string, error) {
	f.bump("GetSchedState")
	return f.state[key], nil
}

func (f *fakeSchedulerStore) SetSchedState(key, value string) error {
	f.bump("SetSchedState")
	f.setStateCalls++
	f.state[key] = value
	return nil
}

func (f *fakeSchedulerStore) TouchTriggerFire(int64) error {
	f.bump("TouchTriggerFire")
	return nil
}

func (f *fakeSchedulerStore) MaxFindingID() (int64, error) {
	f.bump("MaxFindingID")
	return f.maxFindingID, nil
}

func (f *fakeSchedulerStore) MaxToolResultActivityID() (int64, error) {
	f.bump("MaxToolResultActivityID")
	return f.maxToolResultID, nil
}

func (f *fakeSchedulerStore) MaxTimedOutTaskID() (int64, error) {
	f.bump("MaxTimedOutTaskID")
	return f.maxTimeoutID, nil
}

func (f *fakeSchedulerStore) MaxTaskID() (int64, error) {
	f.bump("MaxTaskID")
	return f.maxTaskID, nil
}

func (f *fakeSchedulerStore) NewFindingsSince(int64) ([]db.TaskEvent, error) {
	f.bump("NewFindingsSince")
	return nil, nil
}

func (f *fakeSchedulerStore) TimedOutTasksSince(int64) ([]db.TaskEvent, error) {
	f.bump("TimedOutTasksSince")
	return nil, nil
}

func (f *fakeSchedulerStore) NewTasksSince(int64) ([]db.TaskEvent, error) {
	f.bump("NewTasksSince")
	return nil, nil
}

func (f *fakeSchedulerStore) NewToolCallsSince(int64) ([]db.TaskEvent, error) {
	f.bump("NewToolCallsSince")
	return nil, nil
}

func (f *fakeSchedulerStore) MetGoals() ([]db.TaskEvent, error) {
	f.bump("MetGoals")
	return f.metGoals, nil
}

func TestSchedulerInitUsesMaxIDFastPath(t *testing.T) {
	store := newFakeSchedulerStore()
	store.maxFindingID = 101
	store.maxToolResultID = 9001
	store.maxTimeoutID = 17
	store.maxTaskID = 55
	store.metGoals = []db.TaskEvent{{NodeID: 7}}

	sc := &Scheduler{store: store}
	sc.init()

	if store.state[schedKeyLastFinding] != "101" {
		t.Fatalf("last_finding_id=%q want 101", store.state[schedKeyLastFinding])
	}
	if store.state[schedKeyLastToolCall] != "9001" {
		t.Fatalf("last_toolcall_id=%q want 9001", store.state[schedKeyLastToolCall])
	}
	if store.state[schedKeyLastTimeout] != "17" {
		t.Fatalf("last_timeout_id=%q want 17", store.state[schedKeyLastTimeout])
	}
	if store.state[schedKeyLastTaskCreate] != "55" {
		t.Fatalf("last_taskcreate_id=%q want 55", store.state[schedKeyLastTaskCreate])
	}
	if store.state[schedKeyFiredGoals] != "[7]" {
		t.Fatalf("fired_goals=%q want [7]", store.state[schedKeyFiredGoals])
	}

	for _, forbidden := range []string{"NewFindingsSince", "NewToolCallsSince", "TimedOutTasksSince", "NewTasksSince"} {
		if store.calls[forbidden] != 0 {
			t.Fatalf("init() must not call %s, got %d calls", forbidden, store.calls[forbidden])
		}
	}

	// Second init (restart) must keep existing watermarks without re-querying.
	beforeMax := store.calls["MaxFindingID"] + store.calls["MaxToolResultActivityID"] + store.calls["MetGoals"]
	sc.init()
	afterMax := store.calls["MaxFindingID"] + store.calls["MaxToolResultActivityID"] + store.calls["MetGoals"]
	if afterMax != beforeMax {
		t.Fatalf("restart init re-seeded existing watermarks: before=%d after=%d", beforeMax, afterMax)
	}
}

func TestSchedulerStepSkipsScansWhenNoTriggersEnabled(t *testing.T) {
	store := newFakeSchedulerStore()
	store.state[schedKeyLastFinding] = "10"
	store.state[schedKeyLastToolCall] = "200"
	store.state[schedKeyLastTimeout] = "3"
	store.state[schedKeyLastTaskCreate] = "8"
	store.maxFindingID = 15
	store.maxToolResultID = 250
	store.maxTimeoutID = 5
	store.maxTaskID = 12

	sc := &Scheduler{store: store}
	sc.step()

	if store.calls["ListEnabledTriggers"] != 1 {
		t.Fatalf("ListEnabledTriggers calls=%d want 1", store.calls["ListEnabledTriggers"])
	}
	for _, skipped := range []string{"NewFindingsSince", "NewToolCallsSince", "MetGoals", "TimedOutTasksSince", "NewTasksSince"} {
		if store.calls[skipped] != 0 {
			t.Fatalf("idle step() must skip %s, got %d calls", skipped, store.calls[skipped])
		}
	}
	if store.state[schedKeyLastFinding] != "15" || store.state[schedKeyLastToolCall] != "250" ||
		store.state[schedKeyLastTimeout] != "5" || store.state[schedKeyLastTaskCreate] != "12" {
		t.Fatalf("idle step() did not advance watermarks cheaply: %+v", store.state)
	}

	// Repeating an idle tick with unchanged max IDs must not write scheduler_state.
	writesBefore := store.setStateCalls
	sc.step()
	if store.setStateCalls != writesBefore {
		t.Fatalf("unchanged idle tick performed %d unnecessary SetSchedState writes", store.setStateCalls-writesBefore)
	}
}

func TestSchedulerStepOnlyScansEnabledTriggerTypes(t *testing.T) {
	store := newFakeSchedulerStore()
	store.triggers = []*db.AgentTrigger{
		{ID: 1, AgentKey: "a", Enabled: true, OnFinding: true},
		// OnToolCall with empty ToolNames has no actionable matchers, so it must still skip NewToolCallsSince.
		{ID: 2, AgentKey: "b", Enabled: true, OnToolCall: true, ToolNames: nil},
	}

	sc := &Scheduler{store: store}
	sc.step()

	if store.calls["NewFindingsSince"] != 1 {
		t.Fatalf("NewFindingsSince calls=%d want 1", store.calls["NewFindingsSince"])
	}
	for _, skipped := range []string{"NewToolCallsSince", "MetGoals", "TimedOutTasksSince", "NewTasksSince"} {
		if store.calls[skipped] != 0 {
			t.Fatalf("step() should skip %s when no matching trigger is enabled, got %d", skipped, store.calls[skipped])
		}
	}
	if store.calls["MaxToolResultActivityID"] != 1 {
		t.Fatalf("expected cheap MaxToolResultActivityID fallback, got %d", store.calls["MaxToolResultActivityID"])
	}
}

func TestSchedulerStepAbortsOnListEnabledTriggersError(t *testing.T) {
	store := newFakeSchedulerStore()
	store.triggersErr = errors.New("db unavailable")

	sc := &Scheduler{store: store}
	sc.step()

	if len(store.calls) != 1 || store.calls["ListEnabledTriggers"] != 1 {
		t.Fatalf("step() should abort immediately on ListEnabledTriggers error, calls=%+v", store.calls)
	}
}
