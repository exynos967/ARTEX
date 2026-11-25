package server

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"strconv"
	"strings"
	"time"

	"github.com/RC-CHN/ARTEX/db"
)

// Scheduler drives P3 triggers: on each tick it fires due interval triggers and
// scans for new findings / newly-met goals (any task) to fire event triggers.
// Each fire enqueues a NEW conversation on the agent's per-agent trigger queue
// (StartTriggeredRun): fires for the same agent run one at a time in FIFO order,
// distinct agents still run concurrently. State is persisted (per-trigger last_fire
// + finding watermark + fired-goal set) so a restart resumes without double-firing.
// Triggers only attach to CUSTOM agents.
// schedulerStore is the narrow DB contract used by Scheduler so unit tests can
// verify startup fast-paths and zero-trigger skips without a live PostgreSQL.
type schedulerStore interface {
	ListEnabledTriggers() ([]*db.AgentTrigger, error)
	GetSchedState(key string) (string, error)
	SetSchedState(key, value string) error
	TouchTriggerFire(id int64) error
	MaxFindingID() (int64, error)
	MaxToolResultActivityID() (int64, error)
	MaxTimedOutTaskID() (int64, error)
	MaxTaskID() (int64, error)
	NewFindingsSince(lastID int64) ([]db.TaskEvent, error)
	TimedOutTasksSince(lastID int64) ([]db.TaskEvent, error)
	NewTasksSince(lastID int64) ([]db.TaskEvent, error)
	NewToolCallsSince(lastID int64) ([]db.TaskEvent, error)
	MetGoals() ([]db.TaskEvent, error)
}

type Scheduler struct {
	s     *Server
	pg    *db.DB
	store schedulerStore
	tick  time.Duration
	fire  func(agentKey, title, message string, taskID int64, mergeable bool, taskDesc, taskGoal string)
}

func (sc *Scheduler) dispatch(agentKey, title, message string, taskID int64, mergeable bool, taskDesc, taskGoal string) {
	if sc.fire != nil {
		sc.fire(agentKey, title, message, taskID, mergeable, taskDesc, taskGoal)
		return
	}
	if sc.s != nil {
		sc.s.StartTriggeredRun(agentKey, title, message, taskID, mergeable, taskDesc, taskGoal)
	}
}

func (sc *Scheduler) storeDB() schedulerStore {
	if sc.store != nil {
		return sc.store
	}
	if sc.pg != nil {
		return sc.pg
	}
	return nil
}

const (
	schedKeyLastFinding           = "last_finding_id"         // watermark: max finding node id fired for
	schedKeyFiredGoals            = "fired_goals"             // JSON array of goal node ids already fired
	schedKeyGoalTriggersActive    = "goal_triggers_active"    // "1" while >=1 on_goal_met trigger enabled, "0" when 0
	schedKeyLastTimeout           = "last_timeout_id"         // watermark: max task id fired for task timeout
	schedKeyFiredTimeouts         = "fired_timeouts"          // JSON array of timed-out task ids already fired
	schedKeyTimeoutTriggersActive = "timeout_triggers_active" // "1" while >=1 on_task_timeout trigger enabled, "0" when 0
	schedKeyLastToolCall          = "last_toolcall_id"        // watermark: max activity id fired for tool call
	schedKeyLastTaskCreate        = "last_taskcreate_id"      // watermark: max task id fired for task create
	maxSchedulerFiredSetSize      = 10000
)

func newScheduler(s *Server) *Scheduler {
	return &Scheduler{s: s, pg: s.m.pg, tick: 5 * time.Second}
}

// Run loops until ctx is done, ticking the scheduler. Started once from server New.
func (sc *Scheduler) Run(ctx context.Context) {
	if sc.storeDB() == nil {
		return
	}
	sc.init()
	t := time.NewTicker(sc.tick)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			sc.s.reconcileConcurrency() // 并发上限:有空位就把排队任务补位启动
			sc.step()
		}
	}
}

// init seeds the watermarks on first run using lightweight MAX(id) lookups so
// pre-existing findings/tool calls/tasks don't load entire tables or fire all at
// once — only events created AFTER the scheduler first starts count.
func (sc *Scheduler) init() {
	st := sc.storeDB()
	if sc.mustState(schedKeyLastFinding) == "" {
		if maxID, err := st.MaxFindingID(); err == nil {
			_ = st.SetSchedState(schedKeyLastFinding, strconv.FormatInt(maxID, 10))
		}
	}
	if sc.mustState(schedKeyFiredGoals) == "" {
		set := map[int64]bool{}
		if evs, err := st.MetGoals(); err == nil {
			for _, e := range evs {
				set[e.NodeID] = true
			}
		}
		sc.saveFiredGoalSet(set)
	}
	if sc.mustState(schedKeyLastTimeout) == "" {
		if maxID, err := st.MaxTimedOutTaskID(); err == nil {
			_ = st.SetSchedState(schedKeyLastTimeout, strconv.FormatInt(maxID, 10))
		}
	}
	if sc.mustState(schedKeyLastToolCall) == "" {
		if maxID, err := st.MaxToolResultActivityID(); err == nil {
			_ = st.SetSchedState(schedKeyLastToolCall, strconv.FormatInt(maxID, 10))
		}
	}
	if sc.mustState(schedKeyLastTaskCreate) == "" {
		if maxID, err := st.MaxTaskID(); err == nil {
			_ = st.SetSchedState(schedKeyLastTaskCreate, strconv.FormatInt(maxID, 10))
		}
	}
}

func (sc *Scheduler) step() {
	triggers, err := sc.storeDB().ListEnabledTriggers()
	if err != nil {
		return
	}
	// Monotonic id watermarks advance cheaply via MAX(id) even when no trigger is
	// enabled, so enabling a trigger later does not replay backlog events without
	// scanning full event tables on every idle tick.
	sc.fireIntervals(triggers)
	sc.fireFindings(triggers)
	sc.fireGoals(triggers)
	sc.fireTaskTimeouts(triggers)
	sc.fireToolCalls(triggers)
	sc.fireTaskCreates(triggers)
}

func (sc *Scheduler) advanceWatermark(key string, maxID int64) {
	if maxID <= 0 {
		return
	}
	last, _ := strconv.ParseInt(sc.mustState(key), 10, 64)
	if maxID > last {
		_ = sc.storeDB().SetSchedState(key, strconv.FormatInt(maxID, 10))
	}
}

// fireIntervals fires triggers whose interval has elapsed since last_fire.
func (sc *Scheduler) fireIntervals(triggers []*db.AgentTrigger) {
	st := sc.storeDB()
	now := time.Now()
	for _, tr := range triggers {
		if tr.IntervalSec <= 0 {
			continue
		}
		due := tr.LastFire == nil || now.Sub(*tr.LastFire) >= time.Duration(tr.IntervalSec)*time.Second
		if !due {
			continue
		}
		_ = st.TouchTriggerFire(tr.ID)
		ctx := "\n\n【本次为定时触发】" + now.Format(" 2006-01-02 15:04:05 MST")
		sc.dispatch(tr.AgentKey, fmt.Sprintf("定时触发 · %s", now.Format("15:04")), tr.IntervalMessage+ctx, 0, false, "", "")
	}
}

// fireFindings fires on_finding triggers for findings above the persisted
// watermark (monotonic node id → no double-fire across restarts).
func (sc *Scheduler) fireFindings(triggers []*db.AgentTrigger) {
	st := sc.storeDB()
	var want []*db.AgentTrigger
	for _, tr := range triggers {
		if tr.OnFinding {
			want = append(want, tr)
		}
	}
	if len(want) == 0 {
		if maxID, err := st.MaxFindingID(); err == nil {
			sc.advanceWatermark(schedKeyLastFinding, maxID)
		}
		return
	}
	last, _ := strconv.ParseInt(sc.mustState(schedKeyLastFinding), 10, 64)
	events, err := st.NewFindingsSince(last)
	if err != nil || len(events) == 0 {
		return
	}
	maxID := last
	for _, e := range events {
		if e.NodeID > maxID {
			maxID = e.NodeID
		}
		msgCtx := fmt.Sprintf("\n\n【本次由任务发现 finding 触发】\n发现: [%s/%s] %s",
			e.VulnClass, e.Severity, e.Summary)
		for _, tr := range want {
			sc.dispatch(tr.AgentKey, fmt.Sprintf("finding 触发 · task#%d", e.TaskID), tr.FindingMessage+msgCtx, e.TaskID, true, e.TaskDesc, e.TaskGoal)
		}
	}
	_ = st.SetSchedState(schedKeyLastFinding, strconv.FormatInt(maxID, 10))
}

// fireGoals fires on_goal_met triggers for met goals not yet in the fired set.
// While zero on_goal_met triggers are enabled, it avoids scanning MetGoals on
// every idle tick and records the inactive state so enabling a trigger later
// seeds currently met goals without replaying historical backlog.
func (sc *Scheduler) fireGoals(triggers []*db.AgentTrigger) {
	st := sc.storeDB()
	var want []*db.AgentTrigger
	for _, tr := range triggers {
		if tr.OnGoalMet {
			want = append(want, tr)
		}
	}
	if len(want) == 0 {
		if sc.mustState(schedKeyGoalTriggersActive) != "0" {
			_ = st.SetSchedState(schedKeyGoalTriggersActive, "0")
		}
		return
	}
	wasInactive := sc.mustState(schedKeyGoalTriggersActive) == "0"
	events, err := st.MetGoals()
	if err != nil {
		return
	}
	fired := sc.firedGoalSet()
	changed := false
	if wasInactive {
		// Transition 0 -> >0 enabled triggers: consume already-met goals without firing.
		for _, e := range events {
			if !fired[e.NodeID] {
				fired[e.NodeID] = true
				changed = true
			}
		}
		if changed {
			sc.saveFiredGoalSet(fired)
		}
		_ = st.SetSchedState(schedKeyGoalTriggersActive, "1")
		return
	}
	if sc.mustState(schedKeyGoalTriggersActive) != "1" {
		_ = st.SetSchedState(schedKeyGoalTriggersActive, "1")
	}
	if len(events) == 0 {
		return
	}
	for _, e := range events {
		if fired[e.NodeID] {
			continue
		}
		fired[e.NodeID] = true
		changed = true
		msgCtx := fmt.Sprintf("\n\n【本次由任务完成目标触发】\n达成目标: %s", e.Summary)
		for _, tr := range want {
			sc.dispatch(tr.AgentKey, fmt.Sprintf("目标触发 · task#%d", e.TaskID), tr.GoalMessage+msgCtx, e.TaskID, true, e.TaskDesc, e.TaskGoal)
		}
	}
	if changed {
		sc.saveFiredGoalSet(fired)
	}
}

// fireTaskTimeouts fires on_task_timeout triggers for tasks that newly reached
// status='timeout'. Tasks can time out out of task-id order (e.g. #101 before
// #100), so fired task ids are tracked in a bounded persisted dedup set rather
// than relying solely on a monotonic task_id watermark.
func (sc *Scheduler) fireTaskTimeouts(triggers []*db.AgentTrigger) {
	st := sc.storeDB()
	var want []*db.AgentTrigger
	for _, tr := range triggers {
		if tr.OnTaskTimeout {
			want = append(want, tr)
		}
	}
	if len(want) == 0 {
		if maxID, err := st.MaxTimedOutTaskID(); err == nil {
			sc.advanceWatermark(schedKeyLastTimeout, maxID)
		}
		if sc.mustState(schedKeyTimeoutTriggersActive) != "0" {
			_ = st.SetSchedState(schedKeyTimeoutTriggersActive, "0")
		}
		return
	}
	wasInactive := sc.mustState(schedKeyTimeoutTriggersActive) == "0"
	events, err := st.TimedOutTasksSince(0)
	if err != nil {
		return
	}
	rawFired := sc.mustState(schedKeyFiredTimeouts)
	hadFiredKey := rawFired != ""
	fired := sc.firedIDSet(schedKeyFiredTimeouts)
	last, _ := strconv.ParseInt(sc.mustState(schedKeyLastTimeout), 10, 64)

	currentIDs := make(map[int64]bool, len(events))
	maxID := last
	for _, e := range events {
		currentIDs[e.TaskID] = true
		if e.TaskID > maxID {
			maxID = e.TaskID
		}
	}
	changed := false
	// First run after upgrade/init: honor legacy last_timeout_id watermark so
	// historical timed-out tasks <= last are not replayed.
	if !hadFiredKey {
		for _, e := range events {
			if e.TaskID <= last && !fired[e.TaskID] {
				fired[e.TaskID] = true
				changed = true
			}
		}
	}
	// Prune ids that are no longer in status='timeout' (e.g. deleted, archived,
	// or revived), keeping the persisted set bounded and letting a revived task
	// fire again if it later times out anew.
	for id := range fired {
		if !currentIDs[id] {
			delete(fired, id)
			changed = true
		}
	}

	if wasInactive {
		for _, e := range events {
			if !fired[e.TaskID] {
				fired[e.TaskID] = true
				changed = true
			}
		}
		if changed || !hadFiredKey {
			sc.saveFiredIDSet(schedKeyFiredTimeouts, fired)
		}
		if maxID > last {
			_ = st.SetSchedState(schedKeyLastTimeout, strconv.FormatInt(maxID, 10))
		}
		_ = st.SetSchedState(schedKeyTimeoutTriggersActive, "1")
		return
	}
	if sc.mustState(schedKeyTimeoutTriggersActive) != "1" {
		_ = st.SetSchedState(schedKeyTimeoutTriggersActive, "1")
	}
	for _, e := range events {
		if fired[e.TaskID] {
			continue
		}
		fired[e.TaskID] = true
		changed = true
		msgCtx := "\n\n【本次由任务超时触发】"
		for _, tr := range want {
			sc.dispatch(tr.AgentKey, fmt.Sprintf("超时触发 · task#%d", e.TaskID), tr.TaskTimeoutMessage+msgCtx, e.TaskID, true, e.TaskDesc, e.TaskGoal)
		}
	}
	if changed || !hadFiredKey {
		sc.saveFiredIDSet(schedKeyFiredTimeouts, fired)
	}
	if maxID > last {
		_ = st.SetSchedState(schedKeyLastTimeout, strconv.FormatInt(maxID, 10))
	}
}

// fireTaskCreates fires on_task_create triggers for tasks newly created above the
// persisted watermark (task id → no double-fire across restarts).
func (sc *Scheduler) fireTaskCreates(triggers []*db.AgentTrigger) {
	st := sc.storeDB()
	var want []*db.AgentTrigger
	for _, tr := range triggers {
		if tr.OnTaskCreate {
			want = append(want, tr)
		}
	}
	if len(want) == 0 {
		if maxID, err := st.MaxTaskID(); err == nil {
			sc.advanceWatermark(schedKeyLastTaskCreate, maxID)
		}
		return
	}
	last, _ := strconv.ParseInt(sc.mustState(schedKeyLastTaskCreate), 10, 64)
	events, err := st.NewTasksSince(last)
	if err != nil || len(events) == 0 {
		return
	}
	maxID := last
	for _, e := range events {
		if e.NodeID > maxID {
			maxID = e.NodeID
		}
		msgCtx := "\n\n【本次由任务创建触发】"
		for _, tr := range want {
			sc.dispatch(tr.AgentKey, fmt.Sprintf("任务创建触发 · task#%d", e.TaskID), tr.TaskCreateMessage+msgCtx, e.TaskID, true, e.TaskDesc, e.TaskGoal)
		}
	}
	_ = st.SetSchedState(schedKeyLastTaskCreate, strconv.FormatInt(maxID, 10))
}

// fireToolCalls fires on_tool_call triggers for tool calls (tool_result rows) above
// the persisted watermark whose tool name is in the trigger's selected set. The fire
// message carries the task id/desc/goal + tool name + (truncated) input & output.
func (sc *Scheduler) fireToolCalls(triggers []*db.AgentTrigger) {
	st := sc.storeDB()
	var want []*db.AgentTrigger
	for _, tr := range triggers {
		if tr.OnToolCall && len(tr.ToolNames) > 0 {
			want = append(want, tr)
		}
	}
	if len(want) == 0 {
		if maxID, err := st.MaxToolResultActivityID(); err == nil {
			sc.advanceWatermark(schedKeyLastToolCall, maxID)
		}
		return
	}
	last, _ := strconv.ParseInt(sc.mustState(schedKeyLastToolCall), 10, 64)
	events, err := st.NewToolCallsSince(last)
	if err != nil || len(events) == 0 {
		return
	}
	maxID := last
	for _, e := range events {
		if e.NodeID > maxID {
			maxID = e.NodeID
		}
		// A failed finding write has no committed finding to report. Keep other
		// tool-error triggers available for user-defined automation.
		if e.ToolIsErr && e.Tool == "report_finding" {
			continue
		}
		errTag := ""
		if e.ToolIsErr {
			errTag = "[error] "
		}
		msgCtx := fmt.Sprintf("\n\n【本次由工具调用触发】\n工具: %s\n入参: %s\n返回: %s%s",
			e.Tool, trunc(e.ToolInput, 1500), errTag, trunc(e.ToolOutput, 1500))
		for _, tr := range want {
			if !containsFold(tr.ToolNames, e.Tool) {
				continue
			}
			sc.dispatch(tr.AgentKey, fmt.Sprintf("工具触发 · %s · task#%d", e.Tool, e.TaskID), tr.ToolCallMessage+msgCtx, e.TaskID, true, e.TaskDesc, e.TaskGoal)
		}
	}
	_ = st.SetSchedState(schedKeyLastToolCall, strconv.FormatInt(maxID, 10))
}

// containsFold reports whether name is in set (case-insensitive).
func containsFold(set []string, name string) bool {
	for _, s := range set {
		if strings.EqualFold(s, name) {
			return true
		}
	}
	return false
}

// trunc caps s to max runes, appending an ellipsis + original length when cut.
func trunc(s string, max int) string {
	r := []rune(s)
	if len(r) <= max {
		return s
	}
	return string(r[:max]) + fmt.Sprintf("…(已截断,共 %d 字)", len(r))
}

func (sc *Scheduler) mustState(key string) string {
	v, _ := sc.storeDB().GetSchedState(key)
	return v
}

func (sc *Scheduler) firedGoalSet() map[int64]bool {
	return sc.firedIDSet(schedKeyFiredGoals)
}

func (sc *Scheduler) saveFiredGoalSet(set map[int64]bool) {
	sc.saveFiredIDSet(schedKeyFiredGoals, set)
}

func (sc *Scheduler) firedIDSet(key string) map[int64]bool {
	out := map[int64]bool{}
	raw := sc.mustState(key)
	if raw == "" {
		return out
	}
	var ids []int64
	if json.Unmarshal([]byte(raw), &ids) == nil {
		for _, id := range ids {
			out[id] = true
		}
	}
	return out
}

func (sc *Scheduler) saveFiredIDSet(key string, set map[int64]bool) {
	ids := make([]int64, 0, len(set))
	for id := range set {
		ids = append(ids, id)
	}
	if len(ids) > maxSchedulerFiredSetSize {
		// Retain the newest (highest) ids when bounding the persisted JSON array.
		for i := 0; i < len(ids); i++ {
			for j := i + 1; j < len(ids); j++ {
				if ids[j] < ids[i] {
					ids[i], ids[j] = ids[j], ids[i]
				}
			}
		}
		ids = ids[len(ids)-maxSchedulerFiredSetSize:]
	}
	b, _ := json.Marshal(ids)
	if err := sc.storeDB().SetSchedState(key, string(b)); err != nil {
		log.Printf("[scheduler] save %s failed: %v", key, err)
	}
}
