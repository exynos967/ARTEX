package server

import (
	"container/list"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/RC-CHN/ARTEX/agent"
	"github.com/RC-CHN/ARTEX/db"
	"github.com/RC-CHN/ARTEX/llmrec"
	"github.com/RC-CHN/ARTEX/norma/llm"
	"github.com/RC-CHN/ARTEX/norma/transcript"
	"github.com/RC-CHN/ARTEX/sidequestion"
)

const (
	sideSnapshotFlushInterval    = 30 * time.Second
	sideSnapshotMaxRetries       = 3
	sideProgressSaveInterval     = 2 * time.Second
	sideEventsFallbackPoll       = 5 * time.Second
	maxSideLatestSnapshots       = 128
	maxSideInactiveWorkerLatest  = 32
)

// sideStore captures the PostgreSQL persistence subset used by side-question
// runtime coordination so unit tests can exercise capture, flushing, SSE, and
// cache-key propagation without requiring an external PostgreSQL instance.
type sideStore interface {
	InterruptSideRequests(ctx context.Context) error
	SaveSideSnapshot(ctx context.Context, s sidequestion.Snapshot) error
	SideSnapshot(ctx context.Context, key string) (*sidequestion.Snapshot, error)
	ExistingSideRequest(ctx context.Context, key, client string) (*sidequestion.Exchange, error)
	SideRequest(ctx context.Context, id string) (*sidequestion.Exchange, error)
	CurrentSideRequest(ctx context.Context, key string) (*sidequestion.Exchange, error)
	SideHistory(ctx context.Context, key string, before int64, limit int) ([]sidequestion.Exchange, error)
	StartSideRequest(ctx context.Context, s sidequestion.Snapshot, clientID, question string) (*sidequestion.Exchange, bool, error)
	UpdateSideRequest(ctx context.Context, e sidequestion.Exchange) (bool, error)
	ClearSideHistory(ctx context.Context, key string) error
	SideMemory(ctx context.Context, e sidequestion.Exchange) (sidequestion.Memory, error)
	SideReplayPage(ctx context.Context, e sidequestion.Exchange, after int64) ([]sidequestion.Exchange, error)
	SaveSideMemory(ctx context.Context, e sidequestion.Exchange, memory sidequestion.Memory) error
}

var _ sideStore = (*db.DB)(nil)

type sidePendingSnapshot struct {
	snap     sidequestion.Snapshot
	attempts int
}

type sideHubEvent struct {
	exchange sidequestion.Exchange
	cleared  bool
}

// sideHub is a lightweight per-request broadcaster with non-blocking
// latest-wins delivery so slow SSE consumers never stall inference or miss
// terminal / cleared transitions.
type sideHub struct {
	mu          sync.Mutex
	subs        map[string]map[chan sideHubEvent]struct{}
	latest      map[string]sidequestion.Exchange
	sessionKeys map[string]string
}

func newSideHub() *sideHub {
	return &sideHub{
		subs:        map[string]map[chan sideHubEvent]struct{}{},
		latest:      map[string]sidequestion.Exchange{},
		sessionKeys: map[string]string{},
	}
}

func sendLatestSideEvent(ch chan sideHubEvent, ev sideHubEvent) {
	select {
	case ch <- ev:
		return
	default:
	}
	select {
	case prev := <-ch:
		if prev.cleared && !ev.cleared {
			ev = prev
		}
	default:
	}
	select {
	case ch <- ev:
	default:
	}
}

func (h *sideHub) subscribe(id string) (<-chan sideHubEvent, *sidequestion.Exchange, func()) {
	ch := make(chan sideHubEvent, 1)
	h.mu.Lock()
	if h.subs[id] == nil {
		h.subs[id] = map[chan sideHubEvent]struct{}{}
	}
	h.subs[id][ch] = struct{}{}
	var live *sidequestion.Exchange
	if cur, ok := h.latest[id]; ok {
		cp := cur
		live = &cp
	}
	h.mu.Unlock()
	unsubscribe := func() {
		h.mu.Lock()
		if group := h.subs[id]; group != nil {
			delete(group, ch)
			if len(group) == 0 {
				delete(h.subs, id)
				if _, active := h.latest[id]; !active {
					delete(h.sessionKeys, id)
				}
			}
		}
		h.mu.Unlock()
	}
	return ch, live, unsubscribe
}

func (h *sideHub) bindSession(id, sessionKey string) {
	if id == "" || sessionKey == "" {
		return
	}
	h.mu.Lock()
	h.sessionKeys[id] = sessionKey
	h.mu.Unlock()
}

func (h *sideHub) publish(e sidequestion.Exchange) {
	h.mu.Lock()
	if cur, ok := h.latest[e.ID]; ok && cur.Sequence >= e.Sequence {
		h.mu.Unlock()
		return
	}
	if e.SessionKey != "" {
		h.sessionKeys[e.ID] = e.SessionKey
	}
	if e.Running() {
		h.latest[e.ID] = e
	} else {
		delete(h.latest, e.ID)
	}
	ev := sideHubEvent{exchange: e}
	for ch := range h.subs[e.ID] {
		sendLatestSideEvent(ch, ev)
	}
	if !e.Running() && len(h.subs[e.ID]) == 0 {
		delete(h.sessionKeys, e.ID)
	}
	h.mu.Unlock()
}

func (h *sideHub) finish(e sidequestion.Exchange) {
	h.mu.Lock()
	delete(h.latest, e.ID)
	ev := sideHubEvent{exchange: e}
	for ch := range h.subs[e.ID] {
		sendLatestSideEvent(ch, ev)
	}
	if len(h.subs[e.ID]) == 0 {
		delete(h.sessionKeys, e.ID)
	}
	h.mu.Unlock()
}

func (h *sideHub) clear(id string) {
	h.mu.Lock()
	h.clearLocked(id)
	h.mu.Unlock()
}

func (h *sideHub) clearSession(sessionKey string) {
	if sessionKey == "" {
		return
	}
	h.mu.Lock()
	var ids []string
	for id, key := range h.sessionKeys {
		if key == sessionKey {
			ids = append(ids, id)
		}
	}
	for _, id := range ids {
		h.clearLocked(id)
	}
	h.mu.Unlock()
}

func (h *sideHub) clearLocked(id string) {
	delete(h.latest, id)
	ev := sideHubEvent{cleared: true}
	for ch := range h.subs[id] {
		sendLatestSideEvent(ch, ev)
	}
	if len(h.subs[id]) == 0 {
		delete(h.sessionKeys, id)
	}
}

type sideRun struct {
	key    string
	parent sidequestion.Parent
	cancel context.CancelFunc
	done   chan struct{}
}
type sideQuestionState struct {
	mu                 sync.Mutex
	commands           sync.Mutex // short admission / clear operations only, never inference
	pending            map[string]sidePendingSnapshot
	latest             map[string]sidequestion.Snapshot
	lru                *list.List
	lruElem            map[string]*list.Element
	maxLatest          int
	maxInactiveWorkers int
	seen               map[string][2]int64
	persisted          map[string][2]int64
	active             map[string]bool
	parents            map[string]sidequestion.Parent
	runs               map[string]sideRun
	hub                *sideHub
	flushNotify        chan struct{}
	done               chan struct{}
	outputTokens       int
	store              sideStore
	flushEvery         time.Duration
	saveEvery          time.Duration
	fallbackPoll       time.Duration
}

func (s *Server) sideDB() sideStore {
	if s.side != nil && s.side.store != nil {
		return s.side.store
	}
	if s.m != nil && s.m.pg != nil {
		return s.m.pg
	}
	return nil
}

func sideModel(cfg agent.Config, id int64, name string) sidequestion.Model {
	b, _ := json.Marshal([]any{cfg.Format, cfg.BaseURL, cfg.Model, cfg.ThinkingType, cfg.ReasoningEffort, cfg.Stream, cfg.MaxTokensField, cfg.SessionHeaderKey})
	h := sha256.Sum256(b)
	return sidequestion.Model{ProfileID: id, Name: name, Format: string(cfg.Format), Model: cfg.Model, Identity: hex.EncodeToString(h[:]), Streaming: cfg.Stream, WindowTokens: cfg.CompactionWindow()}
}

func sideParentSessionID(parent sidequestion.Parent) string {
	if parent.ConversationID > 0 {
		return fmt.Sprintf("conv-%d", parent.ConversationID)
	}
	if parent.IntentID > 0 {
		return fmt.Sprintf("exp%d-worker-i%d", parent.ExplorationID, parent.IntentID)
	}
	return fmt.Sprintf("exp%d-main", parent.ExplorationID)
}

func bindSideProvider(p llm.Provider, cfg agent.Config, id int64, name string) llm.Provider {
	return sidequestion.Bind(p, sideModel(cfg, id, name))
}

func (s *Server) initSideQuestions() {
	var store sideStore
	if s.m != nil && s.m.pg != nil {
		store = s.m.pg
	}
	s.initSideQuestionsWithStore(store, sideSnapshotFlushInterval, sideProgressSaveInterval, sideEventsFallbackPoll)
}

func (s *Server) initSideQuestionsWithStore(store sideStore, flushEvery, saveEvery, fallbackPoll time.Duration) {
	if flushEvery <= 0 {
		flushEvery = sideSnapshotFlushInterval
	}
	if saveEvery <= 0 {
		saveEvery = sideProgressSaveInterval
	}
	if fallbackPoll <= 0 {
		fallbackPoll = sideEventsFallbackPoll
	}
	s.side = &sideQuestionState{
		pending:            map[string]sidePendingSnapshot{},
		latest:             map[string]sidequestion.Snapshot{},
		lru:                list.New(),
		lruElem:            map[string]*list.Element{},
		maxLatest:          maxSideLatestSnapshots,
		maxInactiveWorkers: maxSideInactiveWorkerLatest,
		seen:               map[string][2]int64{},
		persisted:          map[string][2]int64{},
		active:             map[string]bool{},
		parents:            map[string]sidequestion.Parent{},
		runs:               map[string]sideRun{},
		hub:                newSideHub(),
		flushNotify:        make(chan struct{}, 1),
		done:               make(chan struct{}),
		store:              store,
		flushEvery:         flushEvery,
		saveEvery:          saveEvery,
		fallbackPoll:       fallbackPoll,
	}
	if n, err := strconv.Atoi(os.Getenv("ARTEX_BTW_MAX_OUTPUT_TOKENS")); err == nil && n >= 256 && n <= 32768 {
		s.side.outputTokens = n
	}
	if store == nil {
		close(s.side.done)
		return
	}
	if err := store.InterruptSideRequests(s.ctx); err != nil {
		log.Printf("[btw] recover: %v", err)
	}
	s.ctx = sidequestion.WithPublisher(s.ctx, s.publishSideSnapshot)
	s.background(func() {
		defer close(s.side.done)
		tick := time.NewTicker(s.side.flushEvery)
		defer tick.Stop()
		for {
			select {
			case <-tick.C:
				s.flushSideSnapshots()
			case <-s.side.flushNotify:
				s.flushSideSnapshots()
			case <-s.ctx.Done():
				s.flushSideSnapshots()
				return
			}
		}
	})
}

func (s *Server) touchSideLatestLocked(key string) {
	if s.side.lru == nil {
		s.side.lru = list.New()
	}
	if s.side.lruElem == nil {
		s.side.lruElem = map[string]*list.Element{}
	}
	if elem, ok := s.side.lruElem[key]; ok {
		s.side.lru.MoveToFront(elem)
		return
	}
	s.side.lruElem[key] = s.side.lru.PushFront(key)
}

func (s *Server) deleteSideLatestLocked(key string) {
	delete(s.side.latest, key)
	if elem, ok := s.side.lruElem[key]; ok {
		if s.side.lru != nil {
			s.side.lru.Remove(elem)
		}
		delete(s.side.lruElem, key)
	}
}

func (s *Server) evictSideLatestLocked() {
	if s.side.lru == nil {
		return
	}
	maxLatest := s.side.maxLatest
	if maxLatest <= 0 {
		maxLatest = maxSideLatestSnapshots
	}
	maxInactiveWorkers := s.side.maxInactiveWorkers
	if maxInactiveWorkers <= 0 {
		maxInactiveWorkers = maxSideInactiveWorkerLatest
	}

	// 1. Cap inactive worker snapshot retention to a small LRU window so long-running
	//    tasks with hundreds of finished workers never pin megabytes of snapshots in RAM.
	inactiveWorkers := 0
	for k, snap := range s.side.latest {
		if snap.Parent.IntentID > 0 && !s.side.active[k] {
			if _, pend := s.side.pending[k]; !pend {
				inactiveWorkers++
			}
		}
	}
	for elem := s.side.lru.Back(); elem != nil && inactiveWorkers > maxInactiveWorkers; {
		prev := elem.Prev()
		k := elem.Value.(string)
		snap, ok := s.side.latest[k]
		_, pend := s.side.pending[k]
		if ok && snap.Parent.IntentID > 0 && !s.side.active[k] && !pend {
			s.forgetSideKeyLocked(k)
			inactiveWorkers--
		}
		elem = prev
	}

	// 2. Enforce the global hard LRU cap across all latest snapshots, preferring
	//    non-active & non-pending entries first so active /btw sessions are preserved.
	for len(s.side.latest) > maxLatest {
		evicted := false
		for elem := s.side.lru.Back(); elem != nil; elem = elem.Prev() {
			k := elem.Value.(string)
			if !s.side.active[k] {
				if _, pend := s.side.pending[k]; !pend {
					s.forgetSideKeyLocked(k)
					evicted = true
					break
				}
			}
		}
		if evicted {
			continue
		}
		for elem := s.side.lru.Back(); elem != nil; elem = elem.Prev() {
			k := elem.Value.(string)
			if _, pend := s.side.pending[k]; !pend {
				s.deleteSideLatestLocked(k)
				evicted = true
				break
			}
		}
		if evicted {
			continue
		}
		if back := s.side.lru.Back(); back != nil {
			s.deleteSideLatestLocked(back.Value.(string))
		} else {
			break
		}
	}
}

func (s *Server) publishSideSnapshot(snap sidequestion.Snapshot) {
	if s.side == nil {
		return
	}
	s.side.mu.Lock()
	key := snap.Parent.Key()
	old, ok := s.side.seen[key]
	if ok && (old[0] > snap.RunID || old[0] == snap.RunID && old[1] >= snap.Version) {
		s.side.mu.Unlock()
		return
	}
	s.side.latest[key] = snap
	s.touchSideLatestLocked(key)
	s.side.seen[key] = [2]int64{snap.RunID, snap.Version}
	s.side.parents[key] = snap.Parent
	notify := false
	if s.side.active[key] {
		s.side.pending[key] = sidePendingSnapshot{snap: snap}
		notify = snap.Terminal
	}
	s.evictSideLatestLocked()
	s.side.mu.Unlock()
	if notify {
		select {
		case s.side.flushNotify <- struct{}{}:
		default:
		}
	}
}

func (s *Server) markSideActive(p sidequestion.Parent) {
	if s.side == nil {
		return
	}
	key := p.Key()
	s.side.mu.Lock()
	s.side.active[key] = true
	s.side.parents[key] = p
	s.side.mu.Unlock()
}

func (s *Server) recordPersistedSnapshotLocked(key string, snap sidequestion.Snapshot) {
	cur, ok := s.side.persisted[key]
	if !ok || cur[0] < snap.RunID || (cur[0] == snap.RunID && cur[1] < snap.Version) {
		s.side.persisted[key] = [2]int64{snap.RunID, snap.Version}
	}
	if pend, ok := s.side.pending[key]; ok && (pend.snap.RunID < snap.RunID || (pend.snap.RunID == snap.RunID && pend.snap.Version <= snap.Version)) {
		delete(s.side.pending, key)
	}
}

func (s *Server) forgetSideKeyLocked(key string) {
	s.deleteSideLatestLocked(key)
	delete(s.side.pending, key)
	delete(s.side.seen, key)
	delete(s.side.persisted, key)
	delete(s.side.active, key)
	delete(s.side.parents, key)
}

func (s *Server) forgetSideWhereLocked(match func(sidequestion.Parent) bool) {
	var keys []string
	seen := map[string]struct{}{}
	collect := func(key string, p sidequestion.Parent) {
		if _, dup := seen[key]; dup {
			return
		}
		if match(p) {
			seen[key] = struct{}{}
			keys = append(keys, key)
		}
	}
	for key, p := range s.side.parents {
		collect(key, p)
	}
	for key, snap := range s.side.latest {
		collect(key, snap.Parent)
	}
	for key, item := range s.side.pending {
		collect(key, item.snap.Parent)
	}
	for _, key := range keys {
		s.forgetSideKeyLocked(key)
	}
}

func (s *Server) persistSideSnapshotOnDemand(ctx context.Context, snap sidequestion.Snapshot) {
	store := s.sideDB()
	if s.side == nil || store == nil {
		return
	}
	key := snap.Parent.Key()
	s.side.mu.Lock()
	persisted, ok := s.side.persisted[key]
	s.side.mu.Unlock()
	if ok && (persisted[0] > snap.RunID || persisted[0] == snap.RunID && persisted[1] >= snap.Version) {
		return
	}
	if err := store.SaveSideSnapshot(ctx, snap); err != nil {
		if errors.Is(err, db.ErrSideParentGone) {
			s.side.mu.Lock()
			s.forgetSideKeyLocked(key)
			s.side.mu.Unlock()
			return
		}
		log.Printf("[btw] on-demand checkpoint persistence: %v", err)
		return
	}
	s.side.mu.Lock()
	s.recordPersistedSnapshotLocked(key, snap)
	s.side.mu.Unlock()
}

func (s *Server) flushSideSnapshots() map[string]sidequestion.Parent {
	store := s.sideDB()
	if s.side == nil || store == nil {
		return nil
	}
	s.side.commands.Lock()
	defer s.side.commands.Unlock()
	s.side.mu.Lock()
	pending := s.side.pending
	s.side.pending = map[string]sidePendingSnapshot{}
	s.side.mu.Unlock()
	var failed map[string]sidequestion.Parent
	for key, item := range pending {
		snap := item.snap
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		err := store.SaveSideSnapshot(ctx, snap)
		cancel()
		s.side.mu.Lock()
		switch {
		case err == nil:
			s.recordPersistedSnapshotLocked(key, snap)
			if cur, ok := s.side.latest[key]; ok && cur.RunID == snap.RunID && cur.Version == snap.Version {
				s.deleteSideLatestLocked(key)
			}
		case errors.Is(err, db.ErrSideParentGone):
			s.forgetSideKeyLocked(key)
		default:
			if failed == nil {
				failed = map[string]sidequestion.Parent{}
			}
			failed[key] = snap.Parent
			item.attempts++
			if item.attempts < sideSnapshotMaxRetries {
				if newer, ok := s.side.pending[key]; !ok || newer.snap.RunID < snap.RunID || (newer.snap.RunID == snap.RunID && newer.snap.Version < snap.Version) {
					s.side.pending[key] = item
				}
			} else {
				if cur, ok := s.side.latest[key]; ok && cur.RunID == snap.RunID && cur.Version == snap.Version {
					s.deleteSideLatestLocked(key)
				}
				log.Printf("[btw] checkpoint persistence dropped after %d failed attempts (%s): %v", item.attempts, key, err)
			}
		}
		s.side.mu.Unlock()
		if err != nil && !errors.Is(err, db.ErrSideParentGone) && item.attempts < sideSnapshotMaxRetries {
			log.Printf("[btw] checkpoint persistence (attempt %d/%d): %v", item.attempts, sideSnapshotMaxRetries, err)
		}
	}
	return failed
}

func (s *Server) sideSnapshotState(ctx context.Context, p sidequestion.Parent) (*sidequestion.Snapshot, bool, error) {
	if s.side != nil {
		key := p.Key()
		s.side.mu.Lock()
		snap, ok := s.side.latest[key]
		if ok {
			s.touchSideLatestLocked(key)
		}
		s.side.mu.Unlock()
		if ok {
			return &snap, true, nil
		}
	}
	store := s.sideDB()
	if store == nil {
		return nil, false, nil
	}
	snap, err := store.SideSnapshot(ctx, p.Key())
	return snap, false, err
}

func (s *Server) sideSnapshot(ctx context.Context, p sidequestion.Parent) (*sidequestion.Snapshot, error) {
	snap, _, err := s.sideSnapshotState(ctx, p)
	return snap, err
}

func (s *Server) cancelSideRunsLocked(match func(sidequestion.Parent) bool) []<-chan struct{} {
	var done []<-chan struct{}
	for _, run := range s.side.runs {
		if match(run.parent) {
			run.cancel()
			done = append(done, run.done)
		}
	}
	return done
}

func (s *Server) cancelSideWhere(match func(sidequestion.Parent) bool) []<-chan struct{} {
	if s.side == nil {
		return nil
	}
	s.side.mu.Lock()
	defer s.side.mu.Unlock()
	done := s.cancelSideRunsLocked(match)
	s.forgetSideWhereLocked(match)
	return done
}

// prepareDrainTaskSideQuestions cancels and joins in-flight side-question runs
// and flushes pending checkpoints to PostgreSQL WITHOUT dropping s.side.latest.
// Call forgetTaskSideQuestions only after the enclosing delete/archive commits
// so a rolled-back archive never loses live in-memory checkpoints.
func (s *Server) prepareDrainTaskSideQuestions(ctx context.Context, taskID string) error {
	if s.side == nil {
		return nil
	}
	id, _ := strconv.ParseInt(taskID, 10, 64)
	matchTask := func(p sidequestion.Parent) bool { return p.TaskID == id }
	s.side.commands.Lock()
	s.side.mu.Lock()
	done := s.cancelSideRunsLocked(matchTask)
	s.side.mu.Unlock()
	s.side.commands.Unlock()
	for _, ch := range done {
		select {
		case <-ch:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	failed := s.flushSideSnapshots()
	// A failed flush must not silently leave the latest checkpoint out of archive.
	s.side.mu.Lock()
	defer s.side.mu.Unlock()
	for _, p := range failed {
		if p.TaskID == id {
			return errors.New("旁路上下文尚未保存，请重试")
		}
	}
	for _, item := range s.side.pending {
		if item.snap.Parent.TaskID == id {
			return errors.New("旁路上下文尚未保存，请重试")
		}
	}
	return nil
}

// forgetTaskSideQuestions purges all in-memory side-question state for taskID
// once the task has permanently been deleted or archived.
func (s *Server) forgetTaskSideQuestions(taskID string) {
	if s.side == nil {
		return
	}
	id, _ := strconv.ParseInt(taskID, 10, 64)
	s.side.mu.Lock()
	s.forgetSideWhereLocked(func(p sidequestion.Parent) bool { return p.TaskID == id })
	s.side.mu.Unlock()
}

// Called after the task admission barrier closes and the main loops drain.
// Wait for final answer/usage writes before taking the archive snapshot.
func (s *Server) drainTaskSideQuestions(ctx context.Context, taskID string) error {
	if err := s.prepareDrainTaskSideQuestions(ctx, taskID); err != nil {
		return err
	}
	s.forgetTaskSideQuestions(taskID)
	return nil
}

func (s *Server) cancelWorkerSide(taskID string, expID, iid int64) {
	if s.side == nil {
		return
	}
	id, _ := strconv.ParseInt(taskID, 10, 64)
	p := sidequestion.Parent{TaskID: id, ExplorationID: expID, IntentID: iid}
	s.side.commands.Lock()
	defer s.side.commands.Unlock()
	s.cancelSideWhere(func(parent sidequestion.Parent) bool { return parent == p })
}

func (s *Server) sideProvider(model sidequestion.Model) (llm.Provider, error) {
	var p llm.Provider
	var cfg agent.Config
	var ok bool
	if model.ProfileID > 0 {
		// Validate the persisted reference even if a previous provider is cached.
		current, exists := s.loadProfileConfig(model.ProfileID)
		if !exists || sideModel(current, model.ProfileID, model.Name).Identity != model.Identity {
			return nil, errors.New("模型配置已删除或变化，请先运行主 Agent 更新上下文")
		}
		p, cfg, ok = s.providerForProfile(model.ProfileID)
	} else {
		s.cfgMu.Lock()
		p, cfg, ok = s.llmDirect, s.llmCfg, s.llmOn
		s.cfgMu.Unlock()
	}
	if !ok || p == nil || sideModel(cfg, model.ProfileID, model.Name).Identity != model.Identity {
		return nil, errors.New("模型配置已删除或变化，请先运行主 Agent 更新上下文")
	}
	return p, nil
}

func (s *Server) sideParent(w http.ResponseWriter, r *http.Request, kind string) (sidequestion.Parent, bool) {
	p := sidequestion.Parent{}
	if s.side == nil || s.m.pg == nil {
		writeErr(w, 503, "旁路服务不可用")
		return p, false
	}
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil || id <= 0 {
		writeErr(w, 400, "bad id")
		return p, false
	}
	if kind == "conversation" {
		c, err := s.m.pg.GetConversation(id)
		if err != nil {
			writeErr(w, 500, err.Error())
			return p, false
		}
		if c == nil {
			writeErr(w, 404, "conversation not found")
			return p, false
		}
		p.ConversationID = id
		return p, true
	}
	t, ok := s.m.Task(r.PathValue("id"))
	if !ok {
		writeErr(w, 404, "task not found")
		return p, false
	}
	pt, err := s.m.pg.GetTask(id)
	if err != nil {
		writeErr(w, 500, err.Error())
		return p, false
	}
	if pt == nil || s.engine.IsDeleting(t.ID) {
		writeErr(w, 409, "任务已归档或正在删除")
		return p, false
	}
	p.TaskID, p.ExplorationID = id, t.ExpID
	if kind == "worker" {
		iid, err := strconv.ParseInt(r.PathValue("iid"), 10, 64)
		if err != nil || iid <= 0 {
			writeErr(w, 400, "bad intent id")
			return p, false
		}
		n, err := t.Store.GetNode(iid)
		if err != nil {
			writeErr(w, 500, err.Error())
			return p, false
		}
		if n == nil || n.Kind != db.KindIntent {
			writeErr(w, 404, "intent not found")
			return p, false
		}
		if n.State == "stopped" {
			writeErr(w, 409, "Worker 已删除")
			return p, false
		}
		p.IntentID = iid
	}
	return p, true
}

func (s *Server) registerSideRoutes(mux *http.ServeMux) {
	for _, route := range []struct{ path, kind string }{{"/api/conversations/{id}", "conversation"}, {"/api/tasks/{id}/chat", "main"}, {"/api/tasks/{id}/intents/{iid}", "worker"}} {
		for _, method := range []string{"GET", "POST", "DELETE"} {
			mux.HandleFunc(method+" "+route.path+"/side-questions", func(w http.ResponseWriter, r *http.Request) {
				p, ok := s.sideParent(w, r, route.kind)
				if ok {
					s.handleSideQuestions(w, r, p)
				}
			})
		}
	}
	mux.HandleFunc("GET /api/side-questions/{requestID}/events", s.sideEvents)
	mux.HandleFunc("POST /api/side-questions/{requestID}/cancel", s.cancelSideRequest)
}

func (s *Server) handleSideQuestions(w http.ResponseWriter, r *http.Request, p sidequestion.Parent) {
	store := s.sideDB()
	if s.side == nil || store == nil {
		writeErr(w, 503, "旁路服务不可用")
		return
	}
	key := p.Key()
	if r.Method == "DELETE" {
		s.side.commands.Lock()
		defer s.side.commands.Unlock()
		var cancelledIDs []string
		s.side.mu.Lock()
		for id, run := range s.side.runs {
			if run.key == key {
				run.cancel()
				cancelledIDs = append(cancelledIDs, id)
			}
		}
		s.forgetSideKeyLocked(key)
		s.side.mu.Unlock()
		if err := store.ClearSideHistory(r.Context(), key); err != nil {
			writeErr(w, 500, err.Error())
			return
		}
		for _, id := range cancelledIDs {
			s.side.hub.clear(id)
		}
		s.side.hub.clearSession(key)
		writeJSON(w, 200, map[string]bool{"cleared": true})
		return
	}
	if r.Method == "GET" {
		snap, live, err := s.sideSnapshotState(r.Context(), p)
		if err != nil {
			writeErr(w, 500, err.Error())
			return
		}
		before, _ := strconv.ParseInt(r.URL.Query().Get("before"), 10, 64)
		items, err := store.SideHistory(r.Context(), key, before, 21)
		if err != nil {
			writeErr(w, 500, err.Error())
			return
		}
		var next int64
		if len(items) > 20 {
			items = items[:20]
			next = items[len(items)-1].Ordinal
		}
		current, err := store.CurrentSideRequest(r.Context(), key)
		if err != nil {
			writeErr(w, 500, err.Error())
			return
		}
		if len(items) > 0 || current != nil {
			s.markSideActive(p)
		}
		if live && snap != nil {
			s.persistSideSnapshotOnDemand(r.Context(), *snap)
		}
		var meta any
		if snap != nil {
			_, modelErr := s.sideProvider(snap.Model)
			reason := ""
			if modelErr != nil {
				reason = modelErr.Error()
			}
			meta = map[string]any{"captured_at": snap.CapturedAt, "model": snap.Model, "available": modelErr == nil, "reason": reason}
		}
		writeJSON(w, 200, map[string]any{"items": items, "current": current, "next_cursor": next, "snapshot": meta})
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 32<<10)
	var in struct {
		Question string `json:"question"`
		ClientID string `json:"client_request_id"`
	}
	if json.NewDecoder(r.Body).Decode(&in) != nil {
		writeErr(w, 400, "bad json")
		return
	}
	in.Question = strings.TrimSpace(in.Question)
	if in.Question == "" || len([]rune(in.Question)) > 4000 || !validWorkerMessageRequestID(in.ClientID) {
		writeErr(w, 400, "问题须为 1–4000 字符，并提供有效请求 ID")
		return
	}
	s.side.commands.Lock()
	defer s.side.commands.Unlock()
	if p.TaskID > 0 && s.engine != nil && s.engine.IsDeleting(strconv.FormatInt(p.TaskID, 10)) {
		writeErr(w, 409, "任务正在归档或删除")
		return
	}
	if existing, err := store.ExistingSideRequest(r.Context(), key, in.ClientID); err != nil {
		writeErr(w, 500, err.Error())
		return
	} else if existing != nil {
		if existing.Question != in.Question {
			writeErr(w, 409, "同一请求 ID 不能用于不同问题")
			return
		}
		s.markSideActive(p)
		writeJSON(w, 200, existing)
		return
	}
	// Resolve snapshot inside commands.Lock so a concurrent DELETE cannot be
	// resurrected by a stale snapshot captured before DELETE ran.
	snap, _, err := s.sideSnapshotState(r.Context(), p)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	if snap == nil {
		writeErr(w, 409, "尚无上下文快照，请先运行主 Agent")
		return
	}
	provider, err := s.sideProvider(snap.Model)
	if err != nil {
		writeErr(w, 409, err.Error())
		return
	}
	s.side.mu.Lock()
	full := len(s.side.runs) >= 4
	busy := false
	for _, run := range s.side.runs {
		if run.key == key {
			busy = true
		}
	}
	s.side.mu.Unlock()
	if busy {
		writeErr(w, 409, db.ErrSideBusy.Error())
		return
	}
	if full {
		writeErr(w, 429, "旁路请求已达并发上限，请稍后重试")
		return
	}
	agentQuestion := in.Question
	if s.m != nil && s.m.pg != nil {
		var ok bool
		agentQuestion, ok = s.prepareChatMentionMessage(w, in.Question)
		if !ok {
			return
		}
	}
	s.markSideActive(p)
	if err = store.SaveSideSnapshot(r.Context(), *snap); err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	s.side.mu.Lock()
	s.recordPersistedSnapshotLocked(key, *snap)
	s.side.mu.Unlock()
	e, created, err := store.StartSideRequest(r.Context(), *snap, in.ClientID, in.Question)
	if err != nil {
		writeErr(w, 409, err.Error())
		return
	}
	if created {
		ctx, cancel := context.WithTimeout(s.ctx, 120*time.Second)
		s.side.mu.Lock()
		s.side.runs[e.ID] = sideRun{key: key, parent: p, cancel: cancel, done: make(chan struct{})}
		s.side.mu.Unlock()
		s.side.hub.bindSession(e.ID, e.SessionKey)
		if !s.background(func() { s.runSide(ctx, cancel, *e, p, provider, *snap, agentQuestion) }) {
			cancel()
			s.side.mu.Lock()
			if run, ok := s.side.runs[e.ID]; ok {
				close(run.done)
			}
			delete(s.side.runs, e.ID)
			s.side.mu.Unlock()
			e.Status = "cancelled"
			e.Error = "服务正在关闭，旁路回答未启动"
			e.Sequence++
			writeCtx, stop := context.WithTimeout(context.Background(), 3*time.Second)
			_, _ = store.UpdateSideRequest(writeCtx, *e)
			stop()
			s.side.hub.finish(*e)
			writeErr(w, http.StatusServiceUnavailable, "服务正在关闭")
			return
		}
	}
	writeJSON(w, 202, e)
}

func (s *Server) runSide(ctx context.Context, cancel context.CancelFunc, e sidequestion.Exchange, parent sidequestion.Parent, provider llm.Provider, snapshot sidequestion.Snapshot, agentQuestion string) {
	store := s.sideDB()
	defer cancel()
	defer func() {
		s.side.mu.Lock()
		if run, ok := s.side.runs[e.ID]; ok {
			close(run.done)
		}
		delete(s.side.runs, e.ID)
		s.side.mu.Unlock()
	}()
	parentSessionID := strings.TrimSpace(snapshot.SessionID)
	if parentSessionID == "" {
		parentSessionID = sideParentSessionID(parent)
	}
	ctx = transcript.WithSessionID(ctx, parentSessionID)
	ctx = llm.WithPromptCacheKey(ctx, parentSessionID)
	if parent.TaskID > 0 {
		ctx = llmrec.WithTaskID(ctx, strconv.FormatInt(parent.TaskID, 10))
	}
	s.side.hub.bindSession(e.ID, e.SessionKey)
	// Deletions can race between request insertion and registration. Observe the
	// persisted lifecycle even while a provider is blocked without emitting text.
	watchDone := make(chan struct{})
	defer func() { cancel(); <-watchDone }()
	go func() {
		defer close(watchDone)
		tick := time.NewTicker(500 * time.Millisecond)
		defer tick.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-tick.C:
				row, err := store.SideRequest(ctx, e.ID)
				if err == nil && (row == nil || !row.Running()) {
					cancel()
					return
				}
			}
		}
	}()
	saveEvery := s.side.saveEvery
	if saveEvery <= 0 {
		saveEvery = sideProgressSaveInterval
	}
	lastSave := time.Now()
	persist := func() (bool, error) {
		writeCtx, stop := context.WithTimeout(context.Background(), 3*time.Second)
		defer stop()
		ok, err := store.UpdateSideRequest(writeCtx, e)
		if err != nil {
			log.Printf("[btw] answer persistence: %v", err)
			return true, err
		}
		return ok, nil
	}
	memory, runErr := store.SideMemory(ctx, e)
	var answer sidequestion.Answer
	if runErr == nil {
		answer, e.Context, runErr = (sidequestion.SideQuestionService{Provider: provider}).Respond(ctx, snapshot, agentQuestion, sidequestion.Replay{
			Memory: memory,
			Load: func(ctx context.Context, after int64) ([]sidequestion.Exchange, error) {
				return store.SideReplayPage(ctx, e, after)
			},
			Save: func(ctx context.Context, memory sidequestion.Memory) error {
				return store.SaveSideMemory(ctx, e, memory)
			},
		}, sidequestion.ContextOptions{OutputTokens: s.side.outputTokens}, func(a sidequestion.Answer, info sidequestion.ContextInfo) {
			phaseChanged := e.Context.Phase != info.Phase
			e.Answer, e.Usage, e.Context = a.Text, a.Usage, info
			e.Sequence++
			s.side.hub.publish(e)
			if phaseChanged || time.Since(lastSave) >= saveEvery {
				lastSave = time.Now()
				if ok, _ := persist(); !ok {
					cancel()
				}
			}
		})
	}
	e.Answer, e.Usage = answer.Text, answer.Usage
	e.Status = "completed"
	if ctx.Err() != nil {
		e.Status = "cancelled"
		e.Error = "回答已停止"
		if errors.Is(ctx.Err(), context.DeadlineExceeded) {
			e.Status = "failed"
			e.Error = "旁路回答超过 120 秒，已停止"
		}
	} else if runErr != nil {
		e.Status = "failed"
		e.Error = runErr.Error()
	}
	e.Sequence++
	persistedOK := true
	var persistErr error
	for attempt := 0; attempt < 3; attempt++ {
		persistedOK, persistErr = persist()
		if persistErr == nil {
			break
		}
		if attempt < 2 {
			time.Sleep(100 * time.Millisecond)
		}
	}
	if persistErr == nil && !persistedOK {
		checkCtx, stop := context.WithTimeout(context.Background(), 3*time.Second)
		row, err := store.SideRequest(checkCtx, e.ID)
		stop()
		if err == nil && row == nil {
			s.side.hub.clear(e.ID)
		} else if err == nil && row != nil {
			s.side.hub.finish(*row)
		} else {
			s.side.hub.finish(e)
		}
	} else {
		s.side.hub.finish(e)
	}
}

func (s *Server) cancelSideRequest(w http.ResponseWriter, r *http.Request) {
	store := s.sideDB()
	if s.side == nil || store == nil {
		writeErr(w, 503, "旁路服务不可用")
		return
	}
	e, err := store.SideRequest(r.Context(), r.PathValue("requestID"))
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	if e == nil {
		writeErr(w, 404, "side question not found")
		return
	}
	s.side.mu.Lock()
	if run, ok := s.side.runs[e.ID]; ok {
		run.cancel()
	}
	s.side.mu.Unlock()
	writeJSON(w, 200, map[string]bool{"cancelled": true})
}

func (s *Server) sideEvents(w http.ResponseWriter, r *http.Request) {
	store := s.sideDB()
	if s.side == nil || store == nil {
		writeErr(w, 503, "旁路服务不可用")
		return
	}
	flusher, ok := w.(http.Flusher)
	if !ok {
		writeErr(w, 500, "streaming unavailable")
		return
	}
	id := r.PathValue("requestID")
	events, live, unsubscribe := s.side.hub.subscribe(id)
	defer unsubscribe()

	first, err := store.SideRequest(r.Context(), id)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	if first == nil {
		writeErr(w, 404, "side question not found")
		return
	}
	s.side.hub.bindSession(id, first.SessionKey)
	if live != nil && first.Running() && live.Sequence > first.Sequence {
		cp := *live
		first = &cp
	}

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("X-Accel-Buffering", "no")

	writeSnapshot := func(e sidequestion.Exchange) bool {
		b, err := json.Marshal(e)
		if err != nil {
			return false
		}
		if _, err := fmt.Fprintf(w, "id: %d\nevent: snapshot\ndata: %s\n\n", e.Sequence, b); err != nil {
			return false
		}
		flusher.Flush()
		return true
	}
	writeCleared := func() bool {
		if _, err := fmt.Fprint(w, "event: cleared\ndata: {}\n\n"); err != nil {
			return false
		}
		flusher.Flush()
		return true
	}

	if !writeSnapshot(*first) {
		return
	}
	seq := first.Sequence
	if !first.Running() {
		return
	}

	fallbackEvery := s.side.fallbackPoll
	if fallbackEvery <= 0 {
		fallbackEvery = sideEventsFallbackPoll
	}
	fallback := time.NewTicker(fallbackEvery)
	defer fallback.Stop()
	heartbeat := time.NewTicker(15 * time.Second)
	defer heartbeat.Stop()

	for {
		select {
		case <-r.Context().Done():
			return
		case <-s.ctx.Done():
			return
		case ev := <-events:
			if ev.cleared {
				writeCleared()
				return
			}
			if ev.exchange.Sequence > seq || !ev.exchange.Running() {
				if !writeSnapshot(ev.exchange) {
					return
				}
				seq = ev.exchange.Sequence
			}
			if !ev.exchange.Running() {
				return
			}
		case <-fallback.C:
			e, err := store.SideRequest(r.Context(), id)
			if err != nil {
				return
			}
			if e == nil {
				writeCleared()
				return
			}
			if e.Sequence > seq || !e.Running() {
				if !writeSnapshot(*e) {
					return
				}
				seq = e.Sequence
			}
			if !e.Running() {
				return
			}
		case <-heartbeat.C:
			if _, err := fmt.Fprint(w, ": keepalive\n\n"); err != nil {
				return
			}
			flusher.Flush()
		}
	}
}
