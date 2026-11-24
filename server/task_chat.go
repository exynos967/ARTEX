package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/RC-CHN/ARTEX/agent"
	"github.com/RC-CHN/ARTEX/db"
	"github.com/RC-CHN/ARTEX/intercept"
)

func taskConsultKey(taskID string) string {
	return taskID + ":consult"
}

// taskChatKey returns the per-lane busy/cancel key for a task's main-agent
// executions. Segment 0 keeps the bare taskID key for compatibility; extra
// human segments use "<taskID>:seg:<seg>", and automatic worker consultations
// use "<taskID>:consult".
func taskChatKey(taskID string, seg int) string {
	if seg == db.MainSegConsultation {
		return taskConsultKey(taskID)
	}
	if seg <= 0 {
		return taskID
	}
	return taskID + ":seg:" + strconv.Itoa(seg)
}

func parseTaskChatKey(taskID, key string) (int, bool) {
	if key == taskID {
		return 0, true
	}
	if key == taskConsultKey(taskID) {
		return db.MainSegConsultation, true
	}
	prefix := taskID + ":seg:"
	if strings.HasPrefix(key, prefix) {
		seg, err := strconv.Atoi(strings.TrimPrefix(key, prefix))
		if err == nil && seg > 0 {
			return seg, true
		}
	}
	return 0, false
}

// mainSessions lists the task's main-agent conversation segments (newest-first) and
// the current one. The frontend renders these as switchable sessions under 主 Agent.
func (s *Server) mainSessions(w http.ResponseWriter, r *http.Request) {
	t := s.m.ResolveTask(r.URL.Query().Get("task"))
	if t == nil {
		writeErr(w, 404, "task not found")
		return
	}
	list, err := t.Store.ListMainSessions()
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	hasConsultation, _ := t.Store.HasMainConsultationActivity()
	current := 0
	if len(list) > 0 {
		current = list[0].Seq // newest-first
	}
	writeJSON(w, 200, map[string]any{
		"sessions":         list,
		"current":          current,
		"has_consultation": hasConsultation,
	})
}

// newMainSession starts a fresh main-agent conversation segment. Only the segment
// counter advances — the task's exploration graph, assets and goal are untouched, so
// the main agent continues over the same task with a clean transcript/context.
func (s *Server) newMainSession(w http.ResponseWriter, r *http.Request) {
	t := s.m.ResolveTask(r.URL.Query().Get("task"))
	if t == nil {
		writeErr(w, 404, "task not found")
		return
	}
	if s.engine.IsDeleting(t.ID) {
		writeErr(w, 409, "任务正在删除，无法新建会话")
		return
	}
	m, err := t.Store.NewMainSession()
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"seq": m.Seq, "created_at": rfc3339(m.CreatedAt), "current": m.Seq})
}

func (s *Server) chat(w http.ResponseWriter, r *http.Request) {
	t := s.m.ResolveTask(r.URL.Query().Get("task"))
	if t == nil {
		writeErr(w, 404, "no active task")
		return
	}
	if s.engine.IsDeleting(t.ID) {
		writeErr(w, 409, "任务正在删除，无法发送新消息")
		return
	}
	// 注意:任务暂停(paused)不拦截主 Agent 对话。主 Agent 编排会话独立于 planner/
	// worker 的暂停,暂停中仍可继续对话(暂停只终止其正在进行的那一轮,见 control())。
	var req struct {
		Message     string           `json:"message"`
		Attachments []chatAttachment `json:"attachments,omitempty"` // 方式1 上传的文件(路径相对任务工作目录)
		Seg         *int             `json:"seg,omitempty"`         // 目标主会话分段;缺省=最新段
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	agentMessage, ok := s.prepareChatMentionMessage(w, req.Message)
	if !ok {
		return
	}
	if req.Seg != nil && *req.Seg < 0 {
		writeErr(w, 400, "协作请示会话为只读，请在人类主会话发消息或使用人工接答")
		return
	}
	// The turn belongs to whichever main-agent segment the user is chatting in (any
	// segment is interactive, like the top-level chat conversations). Stamp every
	// mainagent row with it so this turn's transcript + activity land in that segment.
	// Missing seg (older clients) falls back to the newest segment.
	mainSeg := 0
	if req.Seg != nil {
		mainSeg = *req.Seg
	} else {
		mainSeg, _ = t.Store.CurrentMainSeg()
	}
	segPtr := &mainSeg

	// Admission is serialized per (task, segment) lane and with deletion's chat
	// cancellation, so each main-agent segment (and the background worker
	// consultation lane) stays independent without corrupting shared transcripts.
	busyKey, ctx, cancel, errStatus, errMsg := s.admitTaskChatLane(t.ID, mainSeg, req.Message)
	if errStatus != 0 {
		writeErr(w, errStatus, errMsg)
		return
	}

	// Persist + broadcast the human turn so the 主 Agent 编排会话 survives page
	// reloads and updates live: the conversation lives in the activity stream as
	// worker="mainagent" (the per-task activity table, replayed via SSE). With
	// attachments, the activity's Detail carries {text, attachments} so the transcript
	// renders attachment cards.
	humanTurn := userActivityWithAttachments("mainagent", req.Message, req.Attachments)
	humanTurn.MainSeg = segPtr
	s.engine.emitActivity(t, humanTurn)
	var ma *agent.MainAgent
	if s.taskRuntimeAvailable(t, "mainagent") {
		ma = s.agentsForTask(t).main
	}
	if ma != nil {
		// Run the agent on a per-turn cancellable ctx (NOT r.Context()): the turn can
		// take minutes (multi-tool loop), and binding it to the request lifecycle meant
		// a page reload / proxy timeout cancelled it mid-run ("context canceled"). The
		// steps + final answer stream back live via SSE (worker="mainagent"), so the
		// handler returns immediately and the browser never needs to hold the request.
		if !s.background(func() {
			defer func() {
				s.finishTaskChatLane(busyKey, cancel)
			}()
			// emit every step (thinking/tool_use/tool_result/text/result) so the main
			// agent session shows its work live, like worker/planner. The final answer
			// is the captured "result" step — no separate reply emit (would duplicate).
			emit := func(rec db.Activity) {
				rec.MainSeg = segPtr
				s.engine.emitActivity(t, rec)
			}
			maTaskID, _ := strconv.ParseInt(t.ID, 10, 64)
			resume := func() { s.reviveTask(t) } // set_goals 新增目标 → 把任务拉回 running
			// 把上传附件的【绝对路径】清单拼进发给 agent 的消息,它据此用 Read/Bash 打开文件。
			// taskDir = agent 的工作目录(CWD),与 chatUpload 落盘、ensureRunDir 一致。
			taskDir := filepath.Join(s.m.dir, "tasks", t.ID)
			agentMsg := composeAgentMessage(agentMessage, req.Attachments, taskDir)
			s.engine.BeginLLMCall(t.ID)
			_, err := ma.Chat(ctx, maTaskID, mainSeg, s.m.Assets(), t.Store, t.Goal, agentMsg, emit, t.Notify, resume, t.NotifyGoal, t.NotifyHint)
			s.engine.EndLLMCall(t.ID)
			if err != nil && ctx.Err() == nil {
				s.engine.emitActivity(t, db.Activity{Worker: "mainagent", Kind: "text", IsError: true, Summary: "（主 Agent 出错：" + err.Error() + "）", MainSeg: segPtr})
			}
		}) {
			s.finishTaskChatLane(busyKey, cancel)
			writeErr(w, 503, "server is shutting down")
			return
		}
		writeJSON(w, 202, map[string]any{"status": "accepted", "mode": "llm", "seg": mainSeg})
		return
	}
	reply := s.fallbackChat(t, req.Message)
	s.engine.emitActivity(t, db.Activity{Worker: "mainagent", Kind: "text", Summary: reply, MainSeg: segPtr})
	s.finishTaskChatLane(busyKey, cancel)
	writeJSON(w, 200, map[string]any{"reply": reply, "mode": "rule", "seg": mainSeg})
}

func (s *Server) admitTaskChatLane(taskID string, seg int, reviewMessage string) (string, context.Context, context.CancelCauseFunc, int, string) {
	busyKey := taskChatKey(taskID, seg)
	s.chatMu.Lock()
	if s.engine.IsDeleting(taskID) {
		s.chatMu.Unlock()
		return "", nil, nil, http.StatusConflict, "任务正在删除，无法发送新消息"
	}
	if seg == db.MainSegConsultation && s.engine.IsPaused(taskID) {
		s.chatMu.Unlock()
		return "", nil, nil, http.StatusConflict, "任务已暂停，暂不处理自动请示"
	}
	if s.chatBusy[busyKey] {
		s.chatMu.Unlock()
		return "", nil, nil, http.StatusConflict, "主 Agent 正在处理当前会话的上一条消息，请稍候"
	}
	ctx, cancel := context.WithCancelCause(s.ctx)
	if seg != db.MainSegConsultation {
		ctx = intercept.WithReviewContext(ctx, "", intercept.ReviewBackground{Source: intercept.BackgroundUserMessage, Text: reviewMessage})
	}
	s.chatBusy[busyKey] = true
	s.chatCancel[busyKey] = cancel
	s.chatMu.Unlock()
	return busyKey, ctx, cancel, 0, ""
}

func (s *Server) cancelTaskChatSeg(taskID string, seg int, cause error) bool {
	busyKey := taskChatKey(taskID, seg)
	s.chatMu.Lock()
	cancel := s.chatCancel[busyKey]
	if cancel != nil {
		cancel(cause)
	}
	s.chatMu.Unlock()
	return cancel != nil
}

func (s *Server) cancelTaskChat(taskID string, cause error) bool {
	s.chatMu.Lock()
	var cancels []context.CancelCauseFunc
	for key, cancel := range s.chatCancel {
		if cancel == nil {
			continue
		}
		if _, ok := parseTaskChatKey(taskID, key); ok {
			cancels = append(cancels, cancel)
		}
	}
	s.chatMu.Unlock()
	for _, cancel := range cancels {
		cancel(cause)
	}
	return len(cancels) > 0
}

func (s *Server) finishTaskChat(taskID string, cancel context.CancelCauseFunc) {
	s.finishTaskChatLane(taskID, cancel)
}

func (s *Server) finishTaskChatLane(busyKey string, cancel context.CancelCauseFunc) {
	cancel(agent.AbortChatTurnFinished)
	s.chatMu.Lock()
	delete(s.chatBusy, busyKey)
	delete(s.chatCancel, busyKey)
	s.chatMu.Unlock()
}

func (s *Server) hasActiveTaskChat(taskID string) bool {
	s.chatMu.Lock()
	defer s.chatMu.Unlock()
	for key, busy := range s.chatBusy {
		if !busy {
			continue
		}
		if _, ok := parseTaskChatKey(taskID, key); ok {
			return true
		}
	}
	return false
}

func (s *Server) taskChatActivityState(taskID string) ([]int, bool) {
	s.chatMu.Lock()
	defer s.chatMu.Unlock()
	runningSegs := []int{}
	consultRunning := false
	for key, busy := range s.chatBusy {
		if !busy {
			continue
		}
		seg, ok := parseTaskChatKey(taskID, key)
		if !ok {
			continue
		}
		if seg == db.MainSegConsultation {
			consultRunning = true
		} else {
			runningSegs = append(runningSegs, seg)
		}
	}
	sort.Ints(runningSegs)
	return runningSegs, consultRunning
}

// taskChatStatus reports the authoritative state of the task's main-agent lanes
// (per human conversation segment plus the dedicated worker consultation lane).
// Activity timestamps are not a reliable proxy because a tool or LLM call may run
// for minutes without emitting an intermediate frame.
func (s *Server) taskChatStatus(w http.ResponseWriter, r *http.Request) {
	t := s.m.ResolveTask(r.PathValue("id"))
	if t == nil {
		writeErr(w, http.StatusNotFound, "task not found")
		return
	}
	runningSegs, consultRunning := s.taskChatActivityState(t.ID)
	writeJSON(w, http.StatusOK, map[string]any{
		"running":              len(runningSegs) > 0 || consultRunning,
		"running_segs":         runningSegs,
		"consultation_running": consultRunning,
	})
}

// stopChat aborts an in-flight main-agent turn for a task (manual stop button).
// When seg is provided (in JSON body or query), only that segment (or -1 for the
// automatic consultation lane) is cancelled; omitting seg cancels all active
// main-agent lanes for the task for backwards compatibility.
func (s *Server) stopChat(w http.ResponseWriter, r *http.Request) {
	t := s.m.ResolveTask(r.PathValue("id"))
	if t == nil {
		writeErr(w, 404, "task not found")
		return
	}
	var req struct {
		Seg *int `json:"seg,omitempty"`
	}
	if r.Body != nil {
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&req); err != nil && !errors.Is(err, io.EOF) {
			writeErr(w, 400, err.Error())
			return
		}
	}
	if req.Seg == nil {
		if raw := strings.TrimSpace(r.URL.Query().Get("seg")); raw != "" {
			if parsed, err := strconv.Atoi(raw); err == nil {
				req.Seg = &parsed
			}
		}
	}
	var stopped bool
	if req.Seg != nil {
		if *req.Seg < 0 && *req.Seg != db.MainSegConsultation {
			writeErr(w, 400, "invalid session segment")
			return
		}
		stopped = s.cancelTaskChatSeg(t.ID, *req.Seg, agent.AbortChatStoppedByUser)
	} else {
		stopped = s.cancelTaskChat(t.ID, agent.AbortChatStoppedByUser)
	}
	if !stopped {
		writeJSON(w, 200, map[string]any{"status": "idle"})
		return
	}
	writeJSON(w, 200, map[string]any{"status": "stopping"})
}

// fallbackChat is the no-LLM human-steering handler: simple命令 + 态势摘要.
func (s *Server) fallbackChat(t *Task, msg string) string {
	m := strings.TrimSpace(msg)
	lower := strings.ToLower(m)
	switch {
	case strings.HasPrefix(m, "意图") || strings.HasPrefix(lower, "intent"):
		text := strings.TrimSpace(strings.TrimPrefix(strings.TrimPrefix(m, "意图"), "intent"))
		_, _ = t.Store.AddIntent(map[string]any{"summary": text}, 9, nil, "human")
		return "已注入一条高优先级意图：" + text
	case strings.HasPrefix(m, "提示") || strings.HasPrefix(lower, "hint"):
		text := strings.TrimSpace(strings.TrimPrefix(strings.TrimPrefix(m, "提示"), "hint"))
		_, _ = t.Store.AddNode(db.KindHint, map[string]any{"text": text}, 0, "active", "human", nil)
		return "已记录提示，规划者下次会读到：" + text
	default:
		assetCounts, _ := s.m.Assets().CountsByType()
		assets := 0
		for _, c := range assetCounts {
			assets += c
		}
		fnd, _ := t.Store.ListByKind(db.KindFinding, 1000)
		fr, _ := t.Store.Frontier(1000)
		return fmt.Sprintf("（规则模式，未配置 LLM）当前态势：资产 %d，待领意图 %d，确认发现 %d。\n可用指令：以\"意图 ...\"注入意图，\"提示 ...\"给规划者提示。", assets, len(fr), len(fnd))
	}
}
