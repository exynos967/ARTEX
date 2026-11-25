package harness

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"iter"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/RC-CHN/ARTEX/norma/llm"
	"github.com/RC-CHN/ARTEX/norma/permission"
	"github.com/RC-CHN/ARTEX/norma/tool"
)

// QueryInput is a fully-resolved request to run the loop.
type QueryInput struct {
	Provider        llm.Provider
	System          []string
	DynamicBoundary int
	Messages        []llm.Message // conversation including the latest user turn
	// SystemReminder, when non-empty, is prepended as the first message on each
	// model call. It is not stored in conversation history — the host builds it
	// fresh per Prompt call so it never accumulates across turns.
	SystemReminder string
	Tools          *tool.Registry
	// DeferredTools names tools whose schemas are withheld from the model's tool
	// list (they stay in Tools and are invoked via ExecuteExtraTool). Empty = all
	// tool schemas sent as usual.
	DeferredTools []string
	MaxTokens     int
	Temperature   *float64
	// MaxTurns bounds tool-turns (0 = off). MaxDuration bounds wall-clock time,
	// checked at the turn boundary so a turn is never aborted mid-stream — unlike
	// cancelling ctx, which cuts an in-flight stream/tool (0 = off).
	MaxTurns       int
	MaxDuration    time.Duration
	MaxConcurrency int
	// NonStreaming makes each model call a single non-streaming request (via
	// QueryDeps.CallModelSync / Provider.Complete) instead of a token stream. The
	// loop still emits the same KindText/KindThinking/KindToolUse/KindUsage events
	// to the host — they are surfaced once, when the full response arrives, rather
	// than incrementally. Zero value = streaming (unchanged default).
	NonStreaming bool
	WorkingDir   string
	AgentID      string
	// ToolOutputDir, when set, makes oversized tool output spill to a file there
	// (full content kept) instead of being discarded; MaxToolOutputChars sets the
	// per-tool output budget (head size; 0 = default 30000). See tool.Capture.
	ToolOutputDir      string
	MaxToolOutputChars int

	// Tasks, when non-nil, is the background-task manager shared with the tools.
	// The loop drains its completion notifications into the conversation between
	// tool turns so the model learns when background work finishes.
	Tasks *tool.Manager
	// Notifications replaces the local manager's completion source when tools
	// execute in a host-provided runtime. Tasks remains for local tool execution.
	Notifications tool.NotificationSource

	// Todos, when non-nil, enables todo system-reminders: when the model hasn't
	// used TodoWrite for TodoReminderTurnsSinceWrite turns (and it's been at least
	// TodoReminderTurnsBetweenReminder turns since the last reminder), the current
	// list is re-surfaced as a <system-reminder> user message. Throttle turns are
	// derived by scanning the API-visible history, so it survives compaction and
	// resume. 0 thresholds default to 10/10 (mirrors claude-code).
	Todos                            *tool.TodoStore
	TodoReminderTurnsSinceWrite      int
	TodoReminderTurnsBetweenReminder int

	// BashEnv holds extra "KEY=VALUE" entries injected into Bash subprocess
	// environments (foreground + background). Empty = inherit unchanged.
	BashEnv []string

	// Permission policy.
	PermissionMode     permission.Mode
	PermissionModeFunc func() permission.Mode
	Allowed            []string
	Disallowed         []string
	CanUseTool         permission.CanUseTool

	// Hooks is optional lifecycle instrumentation. Nil disables it.
	Hooks HookRunner
	// Compactor is optional context-window management. Nil disables it.
	Compactor Compactor
	// Recorder, when non-nil, is notified as the conversation grows so a host can
	// persist a transcript. It fires for genuinely new messages (births) in
	// order, and for compaction boundaries; it is never called for compaction's
	// ephemeral working-set edits (MicroCompact tool-result clearing), so the
	// recorded transcript is the raw, full-fidelity history.
	Recorder Recorder

	// TokenBudget, when > 0, enables budget-driven continuation: after a turn
	// with no tool calls, the agent is nudged to keep working until ~90% of the
	// budget (output tokens), stopping early on diminishing returns.
	TokenBudget int
	// EscalateMaxTokens, when true, first retries a max_tokens truncation with a
	// raised output cap (64k) before falling back to resume-recovery.
	EscalateMaxTokens bool

	// Settlement, when non-nil with a Prompt, runs a bounded wrap-up phase the
	// moment a budget (MaxTurns/MaxDuration) is hit: it injects Prompt as a user
	// turn and blocks DisabledTools at execution time (leaving wire tool schemas
	// unchanged so the prompt-cache prefix stays intact), so a budget-terminated
	// run can checkpoint its findings instead of ending abruptly. The run still
	// finishes with the budget's reason (ReasonMaxTurns/ReasonTimeout), never
	// ReasonCompleted. Nil = off.
	Settlement *Settlement
	// TurnBudget reserves a durable model attempt before issuing it. Hosts may
	// enforce a cumulative budget across resumes. An unavailable ledger fails
	// closed. This is separate from TokenBudget's continuation-nudge behavior.
	TurnBudget TurnBudget
	// RequireFinalText allows a budgeted recovery after a stop without final text.
	RequireFinalText bool
	// ContinueAfterEmptyReply keeps tools and the normal loop available during
	// that recovery. Successful tool progress renews the single recovery allowance;
	// without such progress, another empty reply ends with ReasonEmptyResponse.
	// It does not override explicit budgets or their settlement. False preserves
	// the one text-only recovery used by workers.
	ContinueAfterEmptyReply bool
}

type TurnDecision struct {
	Allowed, Settle bool
	Notice          string
}
type TurnBudget interface {
	BeforeTurn(context.Context, bool) (TurnDecision, error)
	AfterTurn(context.Context, llm.Usage) error
}

// Settlement configures the wrap-up phase that runs when a budget is hit.
type Settlement struct {
	Prompt        string   // wrap-up instruction injected as a user turn (empty = settlement off)
	MaxTurns      int      // turn budget for the wrap-up phase itself (0 = default 2)
	DisabledTools []string // tool names blocked at execution time during wrap-up (e.g. ["Bash"])
	// PromptByReason optionally overrides Prompt based on WHY the run settled
	// (keyed by the terminal reason, e.g. ReasonTimeout / ReasonMaxTurns). When the
	// settling reason has a non-empty entry here it is used; otherwise Prompt is used.
	// Lets a caller inject a different wrap-up depending on whether a run was cut by
	// its time budget vs its step budget, without knowing which at build time.
	PromptByReason map[TerminalReason]string
}

// promptFor returns the wrap-up prompt to inject for a settling reason: the
// PromptByReason override when present and non-empty, else the base Prompt.
func (s *Settlement) promptFor(reason TerminalReason) string {
	if s.PromptByReason != nil {
		if p := s.PromptByReason[reason]; p != "" {
			return p
		}
	}
	return s.Prompt
}

// Compactor is the harness's view of the compaction system (implemented in
// package compaction). Compaction is non-destructive; the harness sends only
// llm.MessagesForAPI(messages) to the model.
type Compactor interface {
	// Pre conditions the history before a model request. lastInputTokens is the
	// total token size the previous model response reported (0 if none yet), used
	// as the initial gate count in preference to local estimation.
	Pre(ctx context.Context, msgs []llm.Message, lastInputTokens int) []llm.Message
	Reactive(ctx context.Context, msgs []llm.Message) ([]llm.Message, bool)
	IsOverflow(err error) bool
}

// ContextView is optionally implemented by a Compactor that builds the request
// message array itself, replacing llm.MessagesForAPI. Hosts with their own
// context manager (e.g. model-driven compression) implement it to project the
// history per request without mutating it.
//
// View MUST be pure: the returned slice is used for this request only and is
// never written back to the loop's history. Implementations that depend on
// stable message identity (content hashing, per-message refs) rely on this —
// writing back would change message bytes and invalidate that identity.
type ContextView interface {
	View(ctx context.Context, msgs []llm.Message) []llm.Message
}

// Recorder receives conversation events for durable transcript persistence
// (implemented in package transcript). RecordMessage fires once per new message
// in birth order; usage carries the token delta attributed to that turn
// (assistant messages only; zero otherwise). RecordBoundary fires when
// compaction inserts a boundary, for observability — boundaries are not part of
// the raw reconstructable history.
type Recorder interface {
	RecordMessage(m llm.Message, usage llm.Usage)
	RecordBoundary(meta llm.BoundaryMeta)
}

// HookRunner is the harness's view of the hook system (implemented in package
// hook). Stop returns two distinct outcomes: preventContinuation (hard
// terminate) and/or blockingErrors (inject + continue).
type HookRunner interface {
	PreToolUse(ctx context.Context, name string, input []byte) (block bool, message string, updated []byte)
	PostToolUse(ctx context.Context, name string, input, result []byte, isErr bool)
	Stop(ctx context.Context, messages []llm.Message) (prevent bool, blockingErrors []string, message string)
}

// QueryDeps are injectable side-effect boundaries for testing (FR-01.6).
type QueryDeps struct {
	CallModel func(ctx context.Context, req llm.CompletionRequest) iter.Seq2[llm.StreamEvent, error]
	// CallModelSync is the non-streaming counterpart of CallModel, used when
	// QueryInput.NonStreaming is set. It performs a single request and returns the
	// fully assembled assistant message, the stop reason, and cumulative usage.
	CallModelSync func(ctx context.Context, req llm.CompletionRequest) (llm.Message, string, llm.Usage, error)
	NewID         func() string
}

func (d *QueryDeps) withDefaults(in QueryInput) {
	if d.CallModel == nil && in.Provider != nil {
		d.CallModel = in.Provider.Stream
	}
	if d.CallModelSync == nil && in.Provider != nil {
		d.CallModelSync = in.Provider.Complete
	}
	if d.NewID == nil {
		var n int64
		d.NewID = func() string { return "id_" + strconv.FormatInt(atomic.AddInt64(&n, 1), 10) }
	}
}

// Query runs the agent loop and returns its event stream. The final event is
// always KindResult carrying a Terminal (unless the consumer stops early).
func Query(ctx context.Context, in QueryInput, deps QueryDeps) iter.Seq2[Event, error] {
	deps.withDefaults(in)
	conc := in.MaxConcurrency
	if conc <= 0 {
		conc = 10
	}
	return func(yield func(Event, error) bool) {
		runCtx, cancel := context.WithCancelCause(ctx)
		defer cancel(nil)
		l := &loop{ctx: runCtx, cancelRun: cancel, in: in, deps: deps, yield: yield, sem: make(chan struct{}, conc)}
		l.messages = append([]llm.Message(nil), in.Messages...)
		if in.ContinueAfterEmptyReply {
			l.messages = withoutLegacyFinalTextPrompt(l.messages)
		}
		l.run()
	}
}

// budgetTracker tracks token-budget continuation state.
type budgetTracker struct {
	continuationCount    int
	lastGlobalTurnTokens int
	lastDeltaTokens      int
}

type loop struct {
	summaryOnly              bool
	summaryRecoveryAttempted bool
	summaryRecoveryAttempts  int
	summaryRecoveryMode      string
	finalTextRecoveryUsed    bool
	summaryRecoveryFailed    bool
	finalTextRecoveryPrompt  string // request-local; never recorded or compacted
	failureStreaks           map[string]failureStreak
	interruptedToolInput     *llm.ContentBlock
	ctx                      context.Context
	cancelRun                context.CancelCauseFunc
	// toolCtx bounds tool execution with the run's MaxDuration deadline, so a tool
	// that overruns the wall-clock budget is interrupted mid-flight (the model call
	// stays on ctx — streams are never cut mid-flight). Derived from ctx, so a parent
	// cancellation (pause/kill/shutdown) still cancels it. Swapped to ctx once the
	// wrap-up phase begins, so settlement tools run live, bounded only by settleMaxTurns.
	toolCtx context.Context
	in      QueryInput
	deps    QueryDeps
	yield   func(Event, error) bool
	sem     chan struct{} // bounds concurrent tool execution

	messages        []llm.Message
	usage           llm.Usage
	lastInputTokens int // total token size the previous model response reported (compaction gate)
	turnCount       int
	boundaryCount   int       // boundary markers already seen, so Recorder fires once each
	startTime       time.Time // loop start, for MaxDuration (wall-clock budget)

	// Tool admission reads the phase from streaming goroutines. A deadline can
	// let the loop enter settlement before those goroutines finish, so this flag
	// must be atomic. The remaining settlement state belongs to the loop only.
	settling     atomic.Bool
	settleReason TerminalReason // the budget reason to finish with after wrap-up
	settleTurn   int

	// recovery / continuation state
	maxOutputTokensOverride      int
	maxOutputTokensRecoveryCount int
	hasAttemptedReactiveCompact  bool
	stopHookActive               bool
	budget                       budgetTracker
	lastContinue                 ContinueReason
}

const (
	budgetCompletionThresholdNum = 9 // 0.9
	budgetCompletionThresholdDen = 10
	budgetDiminishingThreshold   = 500
	escalatedMaxTokens           = 64000
	maxOutputTokensRecoveryLimit = 3
	// maxLoopIterations is a defensive backstop; turnCount counts only tool-turns,
	// so this only guards against a pathological recovery/continuation loop.
	maxLoopIterations = 10000
)

func (l *loop) emit(ev Event) bool { return l.yield(ev, nil) }

// record forwards a newly appended message to the transcript Recorder, if any.
func (l *loop) record(m llm.Message, u llm.Usage) {
	if l.in.Recorder != nil {
		l.in.Recorder.RecordMessage(m, u)
	}
}

// injectTaskNotifications drains completion notifications from the background-task
// manager and appends them to the conversation as a user message, so the model is
// told when background work finishes. Returns true if any were injected.
func (l *loop) injectTaskNotifications() bool {
	source := l.in.Notifications
	if source == nil && l.in.Tasks != nil {
		source = l.in.Tasks
	}
	if source == nil {
		return false
	}
	notes := source.DrainNotifications()
	if len(notes) == 0 {
		return false
	}
	var b strings.Builder
	for i, n := range notes {
		if i > 0 {
			b.WriteString("\n")
		}
		b.WriteString(n.String())
	}
	msg := llm.UserText(b.String())
	l.messages = append(l.messages, msg)
	l.record(msg, llm.Usage{})
	return true
}

// tailRefRecorder is optionally implemented by a Recorder (e.g. transcript.Writer)
// that persists kept-tail messages after a compaction boundary as compact
// references to already-persisted records rather than duplicating large payloads.
type tailRefRecorder interface {
	RecordMessageRef(m llm.Message)
}

// recordNewBoundary persists a boundary that compaction just inserted (detected
// by a rise in the boundary-marker count). It writes the post-boundary working
// set — the boundary marker, the summary, and the kept recent tail — as durable
// records, so a COLD-START Resume restores the compacted view via MessagesForAPI
// instead of replaying raw history and re-summarizing. When the Recorder
// implements tailRefRecorder, kept-tail messages after the boundary marker and
// summary are recorded via RecordMessageRef so large tool results are referenced
// rather than duplicated on disk. RecordBoundary keeps the observability and
// cumulative-usage checkpoint (a Type:"boundary" record, skipped during message
// reconstruction).
func (l *loop) recordNewBoundary() {
	if l.in.Recorder == nil {
		return
	}
	c := countBoundaries(l.messages)
	if c <= l.boundaryCount {
		return
	}
	if i := llm.LastBoundaryIndex(l.messages); i >= 0 {
		if meta, ok := llm.ParseBoundaryMeta(l.messages[i]); ok {
			l.in.Recorder.RecordBoundary(meta)
		}
		tail := l.messages[i:] // boundary marker + summary + [reinjected skills +] kept tail
		refRec, hasRef := l.in.Recorder.(tailRefRecorder)
		for idx, m := range tail {
			// Boundary marker (idx==0) and freshly generated summary (idx==1) are
			// newly created; subsequent kept-tail messages may already exist on
			// disk and can be written as compact refs.
			if hasRef && idx >= 2 {
				refRec.RecordMessageRef(m)
			} else {
				l.in.Recorder.RecordMessage(m, llm.Usage{})
			}
		}
	}
	l.boundaryCount = c
}

func usageDelta(before, after llm.Usage) llm.Usage {
	return llm.Usage{
		InputTokens:      after.InputTokens - before.InputTokens,
		OutputTokens:     after.OutputTokens - before.OutputTokens,
		CacheReadTokens:  after.CacheReadTokens - before.CacheReadTokens,
		CacheWriteTokens: after.CacheWriteTokens - before.CacheWriteTokens,
	}
}

func countBoundaries(msgs []llm.Message) int {
	n := 0
	for _, m := range msgs {
		if llm.IsBoundaryMarker(m) {
			n++
		}
	}
	return n
}

func (l *loop) finish(reason TerminalReason, err error, text string) {
	l.yield(Event{Kind: KindResult, Terminal: &Terminal{
		InterruptedToolInput:     l.interruptedToolInput,
		SummaryRecoveryAttempted: l.summaryRecoveryAttempted,
		SummaryRecoveryAttempts:  l.summaryRecoveryAttempts,
		SummaryRecoveryMode:      l.summaryRecoveryMode,
		SummaryRecoveryFailed:    l.summaryRecoveryFailed,
		SummaryMissing:           l.in.RequireFinalText && strings.TrimSpace(text) == "",
		Reason:                   reason,
		Err:                      err,
		Usage:                    l.usage,
		Turns:                    l.turnCount,
		Messages:                 l.messages,
		Text:                     text,
	}}, nil)
}

func (l *loop) maxTokens() int {
	if l.maxOutputTokensOverride > 0 {
		return l.maxOutputTokensOverride
	}
	if l.in.MaxTokens > 0 {
		return l.in.MaxTokens
	}
	return 32768
}

func (l *loop) run() {
	var schemas []llm.ToolSchema
	if l.in.Tools != nil {
		schemas = l.in.Tools.Schemas()
		// Deferred tools stay in the registry (callable via ExecuteExtraTool) but
		// their schemas are withheld from the model to save context tokens.
		if len(l.in.DeferredTools) > 0 {
			schemas = filterToolSchemas(schemas, l.in.DeferredTools)
		}
	}
	l.turnCount = 1 // the first model call is turn 1
	l.boundaryCount = countBoundaries(l.messages)
	l.startTime = time.Now() // wall-clock baseline for MaxDuration
	// toolCtx carries the MaxDuration deadline so a tool that overruns the wall-clock
	// budget is interrupted mid-flight (rather than the run only noticing at the next
	// turn boundary, which a hung tool never reaches). On interrupt the loop enters the
	// wrap-up phase on the live parent ctx instead of aborting — see the tools branch.
	l.toolCtx = l.ctx
	if l.in.MaxDuration > 0 {
		var stopTool context.CancelFunc
		l.toolCtx, stopTool = context.WithDeadline(l.ctx, l.startTime.Add(l.in.MaxDuration))
		defer stopTool()
	}
	iterations := 0
	for {
		if cause := context.Cause(l.ctx); tool.IsFatalExecution(cause) {
			l.finish(ReasonExecutionError, cause, "")
			return
		}
		if l.ctx.Err() != nil {
			l.finish(ReasonAbortedStreaming, l.ctx.Err(), "")
			return
		}
		// Defensive backstop against a pathological recovery/continuation loop.
		// turnCount itself only counts tool-turns (below); every continuation path
		// is individually bounded, so this guard should never fire in practice.
		iterations++
		if iterations > maxLoopIterations {
			l.finish(ReasonMaxTurns, nil, "")
			return
		}

		l.injectHostNotices()
		if l.in.TurnBudget != nil {
			d, err := l.in.TurnBudget.BeforeTurn(l.ctx, l.settling.Load())
			if err != nil {
				l.finish(ReasonExecutionError, fmt.Errorf("reserve model turn budget: %w", err), "")
				return
			}
			if d.Notice != "" {
				msg := llm.UserText(d.Notice)
				l.messages = append(l.messages, msg)
				l.record(msg, llm.Usage{})
			}
			if !d.Allowed {
				if !l.summaryOnly && d.Settle && !l.settling.Load() && l.beginSettlement(ReasonMaxTurns) {
					continue
				}
				reason := ReasonMaxTurns
				if l.settling.Load() {
					reason = l.settleReason
				}
				l.finish(reason, nil, "")
				return
			}
		}
		// Non-destructive proactive compaction (MicroCompact → AutoCompact).
		if l.in.Compactor != nil {
			l.messages = l.in.Compactor.Pre(l.ctx, l.messages, l.lastInputTokens)
			l.recordNewBoundary()
		}

		recovering := l.finalTextRecoveryPrompt != ""
		if recovering {
			l.summaryRecoveryAttempted = true
			l.summaryRecoveryAttempts++
			l.finalTextRecoveryUsed = true
			l.summaryRecoveryMode = "continue"
			if l.summaryOnly {
				l.summaryRecoveryMode = "text_only"
			}
		}
		usageBefore := l.usage
		asst, exec, stopReason, streamErr, consumerStopped, aborted := l.streamAndExecute(schemas)
		l.finalTextRecoveryPrompt = ""
		var budgetErr error
		if l.in.TurnBudget != nil {
			budgetErr = l.in.TurnBudget.AfterTurn(l.ctx, usageDelta(usageBefore, l.usage))
		}
		if consumerStopped {
			return
		}
		if cause := context.Cause(l.ctx); tool.IsFatalExecution(cause) {
			// Preserve the attempted call and its error result in the transcript;
			// resuming this intent must not look like the call never happened.
			l.messages = append(l.messages, asst)
			l.record(asst, usageDelta(usageBefore, l.usage))
			if exec != nil && exec.count() > 0 {
				result := llm.Message{Role: llm.RoleUser, Content: exec.results()}
				l.messages = append(l.messages, result)
				l.record(result, llm.Usage{})
			}
			l.finish(ReasonExecutionError, cause, "")
			return
		}
		if streamErr != nil {
			// Completed tool blocks can already have executed while streaming.
			// Preserve their outcomes; never retry the model turn over those effects.
			if len(asst.Content) > 0 {
				l.messages = append(l.messages, asst)
				l.record(asst, usageDelta(usageBefore, l.usage))
			}
			if exec != nil && exec.count() > 0 {
				result := llm.Message{Role: llm.RoleUser, Content: exec.results()}
				l.messages = append(l.messages, result)
				l.record(result, llm.Usage{})
			}
			if l.ctx.Err() != nil {
				l.finish(ReasonAbortedStreaming, l.ctx.Err(), "")
				return
			}
			var incomplete *llm.IncompleteResponseError
			if errors.As(streamErr, &incomplete) {
				// Provider recovery is already bounded to the uncommitted response.
				// Keep prior effects and partial output; never replay this whole run
				// or turn a malformed response into the text-only settlement path.
				l.finish(ReasonIncompleteResponse, streamErr, asst.Text())
				return
			}
			// A recovery failure never repeats this request or its tool effects.
			if recovering {
				l.summaryRecoveryFailed = true
				if !l.summaryOnly {
					l.finish(ReasonModelError, streamErr, "")
					return
				}
				// The main work already completed. Failure of this optional reply
				// must not turn it into a model-error retry of prior side effects.
				reason := ReasonCompleted
				if l.settling.Load() {
					reason = l.settleReason
				}
				l.finish(reason, nil, "")
				return
			}
			// Reactive recovery from prompt-too-long: one forced AutoCompact, then retry.
			if (exec == nil || exec.count() == 0) && l.in.Compactor != nil && l.in.Compactor.IsOverflow(streamErr) && !l.hasAttemptedReactiveCompact {
				l.hasAttemptedReactiveCompact = true
				if msgs, ok := l.in.Compactor.Reactive(l.ctx, l.messages); ok {
					l.messages = msgs
					l.recordNewBoundary()
					l.lastContinue = ContinueReactiveCompactRetry
					continue
				}
				l.finish(ReasonPromptTooLong, streamErr, "")
				return
			}
			l.finish(ReasonModelError, streamErr, "")
			return
		}
		l.hasAttemptedReactiveCompact = false
		l.messages = append(l.messages, asst)
		turnUsage := usageDelta(usageBefore, l.usage)
		// The size the model just reported for its input, preferred by the
		// compactor over local estimation on the next turn's gate check.
		l.lastInputTokens = turnUsage.InputTokens + turnUsage.OutputTokens
		l.record(asst, turnUsage)
		if budgetErr != nil {
			// Tool side effects may already exist; preserve their outcomes before
			// stopping. Never retry a model turn over an uncertain ledger write.
			if exec != nil && exec.count() > 0 {
				result := llm.Message{Role: llm.RoleUser, Content: exec.results()}
				l.messages = append(l.messages, result)
				l.record(result, llm.Usage{})
			}
			l.finish(ReasonExecutionError, fmt.Errorf("record model turn usage: %w", budgetErr), "")
			return
		}
		// surface cumulative usage after each model turn so hosts can show live token
		// counts during a run (not just at the terminal event).
		if u := l.usage; u != (llm.Usage{}) {
			if !l.emit(Event{Kind: KindUsage, Usage: &u}) {
				return
			}
		}
		toolUses := asst.ToolUses()
		// Text-only recovery cannot trigger tools, hooks, keep-working nudges or
		// another model request. Preserve rejected calls as explicit receipts.
		if l.summaryOnly {
			if exec != nil && exec.count() > 0 {
				result := llm.Message{Role: llm.RoleUser, Content: exec.results()}
				l.messages = append(l.messages, result)
				l.record(result, llm.Usage{})
			}
			reason := ReasonCompleted
			if l.settling.Load() {
				reason = l.settleReason
			}
			l.finish(reason, nil, asst.Text())
			return
		}

		// max_tokens truncation with no tool calls → escalate / resume-recovery.
		// These continuations are retries of the same turn (they do not advance
		// turnCount).
		if stopReason == "max_tokens" && len(toolUses) == 0 {
			if l.handleMaxOutputTokens() {
				continue
			}
			// recovery exhausted: surface the truncated turn as completion.
		} else {
			l.maxOutputTokensOverride = 0
		}

		if len(toolUses) == 0 {
			// During the wrap-up phase, a natural stop ends the run with the ORIGINAL
			// budget reason (not "completed") — the run was budget-terminated; the
			// settlement is just a checkpoint. Skip the keep-working nudges below.
			if l.settling.Load() {
				if strings.TrimSpace(asst.Text()) == "" && l.beginFinalTextRecovery() {
					continue
				}
				l.finish(l.settleReason, nil, asst.Text())
				return
			}
			// Stop hooks: hard terminate, or force continue with injected errors.
			// stopHookActive prevents an always-blocking hook from looping forever
			// without an intervening tool-turn.
			if l.in.Hooks != nil && !l.stopHookActive {
				prevent, blocking, msg := l.in.Hooks.Stop(l.ctx, l.messages)
				if prevent {
					l.finish(ReasonStopHookPrevented, nil, msg)
					return
				}
				if len(blocking) > 0 {
					for _, b := range blocking {
						bm := llm.UserText(b)
						l.messages = append(l.messages, bm)
						l.record(bm, llm.Usage{})
					}
					l.stopHookActive = true
					l.lastContinue = ContinueStopHookBlocking
					continue
				}
			}
			l.stopHookActive = false
			// Surface any background-task completions before ending the turn; if any
			// landed, take another turn so the model can react to them.
			if l.injectTaskNotifications() || l.injectHostNotices() {
				l.lastContinue = ContinueTaskNotification
				continue
			}
			// Token budget: nudge to keep working until ~90% / diminishing returns.
			if l.in.TokenBudget > 0 && l.checkBudgetContinue() {
				l.lastContinue = ContinueTokenBudget
				continue
			}
			// Stop hooks and host notices may cancel while processing the final
			// response. Cancellation takes precedence over empty-reply recovery.
			if l.ctx.Err() != nil {
				l.finish(ReasonAbortedStreaming, l.ctx.Err(), "")
				return
			}
			if strings.TrimSpace(asst.Text()) == "" {
				if l.beginFinalTextRecovery() {
					continue
				}
				if l.in.RequireFinalText && l.in.ContinueAfterEmptyReply && l.finalTextRecoveryUsed {
					l.finish(ReasonEmptyResponse, ErrEmptyResponse, "")
					return
				}
			}
			l.finish(ReasonCompleted, nil, asst.Text())
			return
		}

		// Tools were executed during streaming; record their results.
		results := exec.results()
		resultMsg := llm.Message{Role: llm.RoleUser, Content: results}
		l.messages = append(l.messages, resultMsg)
		l.record(resultMsg, llm.Usage{})
		l.noteRepeatedFailures(toolUses, results)
		// Main may recover again after demonstrated tool progress. Failed or
		// rejected calls do not replenish the allowance; Worker and settlement
		// text-only recovery remain bounded to their existing behavior.
		if l.in.RequireFinalText && l.in.ContinueAfterEmptyReply && !l.settling.Load() {
			for _, result := range results {
				if result.Type == llm.BlockToolResult && !result.IsError {
					l.finalTextRecoveryUsed = false
					break
				}
			}
		}
		// Extra messages a tool injected after its result (e.g. the Skill tool's
		// instructions as an independent user message) are appended next so the
		// next model round sees them as standing guidance.
		for _, em := range exec.extraMessages() {
			l.messages = append(l.messages, em)
			l.record(em, llm.Usage{})
		}
		// Surface any background-task completions that landed during this turn so
		// the next model round sees them alongside the tool results.
		l.injectTaskNotifications()
		// Parent-ctx cancellation (pause / planner kill / shutdown) → real abort, no wrap-up.
		if l.ctx.Err() != nil {
			l.finish(ReasonAbortedTools, l.ctx.Err(), "")
			return
		}
		// aborted with the parent still alive ⇒ the run's own MaxDuration deadline (on
		// toolCtx) interrupted an in-flight tool. Enter the wrap-up phase on the live
		// parent ctx instead of dying, so a run whose tool overran the wall-clock budget
		// still checkpoints its findings. Mid-tool interrupts are always time-driven
		// (MaxTurns is only ever checked at the turn boundary), hence ReasonTimeout.
		if aborted {
			if l.settling.Load() {
				l.finish(l.settleReason, nil, "")
				return
			}
			if l.beginSettlement(ReasonTimeout) {
				l.toolCtx = l.ctx // wrap-up tools run live, bounded only by settleMaxTurns
				l.lastContinue = ContinueNextTurn
				continue
			}
			l.finish(ReasonTimeout, nil, "")
			return
		}

		// next_turn: only tool-turns advance turnCount.
		l.stopHookActive = false // a real turn happened; stop hooks may fire fresh
		if l.settling.Load() {
			// wrap-up phase: bounded by its own small turn budget. When spent, finish
			// with the original budget reason (not "completed").
			l.settleTurn++
			if l.in.TurnBudget == nil && l.settleTurn >= l.settleMaxTurns() {
				l.finish(l.settleReason, nil, "")
				return
			}
			l.lastContinue = ContinueNextTurn
			continue
		}
		// Primary budgets are checked HERE, at the turn boundary — never mid-stream —
		// so a turn is not aborted in flight (that would surface as an abort/error).
		// On hit, optionally run the wrap-up phase before finishing.
		nextTurn := l.turnCount + 1
		hitTurns := l.in.MaxTurns > 0 && nextTurn > l.in.MaxTurns
		hitTime := l.in.MaxDuration > 0 && time.Since(l.startTime) >= l.in.MaxDuration
		if hitTurns || hitTime {
			reason := ReasonMaxTurns
			if hitTime && !hitTurns {
				reason = ReasonTimeout
			}
			if l.beginSettlement(reason) {
				l.lastContinue = ContinueNextTurn
				continue
			}
			l.finish(reason, nil, "")
			return
		}
		l.turnCount = nextTurn
		l.lastContinue = ContinueNextTurn
	}
}

// beginFinalTextRecovery consumes an ordinary remaining attempt. It never replays
// earlier tool calls and never extends configured run/settlement limits.
func (l *loop) beginFinalTextRecovery() bool {
	if !l.in.RequireFinalText || l.finalTextRecoveryUsed || l.finalTextRecoveryPrompt != "" || l.ctx.Err() != nil {
		return false
	}
	if l.settling.Load() {
		if l.in.TurnBudget == nil && l.settleTurn+1 >= l.settleMaxTurns() {
			return false
		}
		l.settleTurn++
	} else {
		if l.in.MaxTurns > 0 && l.turnCount >= l.in.MaxTurns {
			return false
		}
		if l.in.MaxDuration > 0 && time.Since(l.startTime) >= l.in.MaxDuration {
			return false
		}
		l.turnCount++
	}
	l.summaryOnly = !l.in.ContinueAfterEmptyReply || l.settling.Load()
	l.finalTextRecoveryPrompt = finalTextOnlyPrompt
	if !l.summaryOnly {
		l.finalTextRecoveryPrompt = continueAfterEmptyReplyPrompt
	}
	l.lastContinue = ContinueFinalTextRecovery
	return true
}

// settleMaxTurns is the wrap-up phase's own turn budget (default 2).
func (l *loop) settleMaxTurns() int {
	if l.in.Settlement != nil && l.in.Settlement.MaxTurns > 0 {
		return l.in.Settlement.MaxTurns
	}
	return 2
}

// beginSettlement enters the wrap-up phase when configured: injects the caller's
// prompt as a user turn and enables execution-layer blocking of DisabledTools
// (leaving req.Tools byte-identical so the prompt-cache prefix survives into
// wrap-up). Returns false when no settlement is configured (caller then finishes
// immediately).
func (l *loop) beginSettlement(reason TerminalReason) bool {
	s := l.in.Settlement
	if s == nil {
		return false
	}
	prompt := s.promptFor(reason)
	if prompt == "" {
		return false
	}
	// A durable budget may expire after an empty reply scheduled a recovery.
	// The explicit settlement replaces that pending request-local reminder.
	l.finalTextRecoveryPrompt = ""
	msg := llm.UserText(prompt)
	l.messages = append(l.messages, msg)
	l.record(msg, llm.Usage{})
	l.settling.Store(true)
	l.settleReason = reason
	l.settleTurn = 0
	return true
}

// filterToolSchemas returns schemas with the named tools removed.
func filterToolSchemas(schemas []llm.ToolSchema, disabled []string) []llm.ToolSchema {
	block := make(map[string]bool, len(disabled))
	for _, d := range disabled {
		block[d] = true
	}
	out := make([]llm.ToolSchema, 0, len(schemas))
	for _, s := range schemas {
		if !block[s.Name] {
			out = append(out, s)
		}
	}
	return out
}

// handleMaxOutputTokens implements the escalate→recover(3×) flow. Returns true
// if it injected a recovery and the loop should continue.
func (l *loop) handleMaxOutputTokens() bool {
	if l.in.EscalateMaxTokens && l.maxOutputTokensOverride == 0 {
		l.maxOutputTokensOverride = escalatedMaxTokens
		l.lastContinue = ContinueMaxOutputTokensEscalate
		return true
	}
	if l.maxOutputTokensRecoveryCount < maxOutputTokensRecoveryLimit {
		nudge := llm.UserText(
			"Output token limit hit. Resume directly — no apology, no recap of what you already wrote. Continue exactly where you left off.")
		l.messages = append(l.messages, nudge)
		l.record(nudge, llm.Usage{})
		l.maxOutputTokensRecoveryCount++
		l.maxOutputTokensOverride = 0
		l.lastContinue = ContinueMaxOutputTokensRecovery
		return true
	}
	return false
}

// checkBudgetContinue continues with a nudge while under 90% of budget and not
// in diminishing returns; otherwise stops.
func (l *loop) checkBudgetContinue() bool {
	budget := l.in.TokenBudget
	if budget <= 0 || l.in.AgentID != "" { // subagents have no budget
		return false
	}
	turnTokens := l.usage.OutputTokens
	delta := turnTokens - l.budget.lastGlobalTurnTokens
	diminishing := l.budget.continuationCount >= 3 && delta < budgetDiminishingThreshold && l.budget.lastDeltaTokens < budgetDiminishingThreshold
	if !diminishing && turnTokens < budget*budgetCompletionThresholdNum/budgetCompletionThresholdDen {
		l.budget.continuationCount++
		l.budget.lastDeltaTokens = delta
		l.budget.lastGlobalTurnTokens = turnTokens
		pct := 0
		if budget > 0 {
			pct = turnTokens * 100 / budget
		}
		nudge := llm.UserText(fmt.Sprintf(
			"You have used %d%% of your token budget for this task (%d/%d output tokens). Keep going and finish the task; wrap up before the budget is exhausted.",
			pct, turnTokens, budget))
		l.messages = append(l.messages, nudge)
		l.record(nudge, llm.Usage{})
		return true
	}
	return false
}

// Todo system-reminder throttle defaults (mirror claude-code's TODO_REMINDER_CONFIG).
const (
	defaultTodoTurnsSinceWrite = 10
	defaultTodoTurnsBetween    = 10
)

func (l *loop) todoTurnsSinceWrite() int {
	if l.in.TodoReminderTurnsSinceWrite > 0 {
		return l.in.TodoReminderTurnsSinceWrite
	}
	return defaultTodoTurnsSinceWrite
}

func (l *loop) todoTurnsBetween() int {
	if l.in.TodoReminderTurnsBetweenReminder > 0 {
		return l.in.TodoReminderTurnsBetweenReminder
	}
	return defaultTodoTurnsBetween
}

// maybeInjectTodoReminder appends a todo <system-reminder> user message to the
// history when the model has gone long enough without touching TodoWrite and
// without a recent reminder. Throttle turns are derived from the API-visible
// window (post-boundary) so a reminder re-appears after compaction drops the
// prior one. No-op when todos are disabled or the list is empty.
func (l *loop) maybeInjectTodoReminder() {
	if l.in.Todos == nil {
		return
	}
	todos := l.in.Todos.List()
	if len(todos) == 0 {
		return
	}
	sinceWrite, sinceReminder := todoReminderTurnCounts(llm.MessagesForAPI(l.messages))
	if sinceWrite < l.todoTurnsSinceWrite() || sinceReminder < l.todoTurnsBetween() {
		return
	}
	body := tool.RenderTodoReminder(todos)
	if body == "" {
		return
	}
	msg := llm.TodoReminderMessage(body)
	l.messages = append(l.messages, msg)
	l.record(msg, llm.Usage{})
}

// todoReminderTurnCounts scans messages (most-recent first) and returns the
// number of assistant turns since the last TodoWrite tool_use and since the last
// todo reminder. The turn that contains the TodoWrite is not itself counted (so
// the call turn reads as 0). A never-seen event yields the total assistant-turn
// count (effectively "long ago").
func todoReminderTurnCounts(msgs []llm.Message) (sinceWrite, sinceReminder int) {
	foundWrite, foundReminder := false, false
	for i := len(msgs) - 1; i >= 0; i-- {
		m := msgs[i]
		if !foundReminder && llm.IsTodoReminder(m) {
			foundReminder = true
			continue
		}
		if m.Role != llm.RoleAssistant {
			continue
		}
		if !foundWrite {
			if messageHasToolUse(m, "TodoWrite") {
				foundWrite = true
			} else {
				sinceWrite++
			}
		}
		if !foundReminder {
			sinceReminder++
		}
	}
	return
}

func messageHasToolUse(m llm.Message, name string) bool {
	for _, b := range m.Content {
		if b.Type == llm.BlockToolUse && b.Name == name {
			return true
		}
	}
	return false
}

// streamAndExecute runs one model completion, surfacing text/thinking, and feeds
// tool_use blocks to the streaming executor as they finish — so tools begin
// running while the rest of the message is still arriving. It returns the
// assembled assistant message, the executor, the stop reason, and flags.
// requestMessages builds the message array for one model request. A Compactor
// that implements ContextView takes over the projection entirely; otherwise the
// default working set (post-boundary, unpaired tool blocks dropped) is used.
// Either way l.messages is left untouched.
func (l *loop) requestMessages() []llm.Message {
	if v, ok := l.in.Compactor.(ContextView); ok {
		return v.View(l.ctx, l.messages)
	}
	return llm.MessagesForAPI(l.messages)
}

func (l *loop) streamAndExecute(schemas []llm.ToolSchema) (asst llm.Message, exec *streamExec, stopReason string, err error, consumerStopped, aborted bool) {
	l.interruptedToolInput = nil
	// Keep req.Tools byte-identical during summaryOnly recovery to preserve the
	// prompt-cache prefix; streamExec enforces summaryOnly at execution time.
	l.maybeInjectTodoReminder()
	msgs := l.requestMessages()
	if l.finalTextRecoveryPrompt != "" {
		// Copy before append: ContextView may share its backing array with history.
		msgs = append(append([]llm.Message(nil), msgs...), llm.UserText(l.finalTextRecoveryPrompt))
	}
	if l.in.SystemReminder != "" {
		msgs = append([]llm.Message{llm.UserText(l.in.SystemReminder)}, msgs...)
	}
	req := llm.CompletionRequest{
		System:          l.in.System,
		DynamicBoundary: l.in.DynamicBoundary,
		Messages:        msgs,
		Tools:           schemas,
		MaxTokens:       l.maxTokens(),
		Temperature:     l.in.Temperature,
	}
	if l.in.NonStreaming {
		return l.completeAndExecute(req)
	}
	exec = newStreamExec(l)
	acc := llm.NewAccumulator()

	// Tool calls are collected per call, not in one "current call" buffer:
	// compatible gateways may interleave the argument deltas of parallel calls,
	// and a single buffer would splice one call's fragments into another's JSON.
	// A call is dispatched as soon as its arguments are complete JSON — the next
	// tool_use_start is only a hint that the previous call probably ended, and
	// anything still incomplete waits for the tool phase to finish.
	type toolDraft struct {
		id, name string
		input    strings.Builder
	}
	var drafts []*toolDraft
	byID := map[string]*toolDraft{}
	lastDraft := func() *toolDraft {
		if len(drafts) == 0 {
			return nil
		}
		return drafts[len(drafts)-1]
	}
	// flushCalls dispatches the calls that are certainly finished, in arrival
	// order. force=false is used when ANOTHER call starts: only a call whose
	// arguments are already valid JSON can be closed there, because a gateway may
	// still be streaming a parallel call's fragments into a different index.
	// force=true is used when the tool phase itself ends (text, stop, end of
	// stream), where nothing can arrive any more.
	flushCalls := func(force bool) bool { // false = consumer stopped
		n := 0
		for n < len(drafts) {
			raw := strings.TrimSpace(drafts[n].input.String())
			if !force && (raw == "" || !json.Valid([]byte(raw))) {
				// Later drafts wait too: tool results must keep arrival order.
				break
			}
			n++
		}
		if n == 0 {
			return true
		}
		pending := append([]*toolDraft(nil), drafts[:n]...)
		// byID keeps pointing at flushed drafts on purpose: a late fragment for a
		// call that already ran must land in its own dead buffer (harmless) rather
		// than fall through to "the last draft" and corrupt a live call.
		drafts = append([]*toolDraft(nil), drafts[n:]...)
		for _, d := range pending {
			raw := strings.TrimSpace(d.input.String())
			if raw == "" {
				// A call with no arguments is a complete call ("{}"). Incomplete
				// bytes are NOT turned into "{}": for a raw-input tool that would
				// throw away the fragments it repairs from, and for every other
				// tool execOne refuses them explicitly instead of running an
				// empty call.
				raw = "{}"
			}
			block := llm.ContentBlock{Type: llm.BlockToolUse, ID: d.id, Name: d.name, Input: []byte(raw)}
			if !l.emit(Event{Kind: KindToolUse, ToolUse: &block}) {
				return false
			}
			exec.add(block)
		}
		return exec.drain()
	}

	for ev, e := range l.deps.CallModel(l.ctx, req) {
		if e != nil {
			err = e
			break
		}
		// Transport diagnostics are metadata, not a content-block boundary.
		// In particular they must not finalize a partial tool before a stream error.
		// Providers deliver final accounting before their cancellation error, so
		// retain it even when cancellation has already stopped content execution.
		if ev.Type == llm.SEStreamDiagnostics {
			acc.Add(ev) // per-attempt accounting without dispatching pending tool input
			continue
		}
		if l.ctx.Err() != nil {
			err = l.ctx.Err()
			break
		}
		switch ev.Type {
		case llm.SEToolUseStart:
			// Close the calls that are already complete before opening another
			// one: that is what lets a finished tool run while the model keeps
			// streaming its siblings (FR-01.4).
			if !flushCalls(false) {
				return asst, exec, "", nil, true, false
			}
			if d := byID[ev.ToolID]; d != nil {
				// A gateway repeated the header for a call already started. Keep
				// exactly one draft, or the same call would run twice.
				if ev.ToolName != "" {
					d.name = ev.ToolName
				}
				acc.Add(ev)
				continue
			}
			d := &toolDraft{id: ev.ToolID, name: ev.ToolName}
			drafts = append(drafts, d)
			if ev.ToolID != "" {
				byID[ev.ToolID] = d
			}
			acc.Add(ev)
			continue
		case llm.SEToolInputJSON:
			// Route by call id. A host provider that does not stamp one gets the
			// legacy behaviour: the call most recently started.
			d := byID[ev.ToolID]
			if d == nil {
				d = lastDraft()
			}
			if d != nil {
				d.input.WriteString(ev.Text)
			}
			acc.Add(ev)
			continue
		}
		// Any other event ends the tool phase: dispatch everything collected,
		// in arrival order, before handling the event.
		if !flushCalls(true) {
			return asst, exec, "", nil, true, false
		}
		switch ev.Type {
		case llm.SETextDelta:
			if ev.Text != "" && !l.emit(Event{Kind: KindText, Text: ev.Text}) {
				return asst, exec, "", nil, true, false
			}
		case llm.SEThinkingDelta:
			if ev.Text != "" && !l.emit(Event{Kind: KindThinking, Text: ev.Text}) {
				return asst, exec, "", nil, true, false
			}
		}
		acc.Add(ev)
	}
	if err == nil {
		err = l.ctx.Err()
	}
	// Calls still open when the stream failed were never submitted. Report the
	// latest one and drop ALL of them from the recorded message: an assistant
	// tool_use without a tool_result cannot be replayed.
	var interruptedIDs map[string]bool
	if err != nil && len(drafts) > 0 {
		d := lastDraft()
		l.interruptedToolInput = &llm.ContentBlock{Type: llm.BlockToolUse, ID: d.id, Name: d.name, Input: []byte(d.input.String())}
		interruptedIDs = make(map[string]bool, len(drafts))
		for _, dr := range drafts {
			if dr.id != "" {
				interruptedIDs[dr.id] = true
			}
		}
	} else if err == nil && !flushCalls(true) {
		return asst, exec, "", nil, true, false
	}
	l.usage.Add(acc.Usage)
	asst = acc.Message()
	if len(interruptedIDs) > 0 {
		content := asst.Content[:0:0]
		for _, b := range asst.Content {
			if b.Type == llm.BlockToolUse && interruptedIDs[b.ID] {
				continue
			}
			content = append(content, b)
		}
		asst.Content = content
	}
	stopReason = acc.StopReason
	if err != nil {
		// Close visible calls with their real result when available, otherwise
		// an interrupted receipt. The failed stream must not leave a running UI.
		cs := !exec.drainSynthetic("tool execution interrupted by model stream failure; outcome may be incomplete")
		return asst, exec, stopReason, err, cs, l.ctx.Err() != nil
	}
	// Drain tools to completion (or synthesize on abort).
	cs, ab := exec.finish()
	if cs {
		return asst, exec, stopReason, nil, true, false
	}
	return asst, exec, stopReason, nil, false, ab
}

// replayableToolInput returns m with tool arguments that are not valid JSON
// replaced by "{}". A partial call cannot be replayed to any provider, and the
// tool result already told the model what happened to it.
func replayableToolInput(m llm.Message) llm.Message {
	var fixed []llm.ContentBlock
	for i, b := range m.Content {
		if b.Type != llm.BlockToolUse || json.Valid(b.Input) {
			continue
		}
		if fixed == nil {
			fixed = append([]llm.ContentBlock(nil), m.Content...)
		}
		fixed[i].Input = json.RawMessage("{}")
	}
	if fixed != nil {
		m.Content = fixed
	}
	return m
}

// completeAndExecute is the non-streaming counterpart of streamAndExecute's body.
// It performs a single non-streaming model call, then replays the assembled
// message as host events (thinking → text → each tool_use) and runs the same
// tool executor. The returned tuple matches streamAndExecute so the turn loop is
// oblivious to which path produced it. Usage is folded into l.usage exactly as
// the streaming accumulator does, so the loop's per-turn usage delta, KindUsage
// emission, and recorder all see identical numbers.
func (l *loop) completeAndExecute(req llm.CompletionRequest) (asst llm.Message, exec *streamExec, stopReason string, err error, consumerStopped, aborted bool) {
	exec = newStreamExec(l)
	msg, sr, usage, cerr := l.deps.CallModelSync(l.ctx, req)
	l.usage.Add(usage) // incomplete responses can still consume tokens
	if cerr != nil {
		// Keep text/thinking for diagnosis and resumption, but an unsuccessful
		// non-streaming response must not submit any of its tool calls.
		asst = llm.Message{Role: msg.Role}
		for _, b := range msg.Content {
			if b.Type != llm.BlockToolUse {
				asst.Content = append(asst.Content, b)
			} else if l.interruptedToolInput == nil {
				copy := b
				l.interruptedToolInput = &copy
			}
		}
		return asst, exec, sr, cerr, false, false
	}
	asst = msg
	stopReason = sr
	// Dispatch below uses the bytes the model sent; the recorded message must
	// carry arguments every wire format can replay. A raw-input tool may have
	// executed a partial call, so its truncated bytes become {} in history only.
	asst = replayableToolInput(asst)
	for _, b := range msg.Content {
		switch b.Type {
		case llm.BlockThinking:
			if b.Thinking != "" && !l.emit(Event{Kind: KindThinking, Text: b.Thinking}) {
				return asst, exec, stopReason, nil, true, false
			}
		case llm.BlockText:
			if b.Text != "" && !l.emit(Event{Kind: KindText, Text: b.Text}) {
				return asst, exec, stopReason, nil, true, false
			}
		case llm.BlockToolUse:
			block := b
			if !l.emit(Event{Kind: KindToolUse, ToolUse: &block}) {
				return asst, exec, stopReason, nil, true, false
			}
			exec.add(block)
			if !exec.drain() { // surface any results ready so far (FIFO)
				return asst, exec, stopReason, nil, true, false
			}
		}
	}
	// Drain tools to completion (or synthesize on abort).
	cs, ab := exec.finish()
	if cs {
		return asst, exec, stopReason, nil, true, false
	}
	return asst, exec, stopReason, nil, false, ab
}
