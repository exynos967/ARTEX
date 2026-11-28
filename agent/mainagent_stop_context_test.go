package agent

import (
	"context"
	"encoding/json"
	"errors"
	"iter"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/RC-CHN/ARTEX/db"
	"github.com/RC-CHN/ARTEX/norma/llm"
	actool "github.com/RC-CHN/ARTEX/norma/tool"
	"github.com/RC-CHN/ARTEX/norma/transcript"
)

type scriptedStopProvider struct {
	mu       sync.Mutex
	requests []llm.CompletionRequest
	streamFn func(ctx context.Context, call int, req llm.CompletionRequest) iter.Seq2[llm.StreamEvent, error]
}

func (p *scriptedStopProvider) Complete(ctx context.Context, req llm.CompletionRequest) (llm.Message, string, llm.Usage, error) {
	p.mu.Lock()
	call := len(p.requests) + 1
	p.requests = append(p.requests, req)
	p.mu.Unlock()
	if ctx.Err() != nil {
		return llm.Message{}, "", llm.Usage{}, ctx.Err()
	}
	acc := llm.NewAccumulator()
	for ev, err := range p.streamFn(ctx, call, req) {
		if err != nil {
			return llm.Message{}, "", llm.Usage{}, err
		}
		acc.Add(ev)
	}
	return acc.Message(), acc.StopReason, acc.Usage, nil
}

func (p *scriptedStopProvider) Stream(ctx context.Context, req llm.CompletionRequest) iter.Seq2[llm.StreamEvent, error] {
	p.mu.Lock()
	call := len(p.requests) + 1
	p.requests = append(p.requests, req)
	p.mu.Unlock()
	return p.streamFn(ctx, call, req)
}

func (p *scriptedStopProvider) lastRequest() llm.CompletionRequest {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.requests[len(p.requests)-1]
}

func reqContainsText(req llm.CompletionRequest, needle string) bool {
	raw, _ := json.Marshal(req.Messages)
	return strings.Contains(string(raw), needle)
}

func TestMainAgentStopPreservesHistoryAcrossAllAbortStages(t *testing.T) {
	cases := []struct {
		name      string
		abortMode string // "before_token" | "unsigned_thinking" | "partial_text" | "mid_tool"
	}{
		{name: "aborted_before_first_token", abortMode: "before_token"},
		{name: "aborted_during_unsigned_thinking", abortMode: "unsigned_thinking"},
		{name: "aborted_after_partial_text", abortMode: "partial_text"},
		{name: "aborted_mid_tool", abortMode: "mid_tool"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			tx := transcript.NewStore(filepath.Join(dir, "transcripts"))

			var cancelTurn2 context.CancelCauseFunc
			prov := &scriptedStopProvider{}
			prov.streamFn = func(ctx context.Context, call int, req llm.CompletionRequest) iter.Seq2[llm.StreamEvent, error] {
				return func(yield func(llm.StreamEvent, error) bool) {
					switch call {
					case 1:
						yield(llm.StreamEvent{Type: llm.SETextDelta, Text: "FIRST_REPLY_TOKEN"}, nil)
						yield(llm.StreamEvent{Type: llm.SEMessageDelta, StopReason: "end_turn"}, nil)
						yield(llm.StreamEvent{Type: llm.SEMessageStop}, nil)
					case 2:
						switch tc.abortMode {
						case "before_token":
							cancelTurn2(AbortChatStoppedByUser)
							yield(llm.StreamEvent{}, ctx.Err())
						case "unsigned_thinking":
							yield(llm.StreamEvent{Type: llm.SEThinkingDelta, Text: "UNFINISHED_UNSIGNED_THINKING"}, nil)
							cancelTurn2(AbortChatStoppedByUser)
							yield(llm.StreamEvent{}, ctx.Err())
						case "partial_text":
							yield(llm.StreamEvent{Type: llm.SETextDelta, Text: "PARTIAL_ANSWER_BEFORE_STOP"}, nil)
							cancelTurn2(AbortChatStoppedByUser)
							yield(llm.StreamEvent{}, ctx.Err())
						case "mid_tool":
							yield(llm.StreamEvent{Type: llm.SEToolUseStart, ToolID: "bash_slow", ToolName: "Bash"}, nil)
							yield(llm.StreamEvent{Type: llm.SEToolInputJSON, ToolID: "bash_slow", Text: `{"command":"sleep 5"}`}, nil)
							yield(llm.StreamEvent{Type: llm.SEMessageDelta, StopReason: "tool_use"}, nil)
							// Cancel right as the tool starts executing.
							go func() {
								cancelTurn2(AbortChatStoppedByUser)
							}()
							yield(llm.StreamEvent{Type: llm.SEMessageStop}, nil)
						}
					case 3:
						yield(llm.StreamEvent{Type: llm.SETextDelta, Text: "THIRD_REPLY_OK"}, nil)
						yield(llm.StreamEvent{Type: llm.SEMessageDelta, StopReason: "end_turn"}, nil)
						yield(llm.StreamEvent{Type: llm.SEMessageStop}, nil)
					default:
						yield(llm.StreamEvent{}, errors.New("unexpected model call"))
					}
				}
			}

			ma := NewMainAgent(prov, "synthetic", dir, tx, 0, 0)

			// Turn 1: normal conversation turn.
			reply1, err := ma.Chat(t.Context(), 1, 0, nil, nil, "test goal", "TURN1_USER_PROMPT", nil, nil, nil, nil, nil)
			if err != nil || reply1 != "FIRST_REPLY_TOKEN" {
				t.Fatalf("turn 1: reply=%q err=%v", reply1, err)
			}

			// Turn 2: aborted by user stop button.
			ctx2, cancel2 := context.WithCancelCause(t.Context())
			cancelTurn2 = cancel2
			defer cancel2(nil)
			_, _ = ma.Chat(ctx2, 1, 0, nil, nil, "test goal", "TURN2_ABORTED_PROMPT", nil, nil, nil, nil, nil)

			// Turn 3: follow-up turn must include full history from Turn 1 and Turn 2.
			reply3, err := ma.Chat(t.Context(), 1, 0, nil, nil, "test goal", "TURN3_FOLLOWUP_PROMPT", nil, nil, nil, nil, nil)
			if err != nil || reply3 != "THIRD_REPLY_OK" {
				t.Fatalf("turn 3: reply=%q err=%v", reply3, err)
			}

			req3 := prov.lastRequest()
			for _, want := range []string{"TURN1_USER_PROMPT", "FIRST_REPLY_TOKEN", "TURN2_ABORTED_PROMPT", "TURN3_FOLLOWUP_PROMPT"} {
				if !reqContainsText(req3, want) {
					raw, _ := json.Marshal(req3.Messages)
					t.Fatalf("turn 3 request missing %q; messages=%s", want, raw)
				}
			}
			if tc.abortMode == "partial_text" && !reqContainsText(req3, "PARTIAL_ANSWER_BEFORE_STOP") {
				t.Fatalf("turn 3 lost partial text from stopped turn 2")
			}
			if tc.abortMode == "unsigned_thinking" && reqContainsText(req3, "UNFINISHED_UNSIGNED_THINKING") {
				t.Fatalf("unsigned thinking leaked into turn 3 replay")
			}
			// Verify no consecutive non-system user messages at the tail (Turn 2 must
			// have an assistant turn before Turn 3 user prompt).
			// Skip req3.Messages[0] which is the SDK's <system-reminder>.
			conv := req3.Messages[1:]
			if len(conv) < 5 {
				t.Fatalf("expected >=5 conversation messages, got %d: %+v", len(conv), conv)
			}
			last := conv[len(conv)-1]
			prev := conv[len(conv)-2]
			if last.Role != llm.RoleUser || prev.Role != llm.RoleAssistant {
				t.Fatalf("expected Assistant right before Turn 3 User; got prev=%s last=%s", prev.Role, last.Role)
			}
		})
	}
}

func TestMainAgentStopBeforePromptPreservesUserMessageAndEmitsResult(t *testing.T) {
	dir := t.TempDir()
	tx := transcript.NewStore(filepath.Join(dir, "transcripts"))

	origPrepare := PrepareExecution
	t.Cleanup(func() { PrepareExecution = origPrepare })

	ctx2, cancel2 := context.WithCancelCause(t.Context())
	defer cancel2(nil)

	blockTurn2 := true
	PrepareExecution = func(ctx context.Context, _ string, _ RunInfo, _ string) (context.Context, actool.ExecutionRuntime, func(), error) {
		if blockTurn2 {
			blockTurn2 = false
			cancel2(AbortChatStoppedByUser)
			return nil, nil, nil, ctx.Err()
		}
		return ctx, nil, func() {}, nil
	}

	prov := &scriptedStopProvider{
		streamFn: func(_ context.Context, _ int, _ llm.CompletionRequest) iter.Seq2[llm.StreamEvent, error] {
			return func(yield func(llm.StreamEvent, error) bool) {
				yield(llm.StreamEvent{Type: llm.SETextDelta, Text: "FOLLOWUP_OK"}, nil)
				yield(llm.StreamEvent{Type: llm.SEMessageDelta, StopReason: "end_turn"}, nil)
				yield(llm.StreamEvent{Type: llm.SEMessageStop}, nil)
			}
		},
	}

	ma := NewMainAgent(prov, "synthetic", dir, tx, 0, 0)
	var emitted []db.Activity
	_, err := ma.Chat(ctx2, 1, 0, nil, nil, "goal", "PRE_PROMPT_ABORTED_MSG", func(a db.Activity) {
		emitted = append(emitted, a)
	}, nil, nil, nil, nil)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected canceled err, got %v", err)
	}
	if len(emitted) == 0 || emitted[len(emitted)-1].Kind != "result" {
		t.Fatalf("expected terminal result activity on pre-prompt abort, got %+v", emitted)
	}

	reply, err := ma.Chat(t.Context(), 1, 0, nil, nil, "goal", "NEXT_MSG_AFTER_STARTUP_STOP", nil, nil, nil, nil, nil)
	if err != nil || reply != "FOLLOWUP_OK" {
		t.Fatalf("followup chat: reply=%q err=%v", reply, err)
	}
	req := prov.lastRequest()
	if !reqContainsText(req, "PRE_PROMPT_ABORTED_MSG") || !reqContainsText(req, "NEXT_MSG_AFTER_STARTUP_STOP") {
		raw, _ := json.Marshal(req.Messages)
		t.Fatalf("followup missing pre-prompt aborted message: %s", raw)
	}
}

func TestCorruptTranscriptQuarantinedAndActivityFallbackRecoversHistory(t *testing.T) {
	dir := t.TempDir()
	tx := transcript.NewStore(filepath.Join(dir, "transcripts"))
	sessionID := "exp0-main"
	path := tx.MainPath(sessionID)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(`{"type":"message","message":{"role":"user","content":[{"type":"text","text":"old"}]}}`+"\n{corrupt-half-written-line"), 0o644); err != nil {
		t.Fatal(err)
	}

	prov := &scriptedStopProvider{
		streamFn: func(_ context.Context, _ int, _ llm.CompletionRequest) iter.Seq2[llm.StreamEvent, error] {
			return func(yield func(llm.StreamEvent, error) bool) {
				yield(llm.StreamEvent{Type: llm.SETextDelta, Text: "RECOVERED_OK"}, nil)
				yield(llm.StreamEvent{Type: llm.SEMessageDelta, StopReason: "end_turn"}, nil)
				yield(llm.StreamEvent{Type: llm.SEMessageStop}, nil)
			}
		},
	}
	ma := NewMainAgent(prov, "synthetic", dir, tx, 0, 0)
	if _, err := ma.Chat(t.Context(), 1, 0, nil, nil, "goal", "FRESH_TURN_AFTER_CORRUPT", nil, nil, nil, nil, nil); err != nil {
		t.Fatalf("chat after corrupt transcript failed: %v", err)
	}
	// Corrupt file must have been quarantined and replaced with a clean readable JSONL.
	entries, err := os.ReadDir(filepath.Dir(path))
	if err != nil {
		t.Fatal(err)
	}
	foundBackup := false
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), "exp0-main.jsonl.corrupt-") {
			foundBackup = true
		}
	}
	if !foundBackup {
		t.Fatalf("expected quarantined backup of corrupt transcript, entries=%+v", entries)
	}
	if _, err := tx.Load(path); err != nil {
		t.Fatalf("new transcript should be clean and loadable, got: %v", err)
	}

	// Verify DB activity fallback reconstruction (excluding the just-emitted current user turn).
	rows := []db.Activity{
		{ID: 1, Kind: "user", Summary: "第一问", Detail: "第一问：检查 8080 端口"},
		{ID: 2, Kind: "tool_use", Summary: "graph_overview {}"},
		{ID: 3, Kind: "result", Summary: "已检查 8080", Detail: "8080 端口运行 Spring Boot"},
		{ID: 4, Kind: "user", Summary: "第二问", Detail: `{"text":"继续查 actuator","attachments":[{"name":"req.txt","path":"uploads/req.txt"}]}`},
		{ID: 5, Kind: "result", Summary: "（运行被中断：用户停止了本轮对话）"},
		{ID: 6, Kind: "user", Summary: "第三问", Detail: "第三问：改查 9090"},
	}
	recovered := reconstructHistoryFromActivities(rows, nil, "第三问：改查 9090")
	if len(recovered) != 4 {
		t.Fatalf("recovered=%d messages, want 4 (2 completed/aborted pairs, current turn dropped): %+v", len(recovered), recovered)
	}
	if recovered[0].Role != llm.RoleUser || !strings.Contains(recovered[0].Text(), "检查 8080 端口") {
		t.Fatalf("recovered[0]=%+v", recovered[0])
	}
	if recovered[1].Role != llm.RoleAssistant || !strings.Contains(recovered[1].Text(), "Spring Boot") {
		t.Fatalf("recovered[1]=%+v", recovered[1])
	}
	if recovered[2].Role != llm.RoleUser || !strings.Contains(recovered[2].Text(), "继续查 actuator") || !strings.Contains(recovered[2].Text(), "uploads/req.txt") {
		t.Fatalf("recovered[2]=%+v", recovered[2])
	}
	if recovered[3].Role != llm.RoleAssistant || !strings.Contains(recovered[3].Text(), "用户停止了本轮对话") {
		t.Fatalf("recovered[3]=%+v", recovered[3])
	}
}
