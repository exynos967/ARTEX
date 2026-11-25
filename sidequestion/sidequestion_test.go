package sidequestion

import (
	"context"
	"encoding/json"
	"errors"
	"iter"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/RC-CHN/ARTEX/llmpool"
	"github.com/RC-CHN/ARTEX/norma/harness"
	"github.com/RC-CHN/ARTEX/norma/llm"
	"github.com/RC-CHN/ARTEX/norma/transcript"
)

type fakeProvider struct {
	stream   func(context.Context, llm.CompletionRequest) iter.Seq2[llm.StreamEvent, error]
	complete func(context.Context, llm.CompletionRequest) (llm.Message, string, llm.Usage, error)
}

func (p fakeProvider) Stream(ctx context.Context, r llm.CompletionRequest) iter.Seq2[llm.StreamEvent, error] {
	return p.stream(ctx, r)
}
func (p fakeProvider) Complete(ctx context.Context, r llm.CompletionRequest) (llm.Message, string, llm.Usage, error) {
	return p.complete(ctx, r)
}
func assistant(text string) llm.Message {
	return llm.Message{Role: llm.RoleAssistant, Content: []llm.ContentBlock{llm.TextBlock(text)}}
}
func fixture() llm.CompletionRequest {
	temp := 0.3
	return llm.CompletionRequest{System: []string{"system"}, Temperature: &temp, MaxTokens: 128, Stop: []string{"END"}, Messages: []llm.Message{
		llm.UserText("<system-reminder>date</system-reminder>"), llm.UserText("read asset"),
		{Role: llm.RoleAssistant, Content: []llm.ContentBlock{{Type: llm.BlockThinking, Thinking: "reason", Signature: "signed"}, {Type: llm.BlockToolUse, ID: "tool-1", Name: "read", Input: json.RawMessage(`{"url":"fixture"}`)}}},
		{Role: llm.RoleUser, Content: []llm.ContentBlock{llm.ToolResultText("tool-1", "verified asset", false)}},
	}, Tools: []llm.ToolSchema{{Name: "read", InputSchema: map[string]any{"properties": map[string]any{"url": map[string]any{"type": "string"}}}}}}
}

func TestCheckpointDeepCopyAndBoundaries(t *testing.T) {
	var snapshots []Snapshot
	p := Bind(fakeProvider{complete: func(context.Context, llm.CompletionRequest) (llm.Message, string, llm.Usage, error) {
		return assistant("finished"), "end_turn", llm.Usage{}, nil
	}}, Model{Model: "actual"})
	ctx, deps := Attach(WithPublisher(t.Context(), func(s Snapshot) { snapshots = append(snapshots, s) }), Parent{ConversationID: 1}, harness.QueryDeps{}, p)
	req := fixture()
	if _, _, _, err := deps.CallModelSync(ctx, req); err != nil {
		t.Fatal(err)
	}
	if len(snapshots) != 2 || snapshots[1].Request.Messages[len(snapshots[1].Request.Messages)-1].Text() != "finished" {
		t.Fatalf("checkpoints: %+v", snapshots)
	}
	before, _ := json.Marshal(snapshots)
	req.System[0] = "mutated"
	*req.Temperature = 2
	req.Stop[0] = "bad"
	req.Messages[2].Content[1].Input[2] = 'X'
	req.Messages[3].Content[0].Content[0].Text = "mutated"
	req.Tools[0].InputSchema["properties"].(map[string]any)["url"].(map[string]any)["type"] = "number"
	after, _ := json.Marshal(snapshots)
	if string(before) != string(after) {
		t.Fatal("published checkpoint aliases structured input")
	}
	// Auxiliary/compaction calls lack the model-attempt marker.
	_, _, _, _ = p.Complete(ctx, llm.CompletionRequest{Messages: []llm.Message{llm.UserText("summary request")}})
	if len(snapshots) != 2 {
		t.Fatal("auxiliary completion replaced snapshot")
	}
	terminal := fixture().Messages[1:]
	terminal = append(terminal, assistant("terminal answer"))
	Finish(ctx, terminal)
	last := snapshots[len(snapshots)-1]
	if last.Request.Messages[0].Text() != "<system-reminder>date</system-reminder>" || len(last.Request.Messages) != 5 {
		t.Fatalf("terminal/reminder duplication: %+v", last.Request.Messages)
	}
	if !strings.Contains(string(mustJSON(t, last)), "verified asset") {
		t.Fatal("terminal lost paired tool result")
	}
}

func mustJSON(t *testing.T, v any) []byte {
	t.Helper()
	b, e := json.Marshal(v)
	if e != nil {
		t.Fatal(e)
	}
	return b
}

func TestSnapshotExcludesPartialStreamAndSelectsPoolMember(t *testing.T) {
	var snapshots []Snapshot
	failed := Bind(fakeProvider{stream: func(context.Context, llm.CompletionRequest) iter.Seq2[llm.StreamEvent, error] {
		return func(y func(llm.StreamEvent, error) bool) { y(llm.StreamEvent{}, errors.New("HTTP 503 unavailable")) }
	}}, Model{Model: "failed"})
	good := Bind(fakeProvider{stream: func(context.Context, llm.CompletionRequest) iter.Seq2[llm.StreamEvent, error] {
		return func(y func(llm.StreamEvent, error) bool) {
			if !y(llm.StreamEvent{Type: llm.SETextDelta, Text: "complete"}, nil) {
				return
			}
			y(llm.StreamEvent{Type: llm.SEMessageStop}, nil)
		}
	}}, Model{Model: "selected"})
	pool := llmpool.New([]*llmpool.Member{{ID: 1, Name: "failed", Rank: 2, Prov: failed}, {ID: 2, Name: "selected", Rank: 1, Prov: good}}, nil)
	ctx, deps := Attach(WithPublisher(t.Context(), func(s Snapshot) { snapshots = append(snapshots, s) }), Parent{ConversationID: 2}, harness.QueryDeps{}, pool)
	for ev, err := range deps.CallModel(ctx, fixture()) {
		if err != nil {
			t.Fatal(err)
		}
		if ev.Type == llm.SETextDelta && strings.Contains(string(mustJSON(t, snapshots[len(snapshots)-1])), "complete") {
			t.Fatal("partial reply published")
		}
	}
	if last := snapshots[len(snapshots)-1]; last.Model.Model != "selected" || last.Request.Messages[len(last.Request.Messages)-1].Text() != "complete" {
		t.Fatalf("wrong selected model/checkpoint: %+v", last)
	}
	count := len(snapshots)
	for range deps.CallModel(ctx, fixture()) {
		break
	}
	if len(snapshots) != count+2 || len(snapshots[len(snapshots)-1].Request.Messages) != len(fixture().Messages) {
		t.Fatal("consumer stop published partial reply")
	}
}

func TestBuildRequestCompactionToolPairingAndBudget(t *testing.T) {
	s := Snapshot{Request: fixture(), Model: Model{WindowTokens: 100000}}
	s.Request.Messages = append(s.Request.Messages, llm.BoundaryMessage(llm.BoundaryMeta{Trigger: "auto"}), llm.UserText("compressed summary"), s.Request.Messages[3])
	history := []Exchange{}
	for i := 0; i < 25; i++ {
		history = append(history, Exchange{Question: strings.Repeat("q", 100), Answer: "answer", Status: "completed"})
	}
	r, err := BuildRequest(s, history, "current question")
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Messages) != 42 || r.Messages[0].Text() != "compressed summary" {
		t.Fatalf("history cap/compaction: %d %+v", len(r.Messages), r.Messages[0])
	}
	for _, m := range r.Messages {
		for _, b := range m.Content {
			if b.Type == llm.BlockToolResult {
				t.Fatal("orphan tool result survived")
			}
		}
	}
	s.Model.WindowTokens = 1000
	r, err = BuildRequest(s, history, "current question")
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Messages) >= 42 || len(r.Messages) < 2 {
		t.Fatal("budget did not reduce side history")
	}
	s.Model.WindowTokens = 10
	if _, err = BuildRequest(s, nil, "question"); err == nil {
		t.Fatal("oversized base accepted")
	}
}

func TestServiceNoToolsAndUsageOnFailure(t *testing.T) {
	for _, streaming := range []bool{false, true} {
		t.Run(map[bool]string{true: "stream", false: "atomic"}[streaming], func(t *testing.T) {
			calls := 0
			p := fakeProvider{complete: func(context.Context, llm.CompletionRequest) (llm.Message, string, llm.Usage, error) {
				calls++
				return llm.Message{Role: llm.RoleAssistant, Content: []llm.ContentBlock{{Type: llm.BlockToolUse, ID: "new", Name: "run_shell", Input: json.RawMessage(`{"command":"touch forbidden"}`)}}}, "tool_use", llm.Usage{InputTokens: 11}, nil
			}, stream: func(context.Context, llm.CompletionRequest) iter.Seq2[llm.StreamEvent, error] {
				return func(y func(llm.StreamEvent, error) bool) {
					calls++
					y(llm.StreamEvent{Type: llm.SEMessageStart, Usage: llm.Usage{InputTokens: 11}}, nil)
					y(llm.StreamEvent{Type: llm.SEToolUseStart, ToolID: "new", ToolName: "run_shell"}, nil)
					y(llm.StreamEvent{Type: llm.SEMessageStop}, nil)
				}
			}}
			before := fixture()
			req, _ := CloneRequest(before)
			out, err := (SideQuestionService{p}).Answer(t.Context(), req, streaming, nil)
			if err != nil || calls != 1 || !out.ToolUse || !strings.Contains(out.Text, "不能执行工具") || out.Usage.InputTokens != 11 {
				t.Fatalf("answer %+v calls=%d err=%v", out, calls, err)
			}
			if !reflect.DeepEqual(before, req) {
				t.Fatal("service mutated main context")
			}
		})
	}
	p := fakeProvider{stream: func(context.Context, llm.CompletionRequest) iter.Seq2[llm.StreamEvent, error] {
		return func(y func(llm.StreamEvent, error) bool) {
			y(llm.StreamEvent{Type: llm.SEMessageStart, Usage: llm.Usage{InputTokens: 12}}, nil)
			y(llm.StreamEvent{Type: llm.SETextDelta, Text: "partial"}, nil)
			y(llm.StreamEvent{}, errors.New("broken"))
		}
	}}
	out, err := (SideQuestionService{p}).Answer(t.Context(), fixture(), true, nil)
	if err == nil || out.Text != "partial" || out.Usage.InputTokens != 12 {
		t.Fatalf("lost failure usage/partial: %+v %v", out, err)
	}
}

func TestMainSideConcurrencyAndIndependentCancellation(t *testing.T) {
	for _, cancelMain := range []bool{false, true} {
		t.Run(map[bool]string{true: "stop-main", false: "stop-side"}[cancelMain], func(t *testing.T) {
			started := make(chan struct{}, 2)
			p := fakeProvider{stream: func(ctx context.Context, _ llm.CompletionRequest) iter.Seq2[llm.StreamEvent, error] {
				return func(y func(llm.StreamEvent, error) bool) {
					started <- struct{}{}
					y(llm.StreamEvent{Type: llm.SEMessageStart, Usage: llm.Usage{InputTokens: 7}}, nil)
					<-ctx.Done()
					y(llm.StreamEvent{}, ctx.Err())
				}
			}}
			mainCtx, stopMain := context.WithCancel(t.Context())
			defer stopMain()
			sideCtx, stopSide := context.WithCancel(t.Context())
			defer stopSide()
			var mu sync.Mutex
			bound := Bind(p, Model{Model: "blocking"})
			mainCtx, deps := Attach(WithPublisher(mainCtx, func(Snapshot) { mu.Lock(); mu.Unlock() }), Parent{ConversationID: 3}, harness.QueryDeps{}, bound)
			mainDone, sideDone := make(chan struct{}), make(chan Answer, 1)
			go func() {
				defer close(mainDone)
				for range deps.CallModel(mainCtx, fixture()) {
				}
			}()
			go func() { a, _ := (SideQuestionService{bound}).Answer(sideCtx, fixture(), true, nil); sideDone <- a }()
			for i := 0; i < 2; i++ {
				select {
				case <-started:
				case <-time.After(time.Second):
					t.Fatal("main and side did not execute concurrently")
				}
			}
			if cancelMain {
				stopMain()
				select {
				case <-mainDone:
				case <-time.After(time.Second):
					t.Fatal("main cancellation stuck")
				}
				select {
				case <-sideDone:
					t.Fatal("main cancellation stopped side")
				default:
				}
				stopSide()
			} else {
				stopSide()
				select {
				case a := <-sideDone:
					if a.Usage.InputTokens != 7 {
						t.Fatal("cancelled usage lost")
					}
				case <-time.After(time.Second):
					t.Fatal("side cancellation stuck")
				}
				select {
				case <-mainDone:
					t.Fatal("side cancellation stopped main")
				default:
				}
				stopMain()
			}
		})
	}
}

func TestCloneRequestStructuralDeepCopyAndEquality(t *testing.T) {
	temp := 0.7
	orig := llm.CompletionRequest{
		System:          []string{"static", "dynamic"},
		DynamicBoundary: 1,
		MaxTokens:       4096,
		Temperature:     &temp,
		Stop:            []string{"HALT"},
		Thinking:        "enabled",
		PromptCacheKey:  "exp7-main",
		Messages: []llm.Message{
			llm.UserText("hello"),
			{Role: llm.RoleAssistant, Content: []llm.ContentBlock{
				{Type: llm.BlockThinking, Thinking: "plan", Signature: "sig-1"},
				{Type: llm.BlockToolUse, ID: "call-1", Name: "Read", Input: json.RawMessage(`{"path":"a.txt"}`)},
			}},
			{Role: llm.RoleUser, Content: []llm.ContentBlock{
				{Type: llm.BlockToolResult, ToolUseID: "call-1", IsError: false, Content: []llm.ContentBlock{
					llm.TextBlock("nested result"),
					{Type: llm.BlockToolResult, ToolUseID: "inner", Content: []llm.ContentBlock{llm.TextBlock("deep")}},
				}},
			}},
		},
		Tools: []llm.ToolSchema{
			{
				Name:        "Read",
				Description: "read file",
				RawInput:    true,
				InputSchema: map[string]any{
					"type":     "object",
					"required": []string{"path"},
					"items":    []any{map[string]any{"k": "v"}, []string{"x"}},
					"meta":     map[string]string{"owner": "core"},
					"empty":    []string{},
					"nilSlice": []string(nil),
					"maps":     []map[string]any{{"a": "b"}},
					"raw":      json.RawMessage(`{"x":1}`),
					"properties": map[string]any{
						"path": map[string]any{"type": "string"},
					},
				},
			},
		},
	}

	cloned, err := CloneRequest(orig)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(orig, cloned) {
		t.Fatalf("structural clone differs from original:\ngot:  %#v\nwant: %#v", cloned, orig)
	}

	before := mustJSON(t, cloned)
	orig.System[0] = "mutated-sys"
	orig.Stop[0] = "MUTATED"
	*orig.Temperature = 1.9
	orig.Messages[1].Content[1].Input[2] = 'Z'
	orig.Messages[2].Content[0].Content[0].Text = "mutated-nested"
	orig.Messages[2].Content[0].Content[1].Content[0].Text = "mutated-deep"
	orig.Tools[0].InputSchema["required"].([]string)[0] = "changed"
	orig.Tools[0].InputSchema["items"].([]any)[0].(map[string]any)["k"] = "changed"
	orig.Tools[0].InputSchema["items"].([]any)[1].([]string)[0] = "changed"
	orig.Tools[0].InputSchema["meta"].(map[string]string)["owner"] = "changed"
	orig.Tools[0].InputSchema["maps"].([]map[string]any)[0]["a"] = "changed"
	orig.Tools[0].InputSchema["raw"].(json.RawMessage)[2] = 'Y'
	orig.Tools[0].InputSchema["properties"].(map[string]any)["path"].(map[string]any)["type"] = "number"

	after := mustJSON(t, cloned)
	if string(before) != string(after) {
		t.Fatalf("CloneRequest aliased mutable state:\nbefore=%s\nafter=%s", before, after)
	}
	if cloned.Tools[0].InputSchema["meta"].(map[string]string)["owner"] != "core" {
		t.Fatal("map[string]string inside InputSchema was aliased")
	}
	if !cloned.Tools[0].RawInput || cloned.PromptCacheKey != "exp7-main" || cloned.DynamicBoundary != 1 {
		t.Fatalf("metadata lost on clone: %+v", cloned)
	}
}

func TestCaptureSessionIDAndPromptCacheKeyPropagation(t *testing.T) {
	t.Run("explicit-and-json-backcompat", func(t *testing.T) {
		var snaps []Snapshot
		p := Bind(fakeProvider{complete: func(context.Context, llm.CompletionRequest) (llm.Message, string, llm.Usage, error) {
			return assistant("ok"), "end_turn", llm.Usage{}, nil
		}}, Model{Model: "m"})
		ctx := WithSessionID(WithPublisher(t.Context(), func(s Snapshot) { snaps = append(snaps, s) }), "exp42-main-s2")
		ctx, deps := Attach(ctx, Parent{TaskID: 1, ExplorationID: 42}, harness.QueryDeps{}, p)
		if _, _, _, err := deps.CallModelSync(ctx, fixture()); err != nil {
			t.Fatal(err)
		}
		if len(snaps) != 2 || snaps[1].SessionID != "exp42-main-s2" {
			t.Fatalf("expected session_id captured, got %+v", snaps)
		}
		// Legacy JSON without session_id must still unmarshal cleanly.
		var legacy Snapshot
		if err := json.Unmarshal([]byte(`{"parent":{"conversation_id":9},"run_id":1,"version":1}`), &legacy); err != nil {
			t.Fatal(err)
		}
		if legacy.SessionID != "" || legacy.Parent.ConversationID != 9 {
			t.Fatalf("unexpected legacy decode: %+v", legacy)
		}
		// BuildRequest propagates SessionID into PromptCacheKey when unset.
		req, err := BuildRequest(snaps[1], nil, "status?")
		if err != nil {
			t.Fatal(err)
		}
		if req.PromptCacheKey != "exp42-main-s2" {
			t.Fatalf("PromptCacheKey=%q want exp42-main-s2", req.PromptCacheKey)
		}
	})

	t.Run("lazy-transcript-session-and-respond-ctx-fallback", func(t *testing.T) {
		var snaps []Snapshot
		p := Bind(fakeProvider{complete: func(context.Context, llm.CompletionRequest) (llm.Message, string, llm.Usage, error) {
			return assistant("ok"), "end_turn", llm.Usage{}, nil
		}}, Model{Model: "m"})
		ctx := WithPublisher(t.Context(), func(s Snapshot) { snaps = append(snaps, s) })
		ctx, deps := Attach(ctx, Parent{ConversationID: 88}, harness.QueryDeps{}, p)
		// Simulate agentcore attaching transcript.WithSessionID right before CallModelSync.
		callCtx := transcript.WithSessionID(ctx, "conv-88")
		if _, _, _, err := deps.CallModelSync(callCtx, fixture()); err != nil {
			t.Fatal(err)
		}
		if len(snaps) != 2 || snaps[1].SessionID != "conv-88" {
			t.Fatalf("lazy transcript session id not captured: %+v", snaps)
		}

		// When a legacy snapshot has empty SessionID, Respond falls back to ctx PromptCacheKey.
		var gotKey string
		svc := SideQuestionService{Provider: fakeProvider{complete: func(_ context.Context, r llm.CompletionRequest) (llm.Message, string, llm.Usage, error) {
			gotKey = r.PromptCacheKey
			return assistant("ans"), "end_turn", llm.Usage{}, nil
		}}}
		legacySnap := snaps[1]
		legacySnap.SessionID = ""
		_, _, err := svc.Respond(llm.WithPromptCacheKey(t.Context(), "conv-88"), legacySnap, "q", Replay{}, ContextOptions{}, nil)
		if err != nil {
			t.Fatal(err)
		}
		if gotKey != "conv-88" {
			t.Fatalf("Respond PromptCacheKey=%q want conv-88", gotKey)
		}
	})
}

func TestFinishPreservesNoaProjectedPrefix(t *testing.T) {
	noaPrefix := func() []llm.Message {
		return []llm.Message{
			llm.UserText("<system-reminder>date</system-reminder>"),
			llm.UserText("[Earlier context summary]\n\n<noa-archive block=\"b1\" tier=\"1\" range=\"m00001-m00004\" path=\"/tmp/b1.md\"/>\nSummary of earlier work."),
			llm.UserText("inspect target\n<noa-ref id=\"m00005\" tokens=\"12\"/>"),
		}
	}

	t.Run("end_turn_preserves_noa_prefix_verbatim", func(t *testing.T) {
		var snaps []Snapshot
		p := Bind(fakeProvider{complete: func(context.Context, llm.CompletionRequest) (llm.Message, string, llm.Usage, error) {
			return assistant("final answer"), "end_turn", llm.Usage{}, nil
		}}, Model{Model: "m"})
		ctx, deps := Attach(WithPublisher(t.Context(), func(s Snapshot) { snaps = append(snaps, s) }), Parent{ConversationID: 10}, harness.QueryDeps{}, p)
		sent := llm.CompletionRequest{System: []string{"sys"}, Messages: noaPrefix()}
		if _, _, _, err := deps.CallModelSync(ctx, sent); err != nil {
			t.Fatal(err)
		}
		// Terminal.Messages holds the raw uncompressed history (no <noa-archive> or <noa-ref>).
		rawTerminal := []llm.Message{
			llm.UserText("raw early turn 1"),
			assistant("raw early reply 1"),
			llm.UserText("inspect target"),
			assistant("final answer"),
		}
		Finish(ctx, rawTerminal)
		last := snaps[len(snaps)-1]
		if !last.Terminal {
			t.Fatal("Finish snapshot should set Terminal=true")
		}
		if len(last.Request.Messages) != 4 {
			t.Fatalf("expected 4 messages (3 noa prefix + 1 answer), got %d: %+v", len(last.Request.Messages), last.Request.Messages)
		}
		if !reflect.DeepEqual(last.Request.Messages[:3], noaPrefix()) {
			t.Fatalf("noa-projected prefix clobbered:\ngot:  %#v\nwant: %#v", last.Request.Messages[:3], noaPrefix())
		}
		if last.Request.Messages[3].Text() != "final answer" {
			t.Fatalf("missing final answer: %+v", last.Request.Messages[3])
		}
		if strings.Contains(string(mustJSON(t, last)), "raw early turn 1") {
			t.Fatal("raw uncompressed history resurrected into noa snapshot")
		}
	})

	t.Run("trailing_tool_call_and_result_appended_after_noa_prefix", func(t *testing.T) {
		var snaps []Snapshot
		toolCallMsg := llm.Message{
			Role: llm.RoleAssistant,
			Content: []llm.ContentBlock{
				{Type: llm.BlockThinking, Thinking: "check file", Signature: "sig-xyz"},
				{Type: llm.BlockToolUse, ID: "call-9", Name: "Read", Input: json.RawMessage(`{"file_path":"a.txt"}`)},
			},
		}
		p := Bind(fakeProvider{complete: func(context.Context, llm.CompletionRequest) (llm.Message, string, llm.Usage, error) {
			return toolCallMsg, "tool_use", llm.Usage{}, nil
		}}, Model{Model: "m"})
		ctx, deps := Attach(WithPublisher(t.Context(), func(s Snapshot) { snaps = append(snaps, s) }), Parent{ConversationID: 11}, harness.QueryDeps{}, p)
		sent := llm.CompletionRequest{System: []string{"sys"}, Messages: noaPrefix()}
		if _, _, _, err := deps.CallModelSync(ctx, sent); err != nil {
			t.Fatal(err)
		}
		toolResMsg := llm.Message{Role: llm.RoleUser, Content: []llm.ContentBlock{llm.ToolResultText("call-9", "file-secret-content", false)}}
		rawTerminal := []llm.Message{
			llm.UserText("raw early turn 1"),
			llm.UserText("inspect target"),
			toolCallMsg,
			toolResMsg,
		}
		Finish(ctx, rawTerminal)
		last := snaps[len(snaps)-1]
		if len(last.Request.Messages) != 5 {
			t.Fatalf("expected 5 messages (3 noa prefix + tool_use + tool_result), got %d: %+v", len(last.Request.Messages), last.Request.Messages)
		}
		if !reflect.DeepEqual(last.Request.Messages[:3], noaPrefix()) {
			t.Fatalf("noa-projected prefix clobbered: %+v", last.Request.Messages[:3])
		}
		if !reflect.DeepEqual(last.Request.Messages[3], toolCallMsg) {
			t.Fatalf("assistant tool_use message damaged: %+v", last.Request.Messages[3])
		}
		if !reflect.DeepEqual(last.Request.Messages[4], toolResMsg) {
			t.Fatalf("trailing tool_result lost: %+v", last.Request.Messages[4])
		}
	})

	t.Run("partial_tool_abort_preserves_noa_prefix_and_paired_call", func(t *testing.T) {
		var snaps []Snapshot
		dualToolMsg := llm.Message{
			Role: llm.RoleAssistant,
			Content: []llm.ContentBlock{
				{Type: llm.BlockToolUse, ID: "call-1", Name: "Read", Input: json.RawMessage(`{"p":"1"}`)},
				{Type: llm.BlockToolUse, ID: "call-2", Name: "Read", Input: json.RawMessage(`{"p":"2"}`)},
			},
		}
		p := Bind(fakeProvider{complete: func(context.Context, llm.CompletionRequest) (llm.Message, string, llm.Usage, error) {
			return dualToolMsg, "tool_use", llm.Usage{}, nil
		}}, Model{Model: "m"})
		ctx, deps := Attach(WithPublisher(t.Context(), func(s Snapshot) { snaps = append(snaps, s) }), Parent{ConversationID: 12}, harness.QueryDeps{}, p)
		// Even when all prior turns were folded into <noa-archive> only:
		compressedOnly := []llm.Message{
			llm.UserText("<system-reminder>date</system-reminder>"),
			llm.UserText("<noa-archive block=\"b2\" tier=\"2\" range=\"m00001-m00010\" path=\"/tmp/b2.md\"/>"),
		}
		if _, _, _, err := deps.CallModelSync(ctx, llm.CompletionRequest{Messages: compressedOnly}); err != nil {
			t.Fatal(err)
		}
		// Only call-1 finished before abort; call-2 has no tool_result.
		rawTerminal := []llm.Message{
			llm.UserText("raw old"),
			dualToolMsg,
			{Role: llm.RoleUser, Content: []llm.ContentBlock{llm.ToolResultText("call-1", "res-1", false)}},
		}
		Finish(ctx, rawTerminal)
		last := snaps[len(snaps)-1]
		if len(last.Request.Messages) != 4 {
			t.Fatalf("expected 4 messages, got %d: %+v", len(last.Request.Messages), last.Request.Messages)
		}
		if !reflect.DeepEqual(last.Request.Messages[:2], compressedOnly) {
			t.Fatalf("compressed prefix clobbered: %+v", last.Request.Messages[:2])
		}
		if uses := last.Request.Messages[2].ToolUses(); len(uses) != 1 || uses[0].ID != "call-1" {
			t.Fatalf("expected only paired call-1, got %+v", uses)
		}
	})

	t.Run("anchor_on_noa_truncated_tool_result", func(t *testing.T) {
		var snaps []Snapshot
		p := Bind(fakeProvider{complete: func(context.Context, llm.CompletionRequest) (llm.Message, string, llm.Usage, error) {
			return assistant("ignored"), "end_turn", llm.Usage{}, nil
		}}, Model{Model: "m"})
		ctx, deps := Attach(WithPublisher(t.Context(), func(s Snapshot) { snaps = append(snaps, s) }), Parent{ConversationID: 13}, harness.QueryDeps{}, p)
		sentPrefix := []llm.Message{
			llm.UserText("<system-reminder>date</system-reminder>"),
			{Role: llm.RoleAssistant, Content: []llm.ContentBlock{{Type: llm.BlockToolUse, ID: "call-8", Name: "Read", Input: json.RawMessage(`{}`)}}},
			{Role: llm.RoleUser, Content: []llm.ContentBlock{llm.ToolResultText("call-8", "[truncated]\n<noa-ref id=\"m00008\" tokens=\"5.0K\" src=\"Read\"/>", false)}},
		}
		if _, _, _, err := deps.CallModelSync(ctx, llm.CompletionRequest{Messages: sentPrefix}); err != nil {
			t.Fatal(err)
		}
		// Terminal carries the full untruncated tool_result plus a different assistant text.
		rawTerminal := []llm.Message{
			{Role: llm.RoleAssistant, Content: []llm.ContentBlock{{Type: llm.BlockToolUse, ID: "call-8", Name: "Read", Input: json.RawMessage(`{}`)}}},
			{Role: llm.RoleUser, Content: []llm.ContentBlock{llm.ToolResultText("call-8", "full huge untruncated content", false)}},
			assistant("final post-tool answer"),
		}
		Finish(ctx, rawTerminal)
		last := snaps[len(snaps)-1]
		if len(last.Request.Messages) != 4 {
			t.Fatalf("expected 4 messages, got %d: %+v", len(last.Request.Messages), last.Request.Messages)
		}
		if !reflect.DeepEqual(last.Request.Messages[:3], sentPrefix) {
			t.Fatalf("noa-truncated tool result clobbered: %+v", last.Request.Messages[:3])
		}
		if last.Request.Messages[3].Text() != "final post-tool answer" {
			t.Fatalf("trailing answer missing: %+v", last.Request.Messages[3])
		}
	})
}

// TestOpenAIResponsesStreamingWithSideQuestionAndBind verifies that the real
// openai-responses streaming adapter emits SEMessageStop so both
// SideQuestionService.Answer(..., streaming=true) and sidequestion.Bind capture
// complete turns cleanly.
func TestOpenAIResponsesStreamingWithSideQuestionAndBind(t *testing.T) {
	sseBody := strings.Join([]string{
		"event: response.created",
		`data: {"type":"response.created"}`,
		"",
		"event: response.output_text.delta",
		`data: {"type":"response.output_text.delta","delta":"hello "}`,
		"",
		"event: response.output_text.delta",
		`data: {"type":"response.output_text.delta","delta":"responses"}`,
		"",
		"event: response.completed",
		`data: {"type":"response.completed","response":{"status":"completed","usage":{"input_tokens":15,"output_tokens":4,"input_tokens_details":{"cached_tokens":5}}}}`,
		"",
	}, "\n")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("content-type", "text/event-stream")
		_, _ = w.Write([]byte(sseBody))
	}))
	defer srv.Close()

	prov, err := llm.NewProvider(llm.Config{
		Format:  llm.FormatOpenAIResponses,
		BaseURL: srv.URL,
		APIKey:  "k",
		Model:   "gpt-5",
	})
	if err != nil {
		t.Fatal(err)
	}

	// 1. SideQuestionService.Answer streaming mode must observe SEMessageStop and succeed.
	ans, err := (SideQuestionService{Provider: prov}).Answer(t.Context(), fixture(), true, nil)
	if err != nil {
		t.Fatalf("SideQuestionService.Answer(openai-responses stream) err: %v", err)
	}
	if ans.Text != "hello responses" || ans.Usage.InputTokens != 15 || ans.Usage.OutputTokens != 4 || ans.Usage.CacheReadTokens != 5 {
		t.Fatalf("unexpected answer: %+v", ans)
	}

	// 2. sidequestion.Bind streaming mode must save the completed response checkpoint.
	var snaps []Snapshot
	bound := Bind(prov, Model{Format: string(llm.FormatOpenAIResponses), Model: "gpt-5", Streaming: true})
	ctx, deps := Attach(WithPublisher(t.Context(), func(s Snapshot) { snaps = append(snaps, s) }), Parent{ConversationID: 77}, harness.QueryDeps{}, bound)
	for _, serr := range deps.CallModel(ctx, fixture()) {
		if serr != nil {
			t.Fatalf("bound stream err: %v", serr)
		}
	}
	if len(snaps) != 2 {
		t.Fatalf("snapshots=%d, want 2 (request + completed response)", len(snaps))
	}
	lastMsg := snaps[1].Request.Messages[len(snaps[1].Request.Messages)-1]
	if lastMsg.Role != llm.RoleAssistant || lastMsg.Text() != "hello responses" {
		t.Fatalf("captured response=%+v, want assistant \"hello responses\"", lastMsg)
	}
}
