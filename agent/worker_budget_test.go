package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/RC-CHN/ARTEX/db"
	"github.com/RC-CHN/ARTEX/norma/harness"
	"github.com/RC-CHN/ARTEX/norma/llm"
	actool "github.com/RC-CHN/ARTEX/norma/tool"
	"github.com/RC-CHN/ARTEX/norma/transcript"
)

func TestWorkerBudget150And10Dogfood(t *testing.T) {
	d := testDB(t)
	defer d.Close()
	task, err := d.CreateTaskWithOptions("synthetic 150+10", "synthetic", db.TaskCreateOptions{})
	if err != nil {
		t.Fatal(err)
	}
	ts := d.Exploration(task.ExplorationID)
	id, err := ts.AddIntent(map[string]any{"summary": "synthetic bounded fixture"}, 1, nil, "test")
	if err != nil {
		t.Fatal(err)
	}
	intent, err := ts.GetNode(id)
	if err != nil {
		t.Fatal(err)
	}
	calls, executed := 0, 0
	settleNotice, finalNotice := false, false
	p := consultationProvider{complete: func(_ context.Context, r llm.CompletionRequest) (llm.Message, string, llm.Usage, error) {
		calls++
		raw, _ := json.Marshal(r.Messages)
		settleNotice = settleNotice || strings.Contains(string(raw), "Worker 预算已到")
		finalNotice = finalNotice || strings.Contains(string(raw), "这是最后一轮")
		if calls == 160 {
			return consultationText("Synthetic work saved; no external deployment remains; original scope incomplete.")
		}
		return consultationCall("SyntheticCheckpoint", fmt.Sprint(calls), map[string]any{})
	}}
	probe := actool.Build(actool.Spec{Name: "SyntheticCheckpoint", Schema: obj(map[string]any{}), Run: func(context.Context, json.RawMessage, *actool.ToolContext) (actool.Result, error) {
		executed++
		return actool.Text("synthetic checkpoint saved"), nil
	}})
	dir := t.TempDir()
	w := NewWorker(p, "synthetic", dir, transcript.NewStore(filepath.Join(dir, "transcripts")), 0, 150, probe)
	reason, _, err := w.Execute(t.Context(), "worker", task.ID, nil, ts, intent, nil, nil, nil, nil)
	if err != nil || reason != harness.ReasonMaxTurns || calls != 160 || executed != 159 || !settleNotice || !finalNotice {
		t.Fatalf("150+10: reason=%s calls=%d executed=%d notices=%v/%v err=%v", reason, calls, executed, settleNotice, finalNotice, err)
	}
	reason, _, err = w.Execute(t.Context(), "worker", task.ID, nil, ts, intent, nil, nil, nil, nil)
	if err != nil || reason != harness.ReasonMaxTurns || calls != 160 {
		t.Fatalf("resume bypass: %s calls=%d err=%v", reason, calls, err)
	}
	toolset := NewToolSet(ts, "mainagent")
	mainctx := WithRunInfo(t.Context(), RunInfo{AgentKey: "mainagent", TaskID: task.ID, ExplorationID: task.ExplorationID})
	workerctx := WithRunInfo(t.Context(), RunInfo{AgentKey: "worker", TaskID: task.ID, IntentID: id})
	var log []map[string]any
	call := func(ctx context.Context, tool actool.CoreTool, in any, wantError bool) map[string]any {
		t.Helper()
		raw, _ := json.Marshal(in)
		result, e := tool.Call(ctx, raw, nil)
		if e != nil || result.IsError != wantError {
			t.Fatalf("%s: %s %v", tool.Name(), result.Flatten(), e)
		}
		var out map[string]any
		if e = json.Unmarshal([]byte(result.Flatten()), &out); e != nil {
			t.Fatal(e)
		}
		log = append(log, map[string]any{"tool": tool.Name(), "input": json.RawMessage(raw), "output": out})
		return out
	}
	b := call(workerctx, toolset.getWorkerBudget(), map[string]any{}, false)
	in := map[string]any{"intent_id": id, "expected_revision": b["revision"], "request_id": "explicit-extra", "additional_turns": 3, "additional_wrapup_turns": 2, "reason": "synthetic new evidence"}
	call(workerctx, toolset.grantWorkerBudget(), in, true)
	call(mainctx, toolset.grantWorkerBudget(), in, false)
	call(mainctx, toolset.grantWorkerBudget(), in, false)
	reason, _, err = w.Execute(t.Context(), "worker", task.ID, nil, ts, intent, nil, nil, nil, nil)
	if err != nil || reason != harness.ReasonMaxTurns || calls != 165 {
		t.Fatalf("grant did not bound resume: reason=%s calls=%d err=%v", reason, calls, err)
	}
	if output := os.Getenv("ARTEX_DOGFOOD_OUTPUT"); output != "" {
		if err = os.MkdirAll(output, 0700); err != nil {
			t.Fatal(err)
		}
		raw, _ := json.MarshalIndent(log, "", "  ")
		if err = os.WriteFile(filepath.Join(output, "worker-budget.json"), raw, 0600); err != nil {
			t.Fatal(err)
		}
	}
}

func TestWorkerTaskSoftBudgetDogfood(t *testing.T) {
	d := testDB(t)
	defer d.Close()
	if err := d.EnsureLLMUsageTable(); err != nil {
		t.Fatal(err)
	}
	task, err := d.CreateTaskWithOptions("synthetic cumulative threshold", "synthetic", db.TaskCreateOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = d.SetTaskTokenBudget(t.Context(), task.ID, 1000, 1); err != nil {
		t.Fatal(err)
	}
	if err = d.InsertLLMUsage(&db.LLMUsage{TaskID: fmt.Sprint(task.ID), InputTokens: 800, Worker: "main", Status: "ok"}); err != nil {
		t.Fatal(err)
	}
	ts := d.Exploration(task.ExplorationID)
	id, err := ts.AddIntent(map[string]any{"summary": "synthetic"}, 1, nil, "test")
	if err != nil {
		t.Fatal(err)
	}
	intent, err := ts.GetNode(id)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	bashMarker := filepath.Join(dir, "bash-must-not-run.txt")
	calls, effects := 0, 0
	var firstTools []llm.ToolSchema
	p := consultationProvider{complete: func(_ context.Context, r llm.CompletionRequest) (llm.Message, string, llm.Usage, error) {
		calls++
		raw, _ := json.Marshal(r.Messages)
		switch calls {
		case 1:
			firstTools = append([]llm.ToolSchema(nil), r.Tools...)
			if !strings.Contains(string(raw), "任务累计预算提醒") {
				t.Fatal("missing advance warning")
			}
			if err := d.InsertLLMUsage(&db.LLMUsage{TaskID: fmt.Sprint(task.ID), InputTokens: 100, OutputTokens: 100, Worker: "worker", Status: "ok"}); err != nil {
				t.Fatal(err)
			}
			return consultationCall("SyntheticCheckpoint", "1", map[string]any{})
		case 2:
			if !strings.Contains(string(raw), "任务累计软预算已到") {
				t.Fatal("no bounded wrapup", calls, string(raw))
			}
			// Prompt-cache prefix preservation keeps tool schemas byte-identical
			// across normal and settlement turns while blocking disabled tools at
			// execution time.
			if !reflect.DeepEqual(firstTools, r.Tools) {
				t.Fatalf("settlement mutated req.Tools:\nwant %+v\ngot  %+v", firstTools, r.Tools)
			}
			return consultationCall("Bash", "2", map[string]any{"command": "echo ran > " + bashMarker})
		case 3:
			if !strings.Contains(string(raw), "settlement_tool_disabled") {
				t.Fatalf("Bash was not rejected at execution during settlement: %s", string(raw))
			}
			return consultationText("Synthetic checkpoint recorded; threshold reached, remaining scope incomplete.")
		default:
			t.Fatalf("unexpected call %d: %s", calls, string(raw))
			return llm.Message{}, "", llm.Usage{}, nil
		}
	}}
	probe := actool.Build(actool.Spec{Name: "SyntheticCheckpoint", Schema: obj(map[string]any{}), Run: func(context.Context, json.RawMessage, *actool.ToolContext) (actool.Result, error) {
		effects++
		return actool.Text("saved synthetic checkpoint"), nil
	}})
	w := NewWorker(p, "synthetic", dir, transcript.NewStore(filepath.Join(dir, "transcripts")), 0, 150, probe)
	reason, _, err := w.Execute(t.Context(), "worker", task.ID, nil, ts, intent, nil, nil, nil, nil)
	if err != nil || reason != harness.ReasonMaxTurns || calls != 3 || effects != 1 {
		t.Fatal(reason, calls, effects, err)
	}
	if _, statErr := os.Stat(bashMarker); !os.IsNotExist(statErr) {
		t.Fatalf("Bash executed during settlement (marker stat err=%v)", statErr)
	}
}
