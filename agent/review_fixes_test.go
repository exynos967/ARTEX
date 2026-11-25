package agent

import (
	"bytes"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/RC-CHN/ARTEX/norma/agentcore"
	"github.com/RC-CHN/ARTEX/norma/permission"
	"github.com/RC-CHN/ARTEX/norma/transcript"
)

func TestPlannerDeltaIncludesChangedColdDigestsScopeAndRelatedTasks(t *testing.T) {
	dir := t.TempDir()
	tx := transcript.NewStore(filepath.Join(dir, "transcripts"))
	prov := &recordingRequestProvider{}
	p := NewPlanner(prov, "test-model", dir, tx, 200000, 5)
	const expID int64 = 101

	opts := agentcore.Options{
		Provider:        prov,
		SystemPrompt:    []string{"planner static prompt"},
		DynamicBoundary: 1,
		PermissionMode:  permission.ModeBypass,
		MaxTurns:        5,
		Todos:           p.todoFor(expID),
		NonStreaming:    true,
	}

	round1 := map[string]any{
		"cold_digests":  []map[string]any{{"id": 50, "body": "initial digest"}},
		"related_tasks": []map[string]any{{"task_id": 1, "summary": "source v1"}},
		"coverage": map[string]any{
			"pct": 10.0, "tested": 1, "denominator": 10, "host_count": 1,
			"scope": []string{"a.example.com"},
		},
	}
	if _, err := p.runPlannerSession(t.Context(), expID, opts, DeferredInfo{}, "r1", "", round1, "", nil); err != nil {
		t.Fatalf("round 1: %v", err)
	}

	// Round 2: cold_digests, coverage.scope, and related_tasks all change -> delta must include them.
	round2 := map[string]any{
		"cold_digests":      []map[string]any{{"id": 51, "body": "new folded digest"}, {"id": 50, "body": "initial digest"}},
		"cold_digests_more": []int64{49},
		"related_tasks":     []map[string]any{{"task_id": 1, "summary": "source v2"}},
		"coverage": map[string]any{
			"pct": 30.0, "tested": 3, "denominator": 10, "host_count": 2,
			"scope": []string{"a.example.com", "b.example.com"},
		},
	}
	if _, err := p.runPlannerSession(t.Context(), expID, opts, DeferredInfo{}, "r2", "", round2, "", nil); err != nil {
		t.Fatalf("round 2: %v", err)
	}
	if len(prov.reqs) != 2 {
		t.Fatalf("expected 2 requests, got %d", len(prov.reqs))
	}
	delta2 := prov.reqs[1].Messages[len(prov.reqs[1].Messages)-1].Text()
	for _, want := range []string{"new folded digest", "cold_digests_more", "b.example.com", "source v2"} {
		if !strings.Contains(delta2, want) {
			t.Fatalf("round 2 delta missing changed field %q:\n%s", want, delta2)
		}
	}

	// Round 3: unchanged again -> delta stays compact and omits unchanged baseline/heavy fields.
	if _, err := p.runPlannerSession(t.Context(), expID, opts, DeferredInfo{}, "r3", "", round2, "", nil); err != nil {
		t.Fatalf("round 3: %v", err)
	}
	delta3 := prov.reqs[2].Messages[len(prov.reqs[2].Messages)-1].Text()
	for _, omitted := range []string{"new folded digest", "b.example.com", "source v2"} {
		if strings.Contains(delta3, omitted) {
			t.Fatalf("round 3 delta unexpectedly repeated unchanged %q:\n%s", omitted, delta3)
		}
	}
}

func TestPlannerRotatesOnCorruptTranscriptAndNoaCompression(t *testing.T) {
	dir := t.TempDir()
	tx := transcript.NewStore(filepath.Join(dir, "transcripts"))
	prov := &recordingRequestProvider{}
	p := NewPlanner(prov, "test-model", dir, tx, 200000, 5)
	const expID int64 = 202

	opts := agentcore.Options{
		Provider:        prov,
		SystemPrompt:    []string{"planner static prompt"},
		DynamicBoundary: 1,
		PermissionMode:  permission.ModeBypass,
		MaxTurns:        5,
		Todos:           p.todoFor(expID),
		NonStreaming:    true,
	}

	// 1. Corrupt transcript file at epoch 0 -> must advance to epoch 1 cleanly.
	badPath := tx.MainPath(plannerSessionID(expID, 0))
	if err := os.MkdirAll(filepath.Dir(badPath), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(badPath, []byte("{not-valid-json\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	overview := map[string]any{"goals": []map[string]any{{"id": 1, "state": "open"}}}
	if _, err := p.runPlannerSession(t.Context(), expID, opts, DeferredInfo{}, "r1", "", overview, "", nil); err != nil {
		t.Fatalf("corrupt transcript round failed: %v", err)
	}
	if got := p.plannerEpoch(expID); got != 1 {
		t.Fatalf("epoch = %d, want 1 after corrupt transcript rotation", got)
	}
	if !strings.Contains(prov.reqs[0].Messages[1].Text(), "graph_overview 预取") {
		t.Fatalf("rotated session did not send fresh baseline")
	}

	// 2. Active noa compression on epoch 1 -> must advance to epoch 2 with fresh baseline.
	noaStatePath := filepath.Join(dir, "noa", plannerSessionID(expID, 1), "state.json")
	if err := os.MkdirAll(filepath.Dir(noaStatePath), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(noaStatePath, []byte(`{"version":1,"blocks":[{"blockId":"b1","active":true}],"stats":{"compressionCount":1}}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := p.runPlannerSession(t.Context(), expID, opts, DeferredInfo{}, "r2", "", overview, "", nil); err != nil {
		t.Fatalf("noa rotation round failed: %v", err)
	}
	if got := p.plannerEpoch(expID); got != 2 {
		t.Fatalf("epoch = %d, want 2 after noa compression rotation", got)
	}
	if len(prov.reqs[1].Messages) != 2 || !strings.Contains(prov.reqs[1].Messages[1].Text(), "graph_overview 预取") {
		t.Fatalf("noa rotated session did not start fresh baseline: msgs=%d", len(prov.reqs[1].Messages))
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestQuotaAwareTransportClonesRequestAndCaps429Body(t *testing.T) {
	var seenHeader string
	huge429 := bytes.Repeat([]byte("x"), 512<<10)
	tr := quotaAwareTransport{
		sessionHeaderKey: "X-Session-ID",
		base: roundTripFunc(func(r *http.Request) (*http.Response, error) {
			seenHeader = r.Header.Get("X-Session-ID")
			return &http.Response{
				StatusCode: http.StatusTooManyRequests,
				Status:     "429 Too Many Requests",
				Body:       io.NopCloser(bytes.NewReader(huge429)),
				Header:     http.Header{},
			}, nil
		}),
	}

	ctx := transcript.WithSessionID(t.Context(), "sess-abc")
	origReq, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://example.invalid/v1/messages", nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := tr.RoundTrip(origReq)
	if err != nil {
		t.Fatalf("RoundTrip: %v", err)
	}
	defer resp.Body.Close()

	if seenHeader != "sess-abc" {
		t.Fatalf("downstream header = %q, want sess-abc", seenHeader)
	}
	if got := origReq.Header.Get("X-Session-ID"); got != "" {
		t.Fatalf("caller request header was mutated in place: %q", got)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	if len(body) != 256<<10 {
		t.Fatalf("429 body length = %d, want capped %d", len(body), 256<<10)
	}
}

func TestExpandDigestIsReadOnlyAndConcurrencySafe(t *testing.T) {
	ts := NewToolSet(nil, "planner")
	tool := ts.expandDigest()
	if !tool.IsReadOnly(nil) {
		t.Fatal("expand_digest must be marked read-only")
	}
	if !tool.IsConcurrencySafe(nil) {
		t.Fatal("expand_digest must be marked concurrency-safe")
	}
}
