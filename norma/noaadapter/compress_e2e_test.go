package noaadapter

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/RC-CHN/ARTEX/norma/harness"
	"github.com/RC-CHN/ARTEX/norma/llm"
	"github.com/RC-CHN/ARTEX/norma/noa"
	"github.com/RC-CHN/ARTEX/norma/permission"
	"github.com/RC-CHN/ARTEX/norma/tool"
)

// The production regression, end to end: the model streams a Compress call whose
// JSON never closes, a real HTTP provider parses the stream, the harness runs the
// tool, and noa salvages the ranges that DID arrive.
//
// Before the transport learned to honour tool.Spec.RawInput, this call died at
// the adapter with incomplete_response and the tool never ran — every time the
// context came under pressure, which is exactly when Compress matters.

func sse(w io.Writer, payload string) { fmt.Fprintf(w, "data: %s\n\n", payload) }

func compressThenTextServer(t *testing.T, args string, calls *atomic.Int32) *httptest.Server {
	t.Helper()
	quoted, err := json.Marshal(args)
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if calls.Add(1) == 1 {
			sse(w, `{"choices":[{"delta":{"tool_calls":[{"index":0,"id":"call_1","function":{"name":"Compress","arguments":`+string(quoted)+`}}]}}]}`)
			sse(w, `{"choices":[{"delta":{},"finish_reason":"tool_calls"}],"usage":{"prompt_tokens":90,"completion_tokens":40}}`)
			fmt.Fprint(w, "data: [DONE]\n\n")
			return
		}
		sse(w, `{"choices":[{"delta":{"content":"done"},"finish_reason":"stop"}]}`)
		fmt.Fprint(w, "data: [DONE]\n\n")
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestTruncatedCompressCallReachesTheToolThroughARealProvider(t *testing.T) {
	sess, msgs := pressureSession(t)
	view := sess.View(msgs)
	if len(view) == 0 {
		t.Fatal("empty view")
	}
	refs := sess.State().MessageRefs.ByRef
	if len(refs) < 6 {
		t.Fatalf("only %d refs assigned; the fixture is too short", len(refs))
	}

	// Two ranges: the first arrives whole, the second is cut off mid-object —
	// the shape a reply truncated by the output limit produces.
	args := `{"content":[{"startId":"` + noa.IndexToRef(2) + `","endId":"` + noa.IndexToRef(5) +
		`","summary":"` + strings.Repeat("salvaged deployment context. ", 20) +
		`"},{"startId":"` + noa.IndexToRef(6) + `","end`

	var calls atomic.Int32
	srv := compressThenTextServer(t, args, &calls)
	p, err := llm.NewProvider(llm.Config{Format: llm.FormatOpenAI, BaseURL: srv.URL, HTTPClient: srv.Client(), MaxRetries: -1, EmptyResponseRetries: -1})
	if err != nil {
		t.Fatal(err)
	}

	reg := tool.NewRegistry(newCompressTool(sess))
	var term *harness.Terminal
	for ev, err := range harness.Query(t.Context(), harness.QueryInput{
		Provider:       p,
		Messages:       view,
		Tools:          reg,
		PermissionMode: permission.ModeBypass,
	}, harness.QueryDeps{}) {
		if err != nil {
			t.Fatalf("event error: %v", err)
		}
		if ev.Kind == harness.KindResult {
			term = ev.Terminal
		}
	}
	if term == nil {
		t.Fatal("no terminal event")
	}
	if term.Reason != harness.ReasonCompleted {
		t.Fatalf("terminal = %s (%v); the truncated call never reached the tool", term.Reason, term.Err)
	}

	blocks := noa.ActiveBlocks(sess.State())
	if len(blocks) != 1 {
		t.Fatalf("%d blocks created; the salvaged range was lost", len(blocks))
	}
	if blocks[0].StartRef != noa.IndexToRef(2) || blocks[0].EndRef != noa.IndexToRef(5) {
		t.Fatalf("block covers %s..%s", blocks[0].StartRef, blocks[0].EndRef)
	}
	// Both requests were made: the tool ran, its result was fed back, and the
	// model finished. A turn that died at the adapter would have made one.
	if calls.Load() != 2 {
		t.Fatalf("provider calls = %d, want 2 (tool round-trip)", calls.Load())
	}
}
