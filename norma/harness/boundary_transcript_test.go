package harness

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"reflect"
	"strings"
	"testing"

	"github.com/RC-CHN/ARTEX/norma/llm"
	"github.com/RC-CHN/ARTEX/norma/permission"
	"github.com/RC-CHN/ARTEX/norma/tool"
	"github.com/RC-CHN/ARTEX/norma/transcript"
)

// multiBoundaryCompactor triggers a fresh compaction boundary on every turn
// once at least keepRecent+1 messages exist after the previous boundary.
type multiBoundaryCompactor struct {
	keepRecent int
	rounds     int
}

func (c *multiBoundaryCompactor) Pre(_ context.Context, msgs []llm.Message, _ int) []llm.Message {
	start := llm.LastBoundaryIndex(msgs) + 1
	if len(msgs)-start <= c.keepRecent {
		return msgs
	}
	c.rounds++
	tailStart := len(msgs) - c.keepRecent
	boundary := llm.BoundaryMessage(llm.BoundaryMeta{
		Trigger:            "auto",
		PreTokens:          10000 * c.rounds,
		MessagesSummarized: tailStart - start,
	})
	summary := llm.Message{
		Role:    llm.RoleUser,
		Content: []llm.ContentBlock{llm.TextBlock(fmt.Sprintf("[summary %d] condensed", c.rounds))},
	}
	out := make([]llm.Message, 0, len(msgs)+2)
	out = append(out, msgs[:tailStart]...)
	out = append(out, boundary, summary)
	out = append(out, msgs[tailStart:]...)
	return out
}

func (c *multiBoundaryCompactor) Reactive(_ context.Context, msgs []llm.Message) ([]llm.Message, bool) {
	return msgs, false
}

func (c *multiBoundaryCompactor) IsOverflow(error) bool { return false }

// TestBoundaryCompactionDeduplicatesKeptTailInTranscript drives harness.Query
// with a real transcript.Writer across multiple tool turns + compactions,
// proving kept-tail tool results are written as Type=="ref" pointers instead of
// duplicated on disk and that LoadActive reconstructs the exact same API view
// and cumulative usage as both full Load and in-memory history.
func TestBoundaryCompactionDeduplicatesKeptTailInTranscript(t *testing.T) {
	const rounds = 8
	const payloadBytes = 64 * 1024

	// Deterministic large-output tool (no shell dependency, works identically on
	// Windows and Linux).
	callIdx := 0
	bigTool := tool.Build(tool.Spec{
		Name:   "BigOutput",
		Schema: map[string]any{"type": "object"},
		Run: func(context.Context, json.RawMessage, *tool.ToolContext) (tool.Result, error) {
			callIdx++
			return tool.Text(fmt.Sprintf("result-%d:%s", callIdx, strings.Repeat("B", payloadBytes))), nil
		},
	})

	turns := make([][]llm.StreamEvent, 0, rounds+1)
	for i := 1; i <= rounds; i++ {
		turns = append(turns, usageToolTurn(fmt.Sprintf("c%d", i), "BigOutput", `{}`, 100*i, 20*i))
	}
	turns = append(turns, usageTextTurn("all done", 900, 50))
	model := &scriptedModel{turns: turns}

	store := transcript.NewStore(t.TempDir())
	sid := "harness-multi-compact"
	writer := store.NewWriter(sid, "")

	seedUser := llm.UserText("start multi-compaction run")
	writer.RecordMessage(seedUser, llm.Usage{})

	comp := &multiBoundaryCompactor{keepRecent: 2}
	term := drain(t, QueryInput{
		Messages:           []llm.Message{seedUser},
		Tools:              tool.NewRegistry(bigTool),
		PermissionMode:     permission.ModeBypass,
		WorkingDir:         t.TempDir(),
		MaxToolOutputChars: payloadBytes + 1024, // keep full 64 KiB output in message
		Compactor:          comp,
		Recorder:           writer,
	}, QueryDeps{CallModel: model.call})

	if term.Reason != ReasonCompleted || term.Text != "all done" {
		t.Fatalf("terminal=%+v", term)
	}
	if err := writer.Err(); err != nil {
		t.Fatalf("writer err: %v", err)
	}
	if comp.rounds < 6 {
		t.Fatalf("expected >=6 compaction rounds, got %d", comp.rounds)
	}

	path := store.MainPath(sid)
	st, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat transcript: %v", err)
	}
	// Each of the 8 tool results is ~64 KiB (~512 KiB total raw births). Without
	// kept-tail refs, re-recording 2 recent messages across 7+ compactions would
	// duplicate another ~450+ KiB. With refs, file size stays well below 650 KiB.
	if st.Size() > 650*1024 {
		t.Fatalf("transcript file size=%d bytes; kept-tail refs did not prevent duplication", st.Size())
	}

	fullRecs, err := store.Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	refCount := 0
	for _, r := range fullRecs {
		if r.Type == "ref" {
			refCount++
		}
	}
	if refCount == 0 {
		t.Fatal("expected Type==\"ref\" records for kept tail after compaction boundaries")
	}

	fullMsgs, fullUsage := transcript.Messages(fullRecs)
	wantAPI := llm.MessagesForAPI(term.Messages)
	if !reflect.DeepEqual(llm.MessagesForAPI(fullMsgs), wantAPI) {
		t.Fatal("full Load API messages differ from in-memory loop messages")
	}
	if fullUsage != term.Usage {
		t.Fatalf("full Load usage=%+v, want %+v", fullUsage, term.Usage)
	}

	// Verify LoadActive WITH .idx and AFTER deleting .idx both match byte-for-byte
	// while reading only a fraction of the file.
	for _, deleteIdx := range []bool{false, true} {
		label := "with-idx"
		if deleteIdx {
			label = "no-idx"
			if err := os.Remove(transcript.IndexPath(path)); err != nil {
				t.Fatalf("remove idx: %v", err)
			}
		}
		active, err := store.LoadActive(path)
		if err != nil {
			t.Fatalf("LoadActive (%s): %v", label, err)
		}
		activeMsgs, _ := transcript.Messages(active.Records)
		if !reflect.DeepEqual(llm.MessagesForAPI(activeMsgs), wantAPI) {
			t.Fatalf("LoadActive (%s): API messages differ from in-memory loop", label)
		}
		if active.TotalUsage != term.Usage {
			t.Fatalf("LoadActive (%s): TotalUsage=%+v, want %+v", label, active.TotalUsage, term.Usage)
		}
		if active.BytesRead >= st.Size()/2 {
			t.Fatalf("LoadActive (%s): BytesRead=%d >= half of fileSize=%d", label, active.BytesRead, st.Size())
		}
	}
}
