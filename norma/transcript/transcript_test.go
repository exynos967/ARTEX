package transcript

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/RC-CHN/ARTEX/norma/llm"
)

func TestRecordAndLoadRoundTrip(t *testing.T) {
	s := NewStore(t.TempDir())
	w := s.NewWriter("sess", "")
	w.RecordMessage(llm.UserText("hi"), llm.Usage{})
	w.RecordMessage(llm.Message{Role: llm.RoleAssistant, Content: []llm.ContentBlock{llm.TextBlock("yo")}}, llm.Usage{InputTokens: 10, OutputTokens: 5})
	if err := w.Err(); err != nil {
		t.Fatalf("write err: %v", err)
	}
	recs, err := s.Load(s.MainPath("sess"))
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if len(recs) != 2 {
		t.Fatalf("want 2 records, got %d", len(recs))
	}
	msgs, total := Messages(recs)
	if len(msgs) != 2 || msgs[0].Text() != "hi" || msgs[1].Text() != "yo" {
		t.Fatalf("reconstructed messages wrong: %+v", msgs)
	}
	if total != (llm.Usage{InputTokens: 10, OutputTokens: 5}) {
		t.Fatalf("usage accumulation wrong: %+v", total)
	}
}

// A boundary record is persisted for observability but skipped when
// reconstructing the conversation (compaction rebuilds the working set itself).
func TestBoundaryRecordSkippedInReconstruction(t *testing.T) {
	s := NewStore(t.TempDir())
	w := s.NewWriter("sess", "")
	w.RecordMessage(llm.UserText("before"), llm.Usage{})
	w.RecordBoundary(llm.BoundaryMeta{Trigger: "auto", PreTokens: 1234, MessagesSummarized: 3})
	w.RecordMessage(llm.UserText("after"), llm.Usage{})

	recs, _ := s.Load(s.MainPath("sess"))
	if len(recs) != 3 {
		t.Fatalf("want 3 records on disk (incl. boundary), got %d", len(recs))
	}
	// The boundary record is present and typed.
	var sawBoundary bool
	for _, r := range recs {
		if r.Type == "boundary" {
			sawBoundary = true
			if r.Boundary == nil || r.Boundary.PreTokens != 1234 {
				t.Fatalf("boundary meta not persisted: %+v", r.Boundary)
			}
		}
	}
	if !sawBoundary {
		t.Fatal("boundary record not written")
	}
	// But reconstruction skips it.
	msgs, _ := Messages(recs)
	if len(msgs) != 2 || msgs[0].Text() != "before" || msgs[1].Text() != "after" {
		t.Fatalf("boundary should be skipped in Messages: %+v", msgs)
	}
}

func TestParentChainAndLastUUID(t *testing.T) {
	s := NewStore(t.TempDir())
	w := s.NewWriter("sess", "")
	w.RecordMessage(llm.UserText("a"), llm.Usage{})
	w.RecordMessage(llm.UserText("b"), llm.Usage{})
	recs, _ := s.Load(s.MainPath("sess"))
	if recs[0].ParentUUID != "" {
		t.Fatalf("first record should have no parent, got %q", recs[0].ParentUUID)
	}
	if recs[1].ParentUUID != recs[0].UUID {
		t.Fatalf("chain broken: rec1.parent=%q, rec0.uuid=%q", recs[1].ParentUUID, recs[0].UUID)
	}
	if LastUUID(recs) != recs[1].UUID {
		t.Fatalf("LastUUID mismatch")
	}
	if LastUUID(nil) != "" {
		t.Fatal("LastUUID(nil) should be empty")
	}
}

func TestResumeWriterContinuesChain(t *testing.T) {
	s := NewStore(t.TempDir())
	w := s.NewWriter("sess", "")
	w.RecordMessage(llm.UserText("first"), llm.Usage{})
	recs, _ := s.Load(s.MainPath("sess"))
	last := LastUUID(recs)

	rw := s.ResumeWriter("sess", last)
	rw.RecordMessage(llm.UserText("second"), llm.Usage{})

	recs2, _ := s.Load(s.MainPath("sess"))
	if len(recs2) != 2 {
		t.Fatalf("want 2 records after resume, got %d", len(recs2))
	}
	if recs2[1].ParentUUID != last {
		t.Fatalf("resumed record should chain to %q, got %q", last, recs2[1].ParentUUID)
	}
}

func TestSubagentSidechainPath(t *testing.T) {
	s := NewStore(t.TempDir())
	w := s.NewWriter("sess", "agent1")
	w.RecordMessage(llm.UserText("sub"), llm.Usage{})
	// Written to the sidechain path, not the main file.
	if recs, _ := s.Load(s.AgentPath("sess", "agent1")); len(recs) != 1 || !recs[0].IsSidechain {
		t.Fatalf("subagent record not on sidechain: %+v", recs)
	}
	if recs, _ := s.Load(s.MainPath("sess")); len(recs) != 0 {
		t.Fatalf("main file should be empty, got %d", len(recs))
	}
}

func TestLoadMissingFileIsFreshSession(t *testing.T) {
	s := NewStore(t.TempDir())
	recs, err := s.Load(s.MainPath("does-not-exist"))
	if err != nil || recs != nil {
		t.Fatalf("missing file should yield (nil, nil), got (%v, %v)", recs, err)
	}
}

func TestMessagesFiltersNilAndBoundary(t *testing.T) {
	recs := []Record{
		{Type: "message", Message: &llm.Message{Role: llm.RoleUser, Content: []llm.ContentBlock{llm.TextBlock("x")}}, Usage: &llm.Usage{InputTokens: 3}},
		{Type: "boundary", Boundary: &llm.BoundaryMeta{}},
		{Type: "message", Message: nil}, // defensive: nil message skipped
	}
	msgs, total := Messages(recs)
	if len(msgs) != 1 || total.InputTokens != 3 {
		t.Fatalf("Messages should keep only the real message: msgs=%d usage=%+v", len(msgs), total)
	}
}

func TestSessionIDContextRoundTrip(t *testing.T) {
	ctx := WithSessionID(context.Background(), "abc123")
	if got := SessionIDFrom(ctx); got != "abc123" {
		t.Fatalf("SessionIDFrom=%q, want abc123", got)
	}
	if got := SessionIDFrom(context.Background()); got != "" {
		t.Fatalf("empty context should yield \"\", got %q", got)
	}
}

func TestNewIDsAreDistinctAndNonEmpty(t *testing.T) {
	a, b := NewSessionID(), NewSessionID()
	if a == "" || b == "" || a == b {
		t.Fatalf("session ids should be non-empty and distinct: %q %q", a, b)
	}
	if id := NewAgentID(); id == "" || len(id) != 32 { // 16 random bytes hex-encoded
		t.Fatalf("agent id malformed: %q", id)
	}
}

func TestLoadCorruptLineErrors(t *testing.T) {
	s := NewStore(t.TempDir())
	path := s.MainPath("sess")
	// Write a valid record, then a corrupt (non-JSON) line.
	w := s.NewWriter("sess", "")
	w.RecordMessage(llm.UserText("ok"), llm.Usage{})
	if err := appendRaw(path, "{not valid json\n"); err != nil {
		t.Fatalf("setup append: %v", err)
	}
	if _, err := s.Load(path); err == nil {
		t.Fatal("Load should error on a corrupt line")
	}
}

// appendRaw appends a raw line to a transcript file for corruption testing.
func appendRaw(path, line string) error {
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = f.WriteString(line)
	return err
}

func TestRecordMessageRefDeduplicatesAcrossCompactions(t *testing.T) {
	s := NewStore(t.TempDir())
	sid := "dedup-10x"
	w := s.NewWriter(sid, "")

	// Seed 4 large messages (100 KiB each = 400 KiB total) that will stay in the kept tail.
	tail := make([]llm.Message, 4)
	for i := range tail {
		payload := fmt.Sprintf("tail-%d:%s", i, strings.Repeat(string(rune('A'+i)), 100*1024))
		if i%2 == 0 {
			tail[i] = llm.UserText(payload)
			w.RecordMessage(tail[i], llm.Usage{})
		} else {
			tail[i] = llm.Message{Role: llm.RoleAssistant, Content: []llm.ContentBlock{llm.TextBlock(payload)}}
			w.RecordMessage(tail[i], llm.Usage{InputTokens: 100, OutputTokens: 50})
		}
	}

	// Simulate 10 compactions keeping the exact same 4 giant tail messages.
	for c := 1; c <= 10; c++ {
		meta := llm.BoundaryMeta{Trigger: "auto", PreTokens: 50000 + c, MessagesSummarized: 5}
		w.RecordBoundary(meta)
		w.RecordMessage(llm.BoundaryMessage(meta), llm.Usage{})
		w.RecordMessage(llm.UserText(fmt.Sprintf("summary-%d", c)), llm.Usage{})
		for _, m := range tail {
			w.RecordMessageRef(m)
		}
		// One small new turn after each compaction.
		w.RecordMessage(llm.Message{
			Role:    llm.RoleAssistant,
			Content: []llm.ContentBlock{llm.TextBlock(fmt.Sprintf("reply-%d", c))},
		}, llm.Usage{InputTokens: 20, OutputTokens: 10})
	}
	if err := w.Err(); err != nil {
		t.Fatalf("writer err: %v", err)
	}

	path := s.MainPath(sid)
	st, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	// Without refs, 10 compactions × 400 KiB would exceed 4.4 MiB.
	// With refs, the 400 KiB payload is stored only ONCE (~430 KiB total).
	if st.Size() > 700*1024 {
		t.Fatalf("transcript grew too large across 10 compactions: %d bytes (expected < 700 KiB)", st.Size())
	}

	fullRecs, err := s.Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	origTypes := make(map[string]string, len(fullRecs))
	refCount := 0
	for _, r := range fullRecs {
		origTypes[r.UUID] = r.Type
		if r.Type == "ref" {
			refCount++
			if origTypes[r.RefUUID] != "message" {
				t.Fatalf("ref %s points to type %q (must point directly to original message, never chain ref->ref)", r.UUID, origTypes[r.RefUUID])
			}
		}
	}
	if refCount != 40 {
		t.Fatalf("refCount=%d, want 40 (10 compactions * 4 kept tail msgs)", refCount)
	}

	fullMsgs, fullUsage := Messages(fullRecs)
	active, err := s.LoadActive(path)
	if err != nil {
		t.Fatalf("LoadActive: %v", err)
	}
	activeMsgs, _ := Messages(active.Records)
	if !reflect.DeepEqual(llm.MessagesForAPI(activeMsgs), llm.MessagesForAPI(fullMsgs)) {
		t.Fatal("LoadActive API messages differ from full Load")
	}
	wantUsage := llm.Usage{InputTokens: 2*100 + 10*20, OutputTokens: 2*50 + 10*10}
	if fullUsage != wantUsage || active.TotalUsage != wantUsage {
		t.Fatalf("usage mismatch: full=%+v active=%+v want=%+v", fullUsage, active.TotalUsage, wantUsage)
	}
}

func TestRecordMessageRefFallbackOnModifiedMessage(t *testing.T) {
	s := NewStore(t.TempDir())
	w := s.NewWriter("modified", "")
	call := llm.Message{
		Role: llm.RoleAssistant,
		Content: []llm.ContentBlock{{
			Type:  llm.BlockToolUse,
			ID:    "t1",
			Name:  "Read",
			Input: json.RawMessage(`{"path":"a.txt"}`),
		}},
	}
	orig := llm.Message{
		Role: llm.RoleUser,
		Content: []llm.ContentBlock{{
			Type:      llm.BlockToolResult,
			ToolUseID: "t1",
			Content:   []llm.ContentBlock{llm.TextBlock(strings.Repeat("X", 20*1024))},
		}},
	}
	w.RecordMessage(call, llm.Usage{})
	w.RecordMessage(orig, llm.Usage{})

	// Simulate MicroCompact clearing the tool result before compaction persists tail.
	cleared := llm.Message{
		Role: llm.RoleUser,
		Content: []llm.ContentBlock{{
			Type:      llm.BlockToolResult,
			ToolUseID: "t1",
			Content:   []llm.ContentBlock{llm.TextBlock("[Old tool result content cleared]")},
		}},
	}
	meta := llm.BoundaryMeta{Trigger: "auto", PreTokens: 9000}
	w.RecordBoundary(meta)
	w.RecordMessage(llm.BoundaryMessage(meta), llm.Usage{})
	w.RecordMessage(llm.UserText("summary"), llm.Usage{})
	w.RecordMessageRef(call)
	w.RecordMessageRef(cleared)

	path := s.MainPath("modified")
	active, err := s.LoadActive(path)
	if err != nil {
		t.Fatalf("LoadActive: %v", err)
	}
	// call was unchanged -> stored as ref; cleared was modified -> stored as full message.
	if got := active.Records[len(active.Records)-2].Type; got != "ref" {
		t.Fatalf("unmodified tool_use should be ref, got %q", got)
	}
	if got := active.Records[len(active.Records)-1].Type; got != "message" {
		t.Fatalf("modified message should be written as full message, got type %q", got)
	}
	msgs, _ := Messages(active.Records)
	api := llm.MessagesForAPI(msgs)
	if len(api) != 3 || !reflect.DeepEqual(api[1], call) || !reflect.DeepEqual(api[2], cleared) {
		t.Fatalf("reconstructed cleared message mismatch: got %+v", api)
	}
}

func TestLoadActiveFastPathFallbackAndStaleIndex(t *testing.T) {
	s := NewStore(t.TempDir())
	sid := "large-active"
	w := s.NewWriter(sid, "")

	// Freeze historical clock on first record so FirstTimestamp is verifiable.
	baseTime := time.Date(2025, 3, 15, 8, 30, 0, 0, time.UTC)
	step := 0
	w.now = func() time.Time {
		step++
		return baseTime.Add(time.Duration(step) * time.Minute)
	}

	// Write ~2 MiB of pre-boundary history across 20 messages.
	for i := 0; i < 20; i++ {
		body := fmt.Sprintf("pre-%d:%s", i, strings.Repeat("p", 100*1024))
		if i%2 == 0 {
			w.RecordMessage(llm.UserText(body), llm.Usage{})
		} else {
			w.RecordMessage(llm.Message{
				Role:    llm.RoleAssistant,
				Content: []llm.ContentBlock{llm.TextBlock(body)},
			}, llm.Usage{InputTokens: 1000, OutputTokens: 200, CacheReadTokens: 500})
		}
	}
	keptTail := llm.UserText("kept-tail:" + strings.Repeat("k", 4096))
	w.RecordMessage(keptTail, llm.Usage{})

	// Compaction boundary.
	meta := llm.BoundaryMeta{Trigger: "auto", PreTokens: 80000, MessagesSummarized: 20}
	w.RecordBoundary(meta)
	w.RecordMessage(llm.BoundaryMessage(meta), llm.Usage{})
	w.RecordMessage(llm.UserText("compaction summary"), llm.Usage{})
	w.RecordMessageRef(keptTail)

	// Post-boundary message containing a literal `"type":"boundary"` inside a
	// tool_use JSON input to prove reverse-scan does not false-positive on nested JSON.
	tricky := llm.Message{
		Role: llm.RoleAssistant,
		Content: []llm.ContentBlock{{
			Type:  llm.BlockToolUse,
			ID:    "tool_1",
			Name:  "Echo",
			Input: json.RawMessage(`{"type":"boundary","nested":true}`),
		}},
	}
	w.RecordMessage(tricky, llm.Usage{InputTokens: 300, OutputTokens: 40, CacheWriteTokens: 10})
	w.RecordMessage(llm.Message{
		Role: llm.RoleUser,
		Content: []llm.ContentBlock{{
			Type:      llm.BlockToolResult,
			ToolUseID: "tool_1",
			Content:   []llm.ContentBlock{llm.TextBlock("ok")},
		}},
	}, llm.Usage{})
	if err := w.Err(); err != nil {
		t.Fatalf("write err: %v", err)
	}

	path := s.MainPath(sid)
	st, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	fileSize := st.Size()

	fullRecs, err := s.Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	fullMsgs, fullUsage := Messages(fullRecs)
	wantAPI := llm.MessagesForAPI(fullMsgs)
	wantFirstTS := fullRecs[0].Timestamp
	wantLastUUID := LastUUID(fullRecs)

	checkActive := func(label string, active ActiveTranscript, maxBytes int64) {
		t.Helper()
		if active.BytesRead <= 0 || active.BytesRead >= maxBytes {
			t.Fatalf("%s: BytesRead=%d, want 0 < BytesRead < %d (fileSize=%d)", label, active.BytesRead, maxBytes, fileSize)
		}
		gotMsgs, _ := Messages(active.Records)
		if !reflect.DeepEqual(llm.MessagesForAPI(gotMsgs), wantAPI) {
			t.Fatalf("%s: API messages differ from full Load", label)
		}
		if active.TotalUsage != fullUsage {
			t.Fatalf("%s: TotalUsage=%+v, want %+v", label, active.TotalUsage, fullUsage)
		}
		if active.FirstTimestamp != wantFirstTS {
			t.Fatalf("%s: FirstTimestamp=%q, want %q", label, active.FirstTimestamp, wantFirstTS)
		}
		if active.LastUUID != wantLastUUID {
			t.Fatalf("%s: LastUUID=%q, want %q", label, active.LastUUID, wantLastUUID)
		}
	}

	// 1. Fast path WITH fresh sidecar .idx.
	activeWithIdx, err := s.LoadActive(path)
	if err != nil {
		t.Fatalf("LoadActive (with idx): %v", err)
	}
	checkActive("with-idx", activeWithIdx, fileSize/20)

	// 2. Reverse-scan fallback AFTER deleting .idx.
	savedIdxBytes, err := os.ReadFile(IndexPath(path))
	if err != nil {
		t.Fatalf("read idx: %v", err)
	}
	if err := os.Remove(IndexPath(path)); err != nil {
		t.Fatalf("remove idx: %v", err)
	}
	activeNoIdx, err := s.LoadActive(path)
	if err != nil {
		t.Fatalf("LoadActive (no idx): %v", err)
	}
	checkActive("no-idx-reverse-scan", activeNoIdx, fileSize/10)

	// 3. Corrupt .idx gracefully falls back.
	if err := os.WriteFile(IndexPath(path), []byte("{corrupt"), 0o644); err != nil {
		t.Fatalf("write corrupt idx: %v", err)
	}
	activeCorruptIdx, err := s.LoadActive(path)
	if err != nil {
		t.Fatalf("LoadActive (corrupt idx): %v", err)
	}
	checkActive("corrupt-idx", activeCorruptIdx, fileSize/10)

	// 4. Stale .idx pointing at mid-line offset gracefully falls back.
	badOffsetIdx := sidecarIndex{
		Version:            sidecarVersion,
		FileSize:           fileSize,
		HasBoundary:        true,
		LastBoundaryOffset: 17, // inside line 0
		FirstTimestamp:     wantFirstTS,
	}
	badBytes, _ := json.Marshal(badOffsetIdx)
	if err := os.WriteFile(IndexPath(path), badBytes, 0o644); err != nil {
		t.Fatalf("write bad-offset idx: %v", err)
	}
	activeBadOffset, err := s.LoadActive(path)
	if err != nil {
		t.Fatalf("LoadActive (bad offset idx): %v", err)
	}
	checkActive("bad-offset-idx", activeBadOffset, fileSize/10)

	// 5. Delta-append after .idx snapshot: restore valid .idx, append a new turn
	// directly to the JSONL file (simulating crash before .idx flush), and verify
	// LoadActive picks up the new record, updates LastUUID, and adds delta usage.
	if err := os.WriteFile(IndexPath(path), savedIdxBytes, 0o644); err != nil {
		t.Fatalf("restore idx: %v", err)
	}
	extraMsg := llm.Message{Role: llm.RoleAssistant, Content: []llm.ContentBlock{llm.TextBlock("after-idx")}}
	extraRec := Record{
		UUID:      "delta-uuid-1",
		SessionID: sid,
		Timestamp: baseTime.Add(99 * time.Minute).Format(time.RFC3339Nano),
		Type:      "message",
		Message:   &extraMsg,
		Usage:     &llm.Usage{InputTokens: 77, OutputTokens: 33},
	}
	extraLine, _ := json.Marshal(extraRec)
	if err := appendRaw(path, string(extraLine)+"\n"); err != nil {
		t.Fatalf("appendRaw delta: %v", err)
	}
	activeDelta, err := s.LoadActive(path)
	if err != nil {
		t.Fatalf("LoadActive (delta): %v", err)
	}
	wantDeltaUsage := fullUsage
	wantDeltaUsage.Add(*extraRec.Usage)
	if activeDelta.TotalUsage != wantDeltaUsage {
		t.Fatalf("delta TotalUsage=%+v, want %+v", activeDelta.TotalUsage, wantDeltaUsage)
	}
	if activeDelta.LastUUID != "delta-uuid-1" {
		t.Fatalf("delta LastUUID=%q, want delta-uuid-1", activeDelta.LastUUID)
	}
	if activeDelta.BytesRead >= fileSize/10 {
		t.Fatalf("delta path read too much: %d vs fileSize %d", activeDelta.BytesRead, fileSize)
	}
}

func TestLoadActiveRefOffsetFallbackWhenFileShifted(t *testing.T) {
	s := NewStore(t.TempDir())
	sid := "shifted-ref"
	w := s.NewWriter(sid, "")
	orig := llm.UserText("original-payload-" + strings.Repeat("Z", 1024))
	w.RecordMessage(orig, llm.Usage{})
	meta := llm.BoundaryMeta{Trigger: "auto", PreTokens: 500}
	w.RecordBoundary(meta)
	w.RecordMessage(llm.BoundaryMessage(meta), llm.Usage{})
	w.RecordMessage(llm.UserText("sum"), llm.Usage{})
	w.RecordMessageRef(orig)

	path := s.MainPath(sid)
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	// Prepend an extra blank/valid record line, shifting every byte offset.
	prefixMsg := llm.UserText("inserted-prefix")
	prefixRec, _ := json.Marshal(Record{
		UUID:      "inserted-0",
		SessionID: sid,
		Timestamp: time.Now().UTC().Format(time.RFC3339Nano),
		Type:      "message",
		Message:   &prefixMsg,
	})
	if err := os.WriteFile(path, append(append(prefixRec, '\n'), data...), 0o644); err != nil {
		t.Fatalf("rewrite shifted file: %v", err)
	}
	_ = os.Remove(IndexPath(path))

	active, err := s.LoadActive(path)
	if err != nil {
		t.Fatalf("LoadActive shifted: %v", err)
	}
	msgs, _ := Messages(active.Records)
	api := llm.MessagesForAPI(msgs)
	if len(api) != 2 || api[1].Text() != orig.Text() {
		t.Fatalf("shifted ref resolution failed: got %d msgs", len(api))
	}
}

func TestLoadActiveMissingAndNoBoundary(t *testing.T) {
	s := NewStore(t.TempDir())
	active, err := s.LoadActive(s.MainPath("missing"))
	if err != nil || len(active.Records) != 0 || active.LastUUID != "" {
		t.Fatalf("missing file should yield empty ActiveTranscript, got %+v err=%v", active, err)
	}

	w := s.NewWriter("no-boundary", "")
	w.RecordMessage(llm.UserText("u1"), llm.Usage{})
	w.RecordMessage(llm.Message{Role: llm.RoleAssistant, Content: []llm.ContentBlock{llm.TextBlock("a1")}}, llm.Usage{InputTokens: 11, OutputTokens: 7})

	active, err = s.LoadActive(s.MainPath("no-boundary"))
	if err != nil {
		t.Fatalf("LoadActive no-boundary: %v", err)
	}
	if len(active.Records) != 2 || active.TotalUsage != (llm.Usage{InputTokens: 11, OutputTokens: 7}) {
		t.Fatalf("unexpected active without boundary: %+v", active)
	}
}

func TestResumeWriterSeedRefsDeduplicatesAfterResume(t *testing.T) {
	s := NewStore(t.TempDir())
	sid := "resume-seed-refs"
	w := s.NewWriter(sid, "")
	big := llm.UserText("big-pre-resume:" + strings.Repeat("R", 80*1024))
	w.RecordMessage(big, llm.Usage{})
	w.RecordMessage(llm.Message{Role: llm.RoleAssistant, Content: []llm.ContentBlock{llm.TextBlock("ack")}}, llm.Usage{InputTokens: 15, OutputTokens: 5})

	path := s.MainPath(sid)
	active1, err := s.LoadActive(path)
	if err != nil {
		t.Fatalf("LoadActive 1: %v", err)
	}
	rw := s.ResumeWriter(sid, active1.LastUUID)
	rw.SeedRefs(active1)

	meta := llm.BoundaryMeta{Trigger: "auto", PreTokens: 10000}
	rw.RecordBoundary(meta)
	rw.RecordMessage(llm.BoundaryMessage(meta), llm.Usage{})
	rw.RecordMessage(llm.UserText("post-resume summary"), llm.Usage{})
	rw.RecordMessageRef(big)
	if err := rw.Err(); err != nil {
		t.Fatalf("rw err: %v", err)
	}

	active2, err := s.LoadActive(path)
	if err != nil {
		t.Fatalf("LoadActive 2: %v", err)
	}
	last := active2.Records[len(active2.Records)-1]
	if last.Type != "ref" {
		t.Fatalf("expected ref record after Resume+SeedRefs, got type %q", last.Type)
	}
	msgs, _ := Messages(active2.Records)
	api := llm.MessagesForAPI(msgs)
	if len(api) != 2 || api[1].Text() != big.Text() {
		t.Fatalf("reconstructed post-resume ref mismatch")
	}
}

// TestLoadActiveLegacyBoundaryWithoutTotalUsageRecoversExactTotals verifies that
// a pre-Phase-4 JSONL transcript whose boundary record has TotalUsage==nil and
// no sidecar .idx file recovers exact cumulative pre-boundary + post-boundary
// usage, and that subsequent appends persist the full total into .idx.
func TestLoadActiveLegacyBoundaryWithoutTotalUsageRecoversExactTotals(t *testing.T) {
	s := NewStore(t.TempDir())
	sid := "legacy-no-total-usage"
	path := s.MainPath(sid)

	u1 := llm.UserText("pre-1")
	a1 := llm.Message{Role: llm.RoleAssistant, Content: []llm.ContentBlock{llm.TextBlock("pre-reply-1")}}
	a2 := llm.Message{Role: llm.RoleAssistant, Content: []llm.ContentBlock{llm.TextBlock("pre-reply-2")}}
	meta := llm.BoundaryMeta{Trigger: "auto", PreTokens: 5000, MessagesSummarized: 3}
	bm := llm.BoundaryMessage(meta)
	sum := llm.UserText("legacy summary")
	post := llm.Message{Role: llm.RoleAssistant, Content: []llm.ContentBlock{llm.TextBlock("post-reply")}}

	legacyRecs := []Record{
		{UUID: "u1", SessionID: sid, Timestamp: "2025-01-01T00:00:01Z", Type: "message", Message: &u1},
		{UUID: "a1", ParentUUID: "u1", SessionID: sid, Timestamp: "2025-01-01T00:00:02Z", Type: "message", Message: &a1, Usage: &llm.Usage{InputTokens: 1000, OutputTokens: 200, CacheReadTokens: 300}},
		{UUID: "a2", ParentUUID: "a1", SessionID: sid, Timestamp: "2025-01-01T00:00:03Z", Type: "message", Message: &a2, Usage: &llm.Usage{InputTokens: 500, OutputTokens: 100, CacheWriteTokens: 50}},
		// Legacy boundary: TotalUsage is nil (omitted on disk).
		{UUID: "b1", ParentUUID: "a2", SessionID: sid, Timestamp: "2025-01-01T00:00:04Z", Type: "boundary", Boundary: &meta},
		{UUID: "bm1", ParentUUID: "b1", SessionID: sid, Timestamp: "2025-01-01T00:00:04Z", Type: "message", Message: &bm},
		{UUID: "s1", ParentUUID: "bm1", SessionID: sid, Timestamp: "2025-01-01T00:00:05Z", Type: "message", Message: &sum},
		{UUID: "p1", ParentUUID: "s1", SessionID: sid, Timestamp: "2025-01-01T00:00:06Z", Type: "message", Message: &post, Usage: &llm.Usage{InputTokens: 250, OutputTokens: 40}},
	}
	var lines strings.Builder
	for _, r := range legacyRecs {
		b, err := json.Marshal(r)
		if err != nil {
			t.Fatal(err)
		}
		lines.Write(b)
		lines.WriteByte('\n')
	}
	if err := os.WriteFile(path, []byte(lines.String()), 0o644); err != nil {
		t.Fatal(err)
	}
	// Ensure no .idx exists.
	_ = os.Remove(IndexPath(path))

	fullRecs, err := s.Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	_, wantUsage := Messages(fullRecs)

	active, err := s.LoadActive(path)
	if err != nil {
		t.Fatalf("LoadActive: %v", err)
	}
	if active.TotalUsage != wantUsage {
		t.Fatalf("legacy LoadActive TotalUsage=%+v, want %+v", active.TotalUsage, wantUsage)
	}
	if active.FirstTimestamp != "2025-01-01T00:00:01Z" {
		t.Fatalf("FirstTimestamp=%q, want 2025-01-01T00:00:01Z", active.FirstTimestamp)
	}

	// Subsequent ResumeWriter append rebuilds and writes .idx — must preserve full total.
	rw := s.ResumeWriter(sid, active.LastUUID)
	rw.RecordMessage(llm.Message{Role: llm.RoleAssistant, Content: []llm.ContentBlock{llm.TextBlock("after-resume")}}, llm.Usage{InputTokens: 70, OutputTokens: 15})
	if err := rw.Err(); err != nil {
		t.Fatalf("rw.Err: %v", err)
	}
	wantAfter := wantUsage
	wantAfter.Add(llm.Usage{InputTokens: 70, OutputTokens: 15})

	active2, err := s.LoadActive(path)
	if err != nil {
		t.Fatalf("LoadActive after resume: %v", err)
	}
	if active2.TotalUsage != wantAfter {
		t.Fatalf("post-resume TotalUsage=%+v, want %+v (must not persist zeroed pre-boundary total into .idx)", active2.TotalUsage, wantAfter)
	}
}

func TestStoreConcurrentAppendAndLoadRaceFree(t *testing.T) {
	s := NewStore(t.TempDir())
	sid := "concurrent-rw"
	path := s.MainPath(sid)
	w := s.NewWriter(sid, "")

	var wg sync.WaitGroup
	wg.Add(3)
	go func() {
		defer wg.Done()
		big := strings.Repeat("Z", 32*1024)
		for i := range 25 {
			w.RecordMessage(llm.UserText(fmt.Sprintf("msg-%d-%s", i, big)), llm.Usage{InputTokens: 10})
		}
	}()
	go func() {
		defer wg.Done()
		for range 25 {
			if _, err := s.Load(path); err != nil {
				t.Errorf("concurrent Load error: %v", err)
			}
		}
	}()
	go func() {
		defer wg.Done()
		for range 25 {
			if _, err := s.LoadActive(path); err != nil {
				t.Errorf("concurrent LoadActive error: %v", err)
			}
		}
	}()
	wg.Wait()
	if err := w.Err(); err != nil {
		t.Fatalf("writer err: %v", err)
	}
}
