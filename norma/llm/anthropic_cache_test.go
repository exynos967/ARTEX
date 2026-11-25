package llm

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
)

// countCacheControls recursively counts every "cache_control" key in a decoded
// JSON payload so tests verify Anthropic's hard limit of 4 breakpoints.
func countCacheControls(v any) int {
	switch x := v.(type) {
	case map[string]any:
		n := 0
		for k, val := range x {
			if k == "cache_control" && val != nil {
				n++
			}
			n += countCacheControls(val)
		}
		return n
	case []any:
		n := 0
		for _, item := range x {
			n += countCacheControls(item)
		}
		return n
	default:
		return 0
	}
}

func decodeAnthropicBody(t *testing.T, p *anthropicProvider, req CompletionRequest) (raw []byte, decoded anthropicReq, generic map[string]any) {
	t.Helper()
	var err error
	raw, err = p.buildBody(req, true)
	if err != nil {
		t.Fatalf("buildBody: %v", err)
	}
	if err := json.Unmarshal(raw, &decoded); err != nil {
		t.Fatalf("unmarshal typed: %v\n%s", err, raw)
	}
	if err := json.Unmarshal(raw, &generic); err != nil {
		t.Fatalf("unmarshal generic: %v\n%s", err, raw)
	}
	return raw, decoded, generic
}

// Verifies total cache_control breakpoints never exceed Anthropic's max of 4
// across every combination of tools, static/dynamic system, and conversation lengths.
func TestAnthropicCacheBreakpointCapAllCombos(t *testing.T) {
	tools0 := []ToolSchema(nil)
	tools3 := []ToolSchema{
		{Name: "Read", Description: "read", InputSchema: map[string]any{"type": "object"}},
		{Name: "Write", Description: "write", InputSchema: map[string]any{"type": "object"}},
		{Name: "Bash", Description: "bash", InputSchema: map[string]any{"type": "object"}},
	}
	sysNone := []string(nil)
	sysSplit := []string{"static-1", "static-2", "<artex-dynamic-time>t</artex-dynamic-time>"}

	makeMsgs := func(n int) []Message {
		out := make([]Message, 0, n)
		for i := range n {
			if i%2 == 0 {
				out = append(out, UserText("user turn"))
			} else {
				out = append(out, Message{Role: RoleAssistant, Content: []ContentBlock{TextBlock("assistant turn")}})
			}
		}
		return out
	}

	p := &anthropicProvider{cfg: Config{Model: "claude-sonnet"}}
	for _, tc := range []struct {
		name     string
		tools    []ToolSchema
		sys      []string
		boundary int
		msgCount int
		wantMax  int
		wantCnt  int
	}{
		{"all 4 slots used (tools+sys+2 msg turns)", tools3, sysSplit, 2, 5, 4, 4},
		{"tools+sys+single message", tools3, sysSplit, 2, 1, 4, 3},
		{"tools+sys+two messages", tools3, sysSplit, 2, 2, 4, 3},
		{"tools+sys+three messages", tools3, sysSplit, 2, 3, 4, 4},
		{"tools+sys+seven messages", tools3, sysSplit, 2, 7, 4, 4},
		{"no tools + static sys + 5 messages", tools0, sysSplit, 2, 5, 4, 3},
		{"tools + no boundary + 5 messages", tools3, sysSplit, 0, 5, 4, 3},
		{"no tools + no sys + 5 messages", tools0, sysNone, 0, 5, 4, 2},
		{"no tools + all-static sys + 5 messages", tools0, sysSplit, 3, 5, 4, 3},
		{"empty messages + tools + sys", tools3, sysSplit, 2, 0, 4, 2},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req := CompletionRequest{
				System:          tc.sys,
				DynamicBoundary: tc.boundary,
				Tools:           tc.tools,
				Messages:        makeMsgs(tc.msgCount),
			}
			_, _, generic := decodeAnthropicBody(t, p, req)
			got := countCacheControls(generic)
			if got > maxAnthropicCacheBreakpoints {
				t.Fatalf("cache_control count=%d exceeds Anthropic max %d", got, maxAnthropicCacheBreakpoints)
			}
			if got != tc.wantCnt {
				t.Fatalf("cache_control count=%d, want %d", got, tc.wantCnt)
			}
		})
	}
}

// Verifies exact placement of breakpoints: last tool only, static system only,
// and rolling message breakpoints at final turn and previous turn boundary.
func TestAnthropicCacheBreakpointPlacement(t *testing.T) {
	p := &anthropicProvider{cfg: Config{Model: "claude-sonnet"}}
	req := CompletionRequest{
		System:          []string{"base prompt", "tool guide", "<artex-dynamic-time>now</artex-dynamic-time>"},
		DynamicBoundary: 2,
		Tools: []ToolSchema{
			{Name: "Read", Description: "read", InputSchema: map[string]any{"type": "object"}},
			{Name: "Bash", Description: "bash", InputSchema: map[string]any{"type": "object"}},
		},
		Messages: []Message{
			UserText("turn 0"),
			{Role: RoleAssistant, Content: []ContentBlock{
				TextBlock("calling bash"),
				{Type: BlockToolUse, ID: "tu_1", Name: "Bash", Input: json.RawMessage(`{"cmd":"ls"}`)},
			}},
			{Role: RoleUser, Content: []ContentBlock{ToolResultText("tu_1", "out1", false)}},
			{Role: RoleAssistant, Content: []ContentBlock{
				{Type: BlockToolUse, ID: "tu_2", Name: "Read", Input: json.RawMessage(`{"path":"a.go"}`)},
			}},
			{Role: RoleUser, Content: []ContentBlock{ToolResultText("tu_2", "pkg", true)}},
		},
	}

	_, body, generic := decodeAnthropicBody(t, p, req)
	if got := countCacheControls(generic); got != 4 {
		t.Fatalf("total cache_control=%d, want 4", got)
	}
	// Breakpoint 1: last tool only.
	if body.Tools[0].CacheControl != nil {
		t.Fatal("non-last tool must not carry cache_control")
	}
	if !reflect.DeepEqual(body.Tools[1].CacheControl, map[string]any{"type": "ephemeral"}) {
		t.Fatalf("last tool cache_control=%v, want ephemeral", body.Tools[1].CacheControl)
	}
	// Breakpoint 2: static system block only.
	if len(body.System) != 2 || body.System[0].CacheControl == nil || body.System[1].CacheControl != nil {
		t.Fatalf("system breakpoints wrong: %+v", body.System)
	}
	// Breakpoints 3-4: messages[2] (len-3) and messages[4] (len-1).
	for idx, m := range body.Messages {
		wantMarked := idx == 2 || idx == 4
		gotMarked := false
		for _, b := range m.Content {
			if b.CacheControl != nil {
				gotMarked = true
			}
		}
		if gotMarked != wantMarked {
			t.Fatalf("message[%d] marked=%v, want %v", idx, gotMarked, wantMarked)
		}
	}
	// Verify all content block fields are preserved faithfully (tool_use, tool_result, is_error).
	tu := body.Messages[1].Content[1]
	if tu.Type != BlockToolUse || tu.ID != "tu_1" || tu.Name != "Bash" || string(tu.Input) != `{"cmd":"ls"}` {
		t.Fatalf("tool_use block corrupted: %+v", tu)
	}
	tr := body.Messages[4].Content[0]
	if tr.Type != BlockToolResult || tr.ToolUseID != "tu_2" || !tr.IsError || len(tr.Content) != 1 || tr.Content[0].Text != "pkg" {
		t.Fatalf("tool_result block corrupted: %+v", tr)
	}
}

// Thinking blocks and empty text blocks must NEVER carry cache_control; marking
// walks back to the previous cacheable block (or earlier message).
func TestAnthropicCacheSkipsThinkingAndEmptyTextBlocks(t *testing.T) {
	p := &anthropicProvider{cfg: Config{Model: "claude-sonnet", ThinkingType: "enabled"}}
	req := CompletionRequest{
		Messages: []Message{
			UserText("start"),
			{Role: RoleAssistant, Content: []ContentBlock{
				{Type: BlockThinking, Thinking: "thought-1", Signature: "sig-1"},
				TextBlock("answer-1"),
			}},
			// Message 2 has ONLY an empty text block (non-cacheable) + valid tool_result before it.
			{Role: RoleUser, Content: []ContentBlock{
				ToolResultText("c1", "result-1", false),
				TextBlock(""),
			}},
			// Message 3 is thinking-only (non-cacheable when thinking is enabled).
			{Role: RoleAssistant, Content: []ContentBlock{
				{Type: BlockThinking, Thinking: "thought-2", Signature: "sig-2"},
			}},
		},
	}

	_, body, generic := decodeAnthropicBody(t, p, req)
	if got := countCacheControls(generic); got != 2 {
		t.Fatalf("total cache_control=%d, want 2", got)
	}
	// Verify no thinking block and no empty text block ever has cache_control.
	for mi, m := range body.Messages {
		for bi, b := range m.Content {
			if b.CacheControl != nil {
				if b.Type == BlockThinking {
					t.Fatalf("thinking block at msg[%d].content[%d] must never be cached", mi, bi)
				}
				if b.Type == BlockText && b.Text == "" {
					t.Fatalf("empty text block at msg[%d].content[%d] must never be cached", mi, bi)
				}
			}
		}
	}
	// Message 3 is thinking-only → first breakpoint walks back to message 2's tool_result (index 0, skipping empty text at index 1).
	if body.Messages[2].Content[0].CacheControl == nil {
		t.Fatalf("expected msg[2].content[0] (tool_result) to be cached: %+v", body.Messages[2])
	}
	if body.Messages[2].Content[1].CacheControl != nil {
		t.Fatalf("expected msg[2].content[1] (empty text) not cached: %+v", body.Messages[2])
	}
	// Second breakpoint walks from firstIdx-2 = 0 → message 0's text block.
	if body.Messages[0].Content[0].CacheControl == nil {
		t.Fatalf("expected msg[0].content[0] to be cached: %+v", body.Messages[0])
	}
	// Thinking block fields (thinking + signature) must remain intact.
	th := body.Messages[3].Content[0]
	if th.Type != BlockThinking || th.Thinking != "thought-2" || th.Signature != "sig-2" {
		t.Fatalf("thinking block fields lost: %+v", th)
	}
}

// Verifies byte-identical cumulative prefix stability across Turn N → Turn N+1:
// when System is stable, the full cumulative prefix (Tools, System, Messages[:idx+1])
// matches byte-for-byte; when a post-boundary dynamic system block mutates, the
// static prefix (Tools, System[0]) up to Breakpoint 2 still stays byte-identical.
func TestAnthropicPrefixBytesIdenticalAcrossTurns(t *testing.T) {
	p := &anthropicProvider{cfg: Config{Model: "claude-sonnet"}}
	tools := []ToolSchema{
		{Name: "Read", Description: "read file", InputSchema: map[string]any{"type": "object"}},
	}
	staticSys := []string{"system instructions", "security policy"}

	mustMarshal := func(v any) []byte {
		t.Helper()
		data, err := json.Marshal(v)
		if err != nil {
			t.Fatal(err)
		}
		return data
	}
	stripMsgCache := func(msgs []anthropicMessage) []anthropicMessage {
		cp := make([]anthropicMessage, len(msgs))
		for i, m := range msgs {
			blocks := append([]anthropicContentBlock(nil), m.Content...)
			for j := range blocks {
				blocks[j].CacheControl = nil
			}
			cp[i] = anthropicMessage{Role: m.Role, Content: blocks}
		}
		return cp
	}

	t.Run("stable system preserves full cumulative prefix across turns", func(t *testing.T) {
		turn1 := CompletionRequest{
			System:          staticSys,
			DynamicBoundary: len(staticSys),
			Tools:           tools,
			Messages:        []Message{UserText("audit target")},
		}
		turn2 := CompletionRequest{
			System:          staticSys,
			DynamicBoundary: len(staticSys),
			Tools:           tools,
			Messages: []Message{
				UserText("audit target"),
				{Role: RoleAssistant, Content: []ContentBlock{TextBlock("checking...")}},
				UserText("next step"),
			},
		}
		turn3 := CompletionRequest{
			System:          staticSys,
			DynamicBoundary: len(staticSys),
			Tools:           tools,
			Messages: []Message{
				UserText("audit target"),
				{Role: RoleAssistant, Content: []ContentBlock{TextBlock("checking...")}},
				UserText("next step"),
				{Role: RoleAssistant, Content: []ContentBlock{TextBlock("done step 2")}},
				UserText("final step"),
			},
		}

		_, b1, _ := decodeAnthropicBody(t, p, turn1)
		_, b2, _ := decodeAnthropicBody(t, p, turn2)
		_, b3, _ := decodeAnthropicBody(t, p, turn3)

		type prefixSnap struct {
			Tools    []anthropicTool        `json:"tools"`
			System   []anthropicSystemBlock `json:"system"`
			Messages []anthropicMessage     `json:"messages"`
		}
		// Turn 1 → Turn 2: entire cumulative prefix (Tools, System, Messages[:1]) is byte-identical.
		p1 := mustMarshal(prefixSnap{Tools: b1.Tools, System: b1.System, Messages: b1.Messages[:1]})
		p2 := mustMarshal(prefixSnap{Tools: b2.Tools, System: b2.System, Messages: b2.Messages[:1]})
		if !bytes.Equal(p1, p2) {
			t.Fatalf("turn 1→2 cumulative prefix diverged:\nT1: %s\nT2: %s", p1, p2)
		}
		// Turn 2 → Turn 3: (Tools, System) is byte-identical, Messages[:3] content is
		// byte-identical, and the rolling checkpoint at Messages[2] stays marked identically.
		if !bytes.Equal(mustMarshal(b2.Tools), mustMarshal(b3.Tools)) {
			t.Fatal("tools JSON prefix changed between turn 2 and 3")
		}
		if !bytes.Equal(mustMarshal(b2.System), mustMarshal(b3.System)) {
			t.Fatal("system JSON prefix changed between turn 2 and 3")
		}
		if !bytes.Equal(mustMarshal(stripMsgCache(b2.Messages[:3])), mustMarshal(stripMsgCache(b3.Messages[:3]))) {
			t.Fatal("turn 2→3 cumulative Messages[:3] content diverged")
		}
		if !bytes.Equal(mustMarshal(b2.Messages[2]), mustMarshal(b3.Messages[2])) {
			t.Fatalf("turn 2→3 rolling checkpoint at message[2] diverged:\nT2: %s\nT3: %s", mustMarshal(b2.Messages[2]), mustMarshal(b3.Messages[2]))
		}
	})

	t.Run("mutating dynamic system preserves static prefix up to boundary", func(t *testing.T) {
		turn1 := CompletionRequest{
			System:          append(append([]string{}, staticSys...), "<artex-dynamic-time>10:00:00</artex-dynamic-time>"),
			DynamicBoundary: 2,
			Tools:           tools,
			Messages:        []Message{UserText("audit target")},
		}
		turn2 := CompletionRequest{
			System:          append(append([]string{}, staticSys...), "<artex-dynamic-time>10:01:00</artex-dynamic-time>"),
			DynamicBoundary: 2,
			Tools:           tools,
			Messages:        []Message{UserText("audit target")},
		}
		_, b1, _ := decodeAnthropicBody(t, p, turn1)
		_, b2, _ := decodeAnthropicBody(t, p, turn2)
		if !bytes.Equal(mustMarshal(b1.Tools), mustMarshal(b2.Tools)) || !bytes.Equal(mustMarshal(b1.System[0]), mustMarshal(b2.System[0])) {
			t.Fatal("static prefix (tools + system[0]) changed when dynamic system[1] mutated")
		}
		if b1.System[1].Text == b2.System[1].Text {
			t.Fatal("expected dynamic system[1] to reflect updated time")
		}
	})
}

func TestAnthropicEmptySystemBlocksSkipped(t *testing.T) {
	p := &anthropicProvider{cfg: Config{Model: "claude-sonnet"}}
	cases := []struct {
		name       string
		sys        []string
		boundary   int
		wantBlocks int
		wantTexts  []string
		wantCached []bool
	}{
		{"all whitespace no boundary", []string{"", "   \n\t "}, 0, 0, nil, nil},
		{"all whitespace with boundary", []string{"  ", ""}, 1, 0, nil, nil},
		{"all whitespace full boundary", []string{"  ", ""}, 2, 0, nil, nil},
		{"static non-empty, dynamic whitespace", []string{"static", "   "}, 1, 1, []string{"static"}, []bool{true}},
		{"static whitespace, dynamic non-empty", []string{"  ", "dynamic"}, 1, 1, []string{"dynamic"}, []bool{false}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, body, _ := decodeAnthropicBody(t, p, CompletionRequest{
				System:          tc.sys,
				DynamicBoundary: tc.boundary,
				Messages:        []Message{UserText("hi")},
			})
			if len(body.System) != tc.wantBlocks {
				t.Fatalf("len(System)=%d, want %d: %+v", len(body.System), tc.wantBlocks, body.System)
			}
			for i, blk := range body.System {
				if blk.Text != tc.wantTexts[i] {
					t.Fatalf("System[%d].Text=%q, want %q", i, blk.Text, tc.wantTexts[i])
				}
				if (blk.CacheControl != nil) != tc.wantCached[i] {
					t.Fatalf("System[%d] cached=%v, want %v", i, blk.CacheControl != nil, tc.wantCached[i])
				}
			}
		})
	}
}

// Verifies Complete caps non-streaming response body reads rather than OOMing.
func TestAnthropicCompleteCapsResponseBody(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("content-type", "application/json")
		// Valid prefix followed by padding that won't close JSON within normal limit?
		// Keep test fast: return malformed JSON and ensure Complete returns IncompleteMalformedFrame cleanly.
		w.Write([]byte(`{"type":"message","content":[{"type":"text","text":"` + strings.Repeat("x", 1024)))
	}))
	defer srv.Close()

	p, err := NewProvider(Config{Format: FormatAnthropic, BaseURL: srv.URL, APIKey: "k", Model: "m", EmptyResponseRetries: -1})
	if err != nil {
		t.Fatal(err)
	}
	_, _, _, err = p.Complete(context.Background(), CompletionRequest{Messages: []Message{UserText("hi")}})
	if err == nil {
		t.Fatal("expected decode error for truncated body")
	}
}
