package llm

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestOpenAIPromptCacheKeyResolutionAndBounding(t *testing.T) {
	stubChat := sse(`data: {"choices":[{"index":0,"delta":{"content":"ok"},"finish_reason":"stop"}]}`, ``, `data: [DONE]`, ``)
	stubResp := sse2(
		event("response.output_text.delta", `{"type":"response.output_text.delta","delta":"ok"}`),
		event("response.completed", `{"type":"response.completed","response":{"status":"completed"}}`),
	)

	longKey := strings.Repeat("session-very-long-key-", 5) // > 64 chars

	for _, format := range []Format{FormatOpenAI, FormatOpenAIResponses} {
		t.Run(string(format), func(t *testing.T) {
			stub := stubChat
			if format == FormatOpenAIResponses {
				stub = stubResp
			}
			captureWithCtx := func(ctx context.Context, req CompletionRequest) map[string]any {
				var raw []byte
				srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					raw, _ = io.ReadAll(r.Body)
					w.Write([]byte(stub))
				}))
				defer srv.Close()
				p, err := NewProvider(Config{Format: format, BaseURL: srv.URL, APIKey: "k", Model: "m", EmptyResponseRetries: -1})
				if err != nil {
					t.Fatal(err)
				}
				for _, err := range p.Stream(ctx, req) {
					if err != nil {
						t.Fatalf("stream err: %v", err)
					}
				}
				var m map[string]any
				if err := json.Unmarshal(raw, &m); err != nil {
					t.Fatalf("unmarshal: %v", err)
				}
				return m
			}

			// 1. From context when req.PromptCacheKey is empty.
			m := captureWithCtx(WithPromptCacheKey(context.Background(), "sess-abc"), CompletionRequest{Messages: []Message{UserText("hi")}})
			if m["prompt_cache_key"] != "sess-abc" {
				t.Fatalf("ctx prompt_cache_key=%v, want sess-abc", m["prompt_cache_key"])
			}

			// 2. Explicit req.PromptCacheKey overrides context.
			m = captureWithCtx(WithPromptCacheKey(context.Background(), "from-ctx"), CompletionRequest{PromptCacheKey: "from-req", Messages: []Message{UserText("hi")}})
			if m["prompt_cache_key"] != "from-req" {
				t.Fatalf("explicit prompt_cache_key=%v, want from-req", m["prompt_cache_key"])
			}

			// 3. Long key (> 64 chars) is deterministically hashed to <= 64 chars.
			m1 := captureWithCtx(WithPromptCacheKey(context.Background(), longKey), CompletionRequest{Messages: []Message{UserText("hi")}})
			m2 := captureWithCtx(WithPromptCacheKey(context.Background(), longKey), CompletionRequest{Messages: []Message{UserText("hi")}})
			k1, _ := m1["prompt_cache_key"].(string)
			k2, _ := m2["prompt_cache_key"].(string)
			if len(k1) == 0 || len(k1) > 64 || k1 != k2 {
				t.Fatalf("bounded key invalid: k1=%q (len %d) k2=%q", k1, len(k1), k2)
			}

			// 4. Empty key omits prompt_cache_key.
			m = captureWithCtx(context.Background(), CompletionRequest{Messages: []Message{UserText("hi")}})
			if _, ok := m["prompt_cache_key"]; ok {
				t.Fatalf("prompt_cache_key should be omitted when empty, got %v", m["prompt_cache_key"])
			}
		})
	}
}

// Verifies OpenAI Chat Completions keeps the full system prompt (static prefix
// first, dynamic suffix after) inside the system role message rather than
// demoting dynamic segments into a trailing user message, preserving valid role
// alternation, DeepSeek reasoning continuity, and token-0 prefix caching.
func TestOpenAIChatDynamicBoundaryPrefixPreservation(t *testing.T) {
	p := &openaiProvider{cfg: Config{Model: "gpt-4o"}}

	turn1 := CompletionRequest{
		System:          []string{"static-sys-1", "static-sys-2", "<artex-dynamic-time>10:00:00</artex-dynamic-time>"},
		DynamicBoundary: 2,
		Messages:        []Message{UserText("scan target")},
	}
	turn2 := CompletionRequest{
		System:          []string{"static-sys-1", "static-sys-2", "<artex-dynamic-time>10:01:00</artex-dynamic-time>"},
		DynamicBoundary: 2,
		Messages: []Message{
			UserText("scan target"),
			{Role: RoleAssistant, Content: []ContentBlock{
				{Type: BlockToolUse, ID: "c1", Name: "Bash", Input: json.RawMessage(`{"cmd":"id"}`)},
			}},
			{Role: RoleUser, Content: []ContentBlock{ToolResultText("c1", "uid=0", false)}},
		},
	}

	raw1, err := p.buildBody(turn1, true)
	if err != nil {
		t.Fatal(err)
	}
	raw2, err := p.buildBody(turn2, true)
	if err != nil {
		t.Fatal(err)
	}

	var b1, b2 oaReq
	if err := json.Unmarshal(raw1, &b1); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(raw2, &b2); err != nil {
		t.Fatal(err)
	}

	const wantStaticPrefix = "static-sys-1\n\nstatic-sys-2\n\n"
	if b1.Messages[0].Role != "system" || b1.Messages[0].Content != wantStaticPrefix+"<artex-dynamic-time>10:00:00</artex-dynamic-time>" {
		t.Fatalf("turn1 messages[0]=%+v", b1.Messages[0])
	}
	if b2.Messages[0].Role != "system" || b2.Messages[0].Content != wantStaticPrefix+"<artex-dynamic-time>10:01:00</artex-dynamic-time>" {
		t.Fatalf("turn2 messages[0]=%+v", b2.Messages[0])
	}
	// Static prefix at token 0 is byte-identical across turns.
	if !strings.HasPrefix(b1.Messages[0].Content, wantStaticPrefix) || !strings.HasPrefix(b2.Messages[0].Content, wantStaticPrefix) {
		t.Fatal("static system prefix must remain at the start of messages[0]")
	}
	// No spurious trailing user message demoted from system prompt:
	// turn1 = [system, user], turn2 = [system, user, assistant, tool].
	if len(b1.Messages) != 2 || b1.Messages[1].Role != "user" || b1.Messages[1].Content != "scan target" {
		t.Fatalf("turn1 messages=%+v (must not append demoted user message)", b1.Messages)
	}
	if len(b2.Messages) != 4 || b2.Messages[3].Role != "tool" {
		t.Fatalf("turn2 messages=%+v (must preserve role alternation ending in tool)", b2.Messages)
	}
	assertOpenAIToolOrder(t, b2.Messages)
	// Shared conversation prefix after system stays byte-identical.
	m1, _ := json.Marshal(b1.Messages[1])
	m2, _ := json.Marshal(b2.Messages[1])
	if !bytes.Equal(m1, m2) {
		t.Fatalf("user message diverged across turns:\nT1: %s\nT2: %s", m1, m2)
	}
}

// Verifies OpenAI Responses API keeps the full system prompt (static prefix
// first, dynamic suffix after) in top-level instructions rather than demoting
// dynamic system segments into a trailing user input item.
func TestOpenAIResponsesDynamicBoundaryPrefixPreservation(t *testing.T) {
	p := &openaiResponsesProvider{cfg: Config{Model: "gpt-5"}}

	turn1 := CompletionRequest{
		System:          []string{"static-inst", "<artex-dynamic-time>10:00:00</artex-dynamic-time>"},
		DynamicBoundary: 1,
		Messages:        []Message{UserText("hello")},
	}
	turn2 := CompletionRequest{
		System:          []string{"static-inst", "<artex-dynamic-time>10:05:00</artex-dynamic-time>"},
		DynamicBoundary: 1,
		Messages: []Message{
			UserText("hello"),
			{Role: RoleAssistant, Content: []ContentBlock{TextBlock("hi there")}},
			UserText("follow up"),
		},
	}

	raw1, err := p.buildBody(turn1, true)
	if err != nil {
		t.Fatal(err)
	}
	raw2, err := p.buildBody(turn2, true)
	if err != nil {
		t.Fatal(err)
	}

	var b1, b2 orReq
	if err := json.Unmarshal(raw1, &b1); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(raw2, &b2); err != nil {
		t.Fatal(err)
	}

	if b1.Instructions != "static-inst\n\n<artex-dynamic-time>10:00:00</artex-dynamic-time>" {
		t.Fatalf("b1.Instructions=%q", b1.Instructions)
	}
	if b2.Instructions != "static-inst\n\n<artex-dynamic-time>10:05:00</artex-dynamic-time>" {
		t.Fatalf("b2.Instructions=%q", b2.Instructions)
	}
	// No demoted user item in input.
	if len(b1.Input) != 1 || b1.Input[0].Role != "user" || b1.Input[0].Content != "hello" {
		t.Fatalf("b1.Input=%+v", b1.Input)
	}
	if len(b2.Input) != 3 || b2.Input[2].Role != "user" || b2.Input[2].Content != "follow up" {
		t.Fatalf("b2.Input=%+v", b2.Input)
	}
	if b1.Input[0] != b2.Input[0] {
		t.Fatalf("input[0] prefix diverged: %+v vs %+v", b1.Input[0], b2.Input[0])
	}
}

// Verifies DeepSeek and OpenAI-compatible proxy cache read/write usage parsing
// on BOTH streaming and non-streaming paths.
func TestOpenAICacheUsageMetering(t *testing.T) {
	cases := []struct {
		name      string
		usageJSON string
		want      Usage
	}{
		{
			name:      "openai prompt_tokens_details.cached_tokens",
			usageJSON: `{"prompt_tokens":1000,"completion_tokens":50,"prompt_tokens_details":{"cached_tokens":800}}`,
			want:      Usage{InputTokens: 1000, OutputTokens: 50, CacheReadTokens: 800},
		},
		{
			name:      "deepseek prompt_cache_hit_tokens fallback",
			usageJSON: `{"prompt_tokens":1000,"completion_tokens":50,"prompt_cache_hit_tokens":768,"prompt_cache_miss_tokens":232}`,
			want:      Usage{InputTokens: 1000, OutputTokens: 50, CacheReadTokens: 768, CacheWriteTokens: 0},
		},
		{
			name:      "cached_tokens takes precedence over prompt_cache_hit_tokens",
			usageJSON: `{"prompt_tokens":1000,"completion_tokens":50,"prompt_cache_hit_tokens":100,"prompt_tokens_details":{"cached_tokens":900}}`,
			want:      Usage{InputTokens: 1000, OutputTokens: 50, CacheReadTokens: 900},
		},
		{
			name:      "details cache_write_tokens",
			usageJSON: `{"prompt_tokens":1000,"completion_tokens":40,"prompt_tokens_details":{"cached_tokens":600,"cache_write_tokens":250}}`,
			want:      Usage{InputTokens: 1000, OutputTokens: 40, CacheReadTokens: 600, CacheWriteTokens: 250},
		},
		{
			name:      "details cached_creation_tokens",
			usageJSON: `{"prompt_tokens":1000,"completion_tokens":40,"prompt_tokens_details":{"cached_creation_tokens":300}}`,
			want:      Usage{InputTokens: 1000, OutputTokens: 40, CacheWriteTokens: 300},
		},
		{
			name:      "top-level cache_write_tokens",
			usageJSON: `{"prompt_tokens":500,"completion_tokens":20,"cache_write_tokens":120}`,
			want:      Usage{InputTokens: 500, OutputTokens: 20, CacheWriteTokens: 120},
		},
		{
			name:      "top-level cached_creation_tokens",
			usageJSON: `{"prompt_tokens":500,"completion_tokens":20,"cached_creation_tokens":150}`,
			want:      Usage{InputTokens: 500, OutputTokens: 20, CacheWriteTokens: 150},
		},
		{
			name:      "top-level cache_creation_input_tokens",
			usageJSON: `{"prompt_tokens":500,"completion_tokens":20,"prompt_cache_hit_tokens":300,"cache_creation_input_tokens":180}`,
			want:      Usage{InputTokens: 500, OutputTokens: 20, CacheReadTokens: 300, CacheWriteTokens: 180},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// Streaming frame parser
			_, _, gotStream, hasUsage, malformed, err := parseOpenAIFrameDiagnostics(`{"choices":[],"usage":`+tc.usageJSON+`}`, map[int]bool{})
			if malformed || err != nil || !hasUsage {
				t.Fatalf("stream parse failed: hasUsage=%v malformed=%v err=%v", hasUsage, malformed, err)
			}
			if gotStream != tc.want {
				t.Fatalf("stream usage=%+v, want %+v", gotStream, tc.want)
			}

			// Non-streaming response parser
			_, _, gotComplete, cerr := parseOpenAIResponse([]byte(`{"choices":[{"message":{"content":"ok"},"finish_reason":"stop"}],"usage":`+tc.usageJSON+`}`), nil)
			if cerr != nil {
				t.Fatalf("complete parse failed: %v", cerr)
			}
			if gotComplete != tc.want {
				t.Fatalf("complete usage=%+v, want %+v", gotComplete, tc.want)
			}
		})
	}
}
