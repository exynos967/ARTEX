package agent

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/RC-CHN/ARTEX/db"
	"github.com/RC-CHN/ARTEX/llmrec"
	"github.com/RC-CHN/ARTEX/norma/llm"
)

func TestApprovalHistoryBoundedReverseScanChronologicalOrder(t *testing.T) {
	// Build a 500-message session mixing user text, assistant thinking + text +
	// tool_use, and user tool_result blocks.
	messages := make([]llm.Message, 0, 500)
	var expectedAll []db.InterceptContextEntry

	for i := 0; i < 500; i++ {
		switch i % 3 {
		case 0:
			txt := fmt.Sprintf("user-msg-%d", i)
			messages = append(messages, llm.UserText(txt))
			expectedAll = append(expectedAll, db.InterceptContextEntry{Kind: "user", Text: txt})
		case 1:
			think := fmt.Sprintf("secret-thinking-%d", i)
			txt := fmt.Sprintf("assistant-msg-%d", i)
			toolID := fmt.Sprintf("call-%d", i)
			inJSON := fmt.Sprintf(`{"step":%d}`, i)
			messages = append(messages, llm.Message{
				Role: llm.RoleAssistant,
				Content: []llm.ContentBlock{
					{Type: llm.BlockThinking, Thinking: think},
					llm.TextBlock(txt),
					{Type: llm.BlockToolUse, ID: toolID, Name: "Probe", Input: json.RawMessage(inJSON)},
				},
			})
			expectedAll = append(expectedAll,
				db.InterceptContextEntry{Kind: "assistant", Text: txt},
				db.InterceptContextEntry{Kind: "tool_use", Tool: "Probe", ToolUseID: toolID, Text: inJSON},
			)
		case 2:
			toolID := fmt.Sprintf("call-%d", i-1)
			out := fmt.Sprintf("result-%d", i)
			isErr := i%2 == 0
			messages = append(messages, llm.Message{
				Role: llm.RoleUser,
				Content: []llm.ContentBlock{{
					Type:      llm.BlockToolResult,
					ToolUseID: toolID,
					Content:   []llm.ContentBlock{llm.TextBlock(out)},
					IsError:   isErr,
				}},
			})
			expectedAll = append(expectedAll, db.InterceptContextEntry{
				Kind:      "tool_result",
				ToolUseID: toolID,
				Text:      out,
				IsError:   isErr,
			})
		}
	}

	got := approvalHistory(messages)
	if len(got) != maxApprovalHistoryEntries {
		t.Fatalf("len(approvalHistory)=%d, want %d", len(got), maxApprovalHistoryEntries)
	}
	want := expectedAll[len(expectedAll)-maxApprovalHistoryEntries:]
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("entry[%d] mismatch:\n got: %+v\nwant: %+v", i, got[i], want[i])
		}
		if strings.Contains(got[i].Text, "secret-thinking") {
			t.Fatalf("entry[%d] leaked thinking block: %+v", i, got[i])
		}
	}
}

func TestApprovalHistoryEmptyAndThinkingOnly(t *testing.T) {
	if got := approvalHistory(nil); len(got) != 0 {
		t.Fatalf("nil messages should yield empty history, got %d", len(got))
	}
	msgs := []llm.Message{
		{Role: llm.RoleAssistant, Content: []llm.ContentBlock{{Type: llm.BlockThinking, Thinking: "only thought"}}},
	}
	if got := approvalHistory(msgs); len(got) != 0 {
		t.Fatalf("thinking-only history should be empty, got %+v", got)
	}
}

func TestProviderRoundTripGuardsOversizedRequestCapture(t *testing.T) {
	const reqBytes = 6 << 20 // 6 MiB (> 4 MiB capture cap)
	var serverReceived int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n, _ := io.Copy(io.Discard, r.Body)
		serverReceived = int(n)
		_, _ = io.WriteString(w, "ok")
	}))
	defer srv.Close()

	client, err := quotaAwareHTTPClient("", "")
	if err != nil {
		t.Fatalf("client: %v", err)
	}
	payload := strings.Repeat("p", reqBytes)
	req, err := http.NewRequest(http.MethodPost, srv.URL, strings.NewReader(payload))
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	ctx, capt := llmrec.NewCapture(req.Context())
	req = req.WithContext(ctx)

	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("do: %v", err)
	}
	_, _ = io.ReadAll(resp.Body)
	_ = resp.Body.Close()

	// Outgoing HTTP request delivered to provider must remain untouched (all 6 MiB).
	if serverReceived != reqBytes {
		t.Fatalf("provider received %d bytes, want %d", serverReceived, reqBytes)
	}
	// Captured request must be bounded to ~4 MiB + marker.
	rawReq := capt.RawRequest()
	if len(rawReq) > llmrec.MaxCaptureRequestBytes+64 {
		t.Fatalf("captured request len=%d exceeds 4 MiB cap", len(rawReq))
	}
	if !strings.Contains(rawReq, "truncated by llmrec") {
		t.Fatalf("captured oversized request missing truncation marker")
	}
}
