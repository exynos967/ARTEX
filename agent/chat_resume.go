package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	"github.com/RC-CHN/ARTEX/db"
	"github.com/RC-CHN/ARTEX/norma/agentcore"
	"github.com/RC-CHN/ARTEX/norma/harness"
	"github.com/RC-CHN/ARTEX/norma/llm"
	"github.com/RC-CHN/ARTEX/norma/transcript"
)

const (
	maxRecoveredActivityRows  = 200
	maxRecoveredHistoryBytes  = 64 << 10 // 64 KiB cap when seeding from DB activities
	maxRecoveredSingleMsgByte = 8 << 10  // 8 KiB cap per reconstructed message
)

// abortedTurnClosureText produces a concise assistant message closing an aborted
// turn whose transcript currently ends on a user/tool_result message. Keeping an
// explicit assistant closure guarantees strict user/assistant alternation across
// Anthropic, OpenAI Chat, and OpenAI Responses gateways and tells the model on
// the next turn that the prior turn was interrupted.
func abortedTurnClosureText(ctx context.Context) string {
	if _, short, _, ok := AbortReason(ctx); ok && strings.TrimSpace(short) != "" {
		return fmt.Sprintf("（本轮回复在完成前被中断：%s。以上对话记录与已返回的工具结果仍然有效，请结合完整历史上下文继续响应后续消息。）", short)
	}
	return "（本轮回复在完成前被中断。以上对话记录与已返回的工具结果仍然有效，请结合完整历史上下文继续响应后续消息。）"
}

// quarantineCorruptTranscript moves a damaged JSONL transcript (and removes its
// sidecar index) so future writes land in a clean file instead of appending
// behind a corrupt line that makes every subsequent Resume fail.
func quarantineCorruptTranscript(tx *transcript.Store, sessionID string) {
	if tx == nil || sessionID == "" {
		return
	}
	path := tx.MainPath(sessionID)
	if _, err := os.Stat(path); err != nil {
		return
	}
	backup := fmt.Sprintf("%s.corrupt-%d", path, time.Now().UnixNano())
	if err := os.Rename(path, backup); err != nil {
		log.Printf("[resume] quarantine corrupt transcript %s failed: %v", path, err)
		return
	}
	_ = os.Remove(transcript.IndexPath(path))
	log.Printf("[resume] quarantined corrupt transcript %s -> %s", path, backup)
}

// resumeTranscriptSession reloads prior conversation history into s. On read or
// parse failure it logs the error and quarantines a corrupted file so recovery
// and subsequent turns persist cleanly.
func resumeTranscriptSession(s *agentcore.Session, tx *transcript.Store, sessionID string) error {
	if s == nil || tx == nil || sessionID == "" {
		return nil
	}
	err := s.Resume(sessionID)
	if err != nil {
		log.Printf("[resume] session %s failed to load transcript: %v", sessionID, err)
		quarantineCorruptTranscript(tx, sessionID)
	}
	return err
}

// ensureAbortedTurnClosed appends a closing assistant notice when a human
// conversational turn was aborted and its persisted transcript still ends with
// a user message (either an unanswered user prompt or an interrupted tool_result).
func ensureAbortedTurnClosed(s *agentcore.Session, ctx context.Context, reason harness.TerminalReason) {
	if s == nil {
		return
	}
	if ctx.Err() == nil && reason != harness.ReasonAbortedStreaming && reason != harness.ReasonAbortedTools {
		return
	}
	msgs := s.Messages()
	if len(msgs) == 0 || msgs[len(msgs)-1].Role != llm.RoleUser {
		return
	}
	s.AppendMessages(llm.Message{
		Role:    llm.RoleAssistant,
		Content: []llm.ContentBlock{llm.TextBlock(abortedTurnClosureText(ctx))},
	})
}

// recordAbortedBeforePrompt handles cancellation that occurs during startup
// (prepareExecution / AugmentTools) before Session.Prompt can record the user
// message or emit a terminal result activity.
func recordAbortedBeforePrompt(tx *transcript.Store, sessionID, message string, ctx context.Context, startedAt time.Time, worker string, emit func(db.Activity)) {
	if emit != nil {
		term := &harness.Terminal{Reason: harness.ReasonAbortedStreaming, Err: ctx.Err()}
		sum, detail := terminalText(ctx, term, &runTrace{startedAt: startedAt})
		emit(db.Activity{
			Worker:  worker,
			Kind:    "result",
			IsError: terminalIsError(ctx, term),
			Summary: firstLine(sum, 400),
			Detail:  detail,
		})
	}
	if tx == nil || sessionID == "" || strings.TrimSpace(message) == "" {
		return
	}
	var lastUUID string
	if active, err := tx.LoadActive(tx.MainPath(sessionID)); err == nil {
		lastUUID = active.LastUUID
	} else {
		log.Printf("[resume] session %s load before startup-abort record failed: %v", sessionID, err)
		quarantineCorruptTranscript(tx, sessionID)
	}
	w := tx.ResumeWriter(sessionID, lastUUID)
	w.RecordMessage(llm.UserText(message), llm.Usage{})
	w.RecordMessage(llm.Message{
		Role:    llm.RoleAssistant,
		Content: []llm.ContentBlock{llm.TextBlock(abortedTurnClosureText(ctx))},
	}, llm.Usage{})
}

// extractUserActivityText extracts plain text from a persisted "user" activity,
// unwrapping the JSON envelope produced by userActivityWithAttachments when present.
func extractUserActivityText(summary, detail string) string {
	raw := strings.TrimSpace(detail)
	if raw == "" {
		return strings.TrimSpace(summary)
	}
	if strings.HasPrefix(raw, "{") {
		var env struct {
			Text        string `json:"text"`
			Attachments []struct {
				Name string `json:"name"`
				Path string `json:"path"`
			} `json:"attachments"`
		}
		if json.Unmarshal([]byte(raw), &env) == nil && (env.Text != "" || len(env.Attachments) > 0) {
			var b strings.Builder
			b.WriteString(strings.TrimSpace(env.Text))
			for _, att := range env.Attachments {
				label := strings.TrimSpace(att.Path)
				if label == "" {
					label = strings.TrimSpace(att.Name)
				}
				if label != "" {
					if b.Len() > 0 {
						b.WriteByte('\n')
					}
					b.WriteString("[附件] ")
					b.WriteString(label)
				}
			}
			return b.String()
		}
	}
	return raw
}

func matchesCurrentUserTurn(userText, summary, currentMessage string) bool {
	cur := strings.TrimSpace(currentMessage)
	if cur == "" {
		return false
	}
	if userText != "" && (cur == userText || strings.HasPrefix(cur, userText)) {
		return true
	}
	if s := strings.TrimSpace(summary); s != "" && firstLine(cur, 200) == s {
		return true
	}
	return false
}

func clampRecoveredText(s string, maxBytes int) string {
	s = strings.TrimSpace(s)
	if maxBytes <= 0 || len(s) <= maxBytes {
		return s
	}
	cut := maxBytes
	for cut > 0 && (s[cut]&0xc0) == 0x80 {
		cut--
	}
	return s[:cut] + "\n…[历史记录过长已截断]"
}

// seedMainHistoryFromActivities rebuilds bounded alternating user/assistant
// history from PostgreSQL activity rows strictly scoped to mainSeg. It runs ONLY
// when the JSONL transcript yielded zero messages (e.g., missing/corrupted file
// or prior rule-mode / unrecorded turns), ensuring Main Agent sees the same
// conversation history already shown in the UI.
func seedMainHistoryFromActivities(s *agentcore.Session, ts *db.ExplorationStore, mainSeg int, currentMessage string) {
	if s == nil || ts == nil || len(s.Messages()) > 0 {
		return
	}
	seg := mainSeg
	rows, _, err := ts.ActivityPage(db.ActivitySessionFilter{Main: true, MainSeg: &seg}, 0, maxRecoveredActivityRows)
	if err != nil || len(rows) == 0 {
		return
	}
	recovered := reconstructHistoryFromActivities(rows, func(id int64) string {
		detail, _ := ts.ActivityDetail(id)
		return detail
	}, currentMessage)
	if len(recovered) == 0 {
		return
	}
	s.AppendMessages(recovered...)
	log.Printf("[resume] seeded %d message(s) for exp%d main seg %d from activity log", len(recovered), ts.ID(), mainSeg)
}

func reconstructHistoryFromActivities(rows []db.Activity, loadDetail func(id int64) string, currentMessage string) []llm.Message {
	if len(rows) == 0 {
		return nil
	}
	detailOf := func(a db.Activity) string {
		if strings.TrimSpace(a.Detail) != "" {
			return a.Detail
		}
		if loadDetail != nil && a.ID > 0 {
			return loadDetail(a.ID)
		}
		return ""
	}
	// server/task_chat.go inserts the current human turn into activity BEFORE
	// invoking MainAgent.Chat. Drop that single trailing user row so we do not
	// duplicate the message that Session.Prompt is about to append.
	if last := rows[len(rows)-1]; last.Kind == "user" {
		userText := extractUserActivityText(last.Summary, detailOf(last))
		if matchesCurrentUserTurn(userText, last.Summary, currentMessage) {
			rows = rows[:len(rows)-1]
		}
	}
	if len(rows) == 0 {
		return nil
	}

	var rawMsgs []llm.Message
	appendMsg := func(role llm.Role, text string) {
		text = clampRecoveredText(text, maxRecoveredSingleMsgByte)
		if text == "" {
			return
		}
		if n := len(rawMsgs); n > 0 && rawMsgs[n-1].Role == role {
			prev := rawMsgs[n-1].Text()
			if prev == text {
				return
			}
			merged := clampRecoveredText(prev+"\n\n"+text, maxRecoveredSingleMsgByte)
			rawMsgs[n-1] = llm.Message{Role: role, Content: []llm.ContentBlock{llm.TextBlock(merged)}}
			return
		}
		rawMsgs = append(rawMsgs, llm.Message{Role: role, Content: []llm.ContentBlock{llm.TextBlock(text)}})
	}

	for _, a := range rows {
		switch a.Kind {
		case "user":
			appendMsg(llm.RoleUser, extractUserActivityText(a.Summary, detailOf(a)))
		case "text", "result":
			body := strings.TrimSpace(detailOf(a))
			if body == "" {
				body = strings.TrimSpace(a.Summary)
			}
			appendMsg(llm.RoleAssistant, body)
		case "tool_use":
			if sum := strings.TrimSpace(a.Summary); sum != "" {
				appendMsg(llm.RoleAssistant, "[已调用工具] "+sum)
			}
		}
	}
	if len(rawMsgs) == 0 {
		return nil
	}
	// Ensure conversation starts with a user turn and ends on an assistant turn
	// so appending the new user message preserves strict alternation.
	for len(rawMsgs) > 0 && rawMsgs[0].Role != llm.RoleUser {
		rawMsgs = rawMsgs[1:]
	}
	if len(rawMsgs) == 0 {
		return nil
	}
	if rawMsgs[len(rawMsgs)-1].Role == llm.RoleUser {
		rawMsgs = append(rawMsgs, llm.Message{
			Role:    llm.RoleAssistant,
			Content: []llm.ContentBlock{llm.TextBlock("（上一轮对话未正常完成或已被中断。）")},
		})
	}
	// Keep the most recent turns within the total byte budget.
	total := 0
	start := len(rawMsgs)
	for i := len(rawMsgs) - 1; i >= 0; i-- {
		sz := len(rawMsgs[i].Text())
		if total+sz > maxRecoveredHistoryBytes && start < len(rawMsgs) {
			break
		}
		total += sz
		start = i
	}
	for start < len(rawMsgs) && rawMsgs[start].Role != llm.RoleUser {
		start++
	}
	if start >= len(rawMsgs) {
		return nil
	}
	return rawMsgs[start:]
}
