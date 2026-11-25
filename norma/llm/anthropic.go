package llm

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"iter"
	"net/http"
	"strings"
)

type anthropicProvider struct{ cfg Config }

const maxAnthropicCacheBreakpoints = 4

func ephemeralCacheControl() map[string]any {
	return map[string]any{"type": "ephemeral"}
}

type anthropicSystemBlock struct {
	Type         string         `json:"type"`
	Text         string         `json:"text"`
	CacheControl map[string]any `json:"cache_control,omitempty"`
}

// anthropicContentBlock is the Anthropic wire representation of a ContentBlock,
// keeping cache_control strictly at the adapter boundary while llm.Message stays
// vendor-neutral.
type anthropicContentBlock struct {
	Type         BlockType               `json:"type"`
	Text         string                  `json:"text,omitempty"`
	Thinking     string                  `json:"thinking,omitempty"`
	Signature    string                  `json:"signature,omitempty"`
	ID           string                  `json:"id,omitempty"`
	Name         string                  `json:"name,omitempty"`
	Input        json.RawMessage         `json:"input,omitempty"`
	ToolUseID    string                  `json:"tool_use_id,omitempty"`
	Content      []anthropicContentBlock `json:"content,omitempty"`
	IsError      bool                    `json:"is_error,omitempty"`
	CacheControl map[string]any          `json:"cache_control,omitempty"`
}

type anthropicMessage struct {
	Role    Role                    `json:"role"`
	Content []anthropicContentBlock `json:"content"`
}

type anthropicReq struct {
	Model         string                 `json:"model"`
	System        []anthropicSystemBlock `json:"system,omitempty"`
	Messages      []anthropicMessage     `json:"messages"`
	Tools         []anthropicTool        `json:"tools,omitempty"`
	MaxTokens     int                    `json:"max_tokens"`
	Temperature   *float64               `json:"temperature,omitempty"`
	StopSequences []string               `json:"stop_sequences,omitempty"`
	Thinking      *anthropicThinking     `json:"thinking,omitempty"`
	OutputConfig  *anthropicOutputConfig `json:"output_config,omitempty"`
	Stream        bool                   `json:"stream"`
}

// anthropicThinking is the "thinking":{"type":"enabled"|"disabled"} switch.
type anthropicThinking struct {
	Type string `json:"type"`
}

// anthropicOutputConfig carries the reasoning strength via
// "output_config":{"effort":"low"|"medium"|"high"|"max"}.
type anthropicOutputConfig struct {
	Effort string `json:"effort"`
}

type anthropicTool struct {
	Name         string         `json:"name"`
	Description  string         `json:"description"`
	InputSchema  map[string]any `json:"input_schema"`
	CacheControl map[string]any `json:"cache_control,omitempty"`
}

func (p *anthropicProvider) buildBody(req CompletionRequest, stream bool) ([]byte, error) {
	maxTok := req.MaxTokens
	if maxTok == 0 {
		maxTok = 8192
	}
	// Effective thinking mode: a non-empty per-request override (req.Thinking)
	// wins over Config.ThinkingType. Thinking-type content blocks may be replayed
	// only when thinking is actively "enabled"; any other mode (incl. "disabled")
	// strips them so Anthropic does not reject the request.
	thinkingType := p.cfg.ThinkingType
	if req.Thinking != "" {
		thinkingType = req.Thinking
	}
	thinkingEnabled := thinkingType == "enabled"

	usedBreakpoints := 0
	var tools []anthropicTool
	for _, t := range req.Tools {
		tools = append(tools, anthropicTool{Name: t.Name, Description: t.Description, InputSchema: t.InputSchema})
	}
	// Breakpoint 1: mark the last tool definition so the entire tools prefix is cached.
	if len(tools) > 0 && usedBreakpoints < maxAnthropicCacheBreakpoints {
		tools[len(tools)-1].CacheControl = ephemeralCacheControl()
		usedBreakpoints++
	}

	// Breakpoint 2: static system prefix (via buildAnthropicSystem).
	system := buildAnthropicSystem(req)
	for _, sb := range system {
		if sb.CacheControl != nil {
			usedBreakpoints++
		}
	}

	// Breakpoints 3–4: rolling message breakpoints within remaining budget (max 2).
	msgBudget := min(2, max(0, maxAnthropicCacheBreakpoints-usedBreakpoints))
	normalized := mergeAdjacentSameRole(filterThinkingBlocks(req.Messages, thinkingEnabled))

	body := anthropicReq{
		Model:         p.cfg.Model,
		Messages:      buildAnthropicMessages(normalized, msgBudget),
		Tools:         tools,
		MaxTokens:     maxTok,
		Temperature:   req.Temperature,
		StopSequences: req.Stop,
		Stream:        stream,
		System:        system,
	}
	if thinkingType != "" {
		body.Thinking = &anthropicThinking{Type: thinkingType}
	}
	if p.cfg.ReasoningEffort != "" {
		body.OutputConfig = &anthropicOutputConfig{Effort: p.cfg.ReasoningEffort}
	}
	return json.Marshal(body)
}

// buildAnthropicMessages converts normalized vendor-neutral messages into
// Anthropic wire messages and places up to budget rolling ephemeral cache
// breakpoints: on the last cacheable block of the final message, and (when
// budget >= 2 and len >= 3) on the previous turn boundary (firstIdx-2, walking
// back if needed). Thinking blocks and empty text blocks are never marked.
func buildAnthropicMessages(msgs []Message, budget int) []anthropicMessage {
	out := make([]anthropicMessage, len(msgs))
	for i, m := range msgs {
		blocks := make([]anthropicContentBlock, len(m.Content))
		for j, b := range m.Content {
			blocks[j] = convertAnthropicBlock(b)
		}
		out[i] = anthropicMessage{Role: m.Role, Content: blocks}
	}
	if budget <= 0 || len(out) == 0 {
		return out
	}

	firstIdx := -1
	for i := len(out) - 1; i >= 0; i-- {
		if bIdx := lastCacheableAnthropicBlock(out[i].Content); bIdx >= 0 {
			out[i].Content[bIdx].CacheControl = ephemeralCacheControl()
			firstIdx = i
			break
		}
	}
	if budget >= 2 && firstIdx >= 2 {
		for i := firstIdx - 2; i >= 0; i-- {
			if bIdx := lastCacheableAnthropicBlock(out[i].Content); bIdx >= 0 {
				out[i].Content[bIdx].CacheControl = ephemeralCacheControl()
				break
			}
		}
	}
	return out
}

func convertAnthropicBlock(b ContentBlock) anthropicContentBlock {
	ab := anthropicContentBlock{
		Type:      b.Type,
		Text:      b.Text,
		Thinking:  b.Thinking,
		Signature: b.Signature,
		ID:        b.ID,
		Name:      b.Name,
		Input:     b.Input,
		ToolUseID: b.ToolUseID,
		IsError:   b.IsError,
	}
	if len(b.Content) > 0 {
		ab.Content = make([]anthropicContentBlock, len(b.Content))
		for i, inner := range b.Content {
			ab.Content[i] = convertAnthropicBlock(inner)
		}
	}
	return ab
}

func lastCacheableAnthropicBlock(blocks []anthropicContentBlock) int {
	for i := len(blocks) - 1; i >= 0; i-- {
		if isAnthropicCacheableBlock(blocks[i]) {
			return i
		}
	}
	return -1
}

// isAnthropicCacheableBlock reports whether b may carry Anthropic's
// cache_control marker. Thinking blocks and empty text blocks are rejected by
// Anthropic if marked.
func isAnthropicCacheableBlock(b anthropicContentBlock) bool {
	switch b.Type {
	case BlockThinking:
		return false
	case BlockText:
		return b.Text != ""
	default:
		return b.Type != ""
	}
}

// buildAnthropicSystem splits the system prompt at DynamicBoundary, placing a
// cache breakpoint on the static prefix (FR-02.2). Empty/whitespace-only blocks
// are skipped because Anthropic rejects empty text blocks in system.
func buildAnthropicSystem(req CompletionRequest) []anthropicSystemBlock {
	if len(req.System) == 0 {
		return nil
	}
	b := req.DynamicBoundary
	if b <= 0 {
		// No boundary set → no cache breakpoint.
		text := joinSystem(req.System)
		if text == "" {
			return nil
		}
		return []anthropicSystemBlock{{Type: "text", Text: text}}
	}
	if b >= len(req.System) {
		// Boundary at/after the end → the whole system prompt is static; cache it
		// all in one block (an all-static prompt should still be cacheable).
		text := joinSystem(req.System)
		if text == "" {
			return nil
		}
		return []anthropicSystemBlock{{Type: "text", Text: text, CacheControl: ephemeralCacheControl()}}
	}
	var out []anthropicSystemBlock
	if staticText := joinSystem(req.System[:b]); staticText != "" {
		out = append(out, anthropicSystemBlock{Type: "text", Text: staticText, CacheControl: ephemeralCacheControl()})
	}
	if dynamicText := joinSystem(req.System[b:]); dynamicText != "" {
		out = append(out, anthropicSystemBlock{Type: "text", Text: dynamicText})
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func (p *anthropicProvider) Stream(ctx context.Context, req CompletionRequest) iter.Seq2[StreamEvent, error] {
	return func(yield func(StreamEvent, error) bool) {
		body, err := p.buildBody(req, true)
		if err != nil {
			yield(StreamEvent{}, err)
			return
		}
		// Tools that repair their own arguments opt out of the transport's JSON
		// check; every other call with partial arguments stays fatal.
		rawTools := rawInputToolSet(req.Tools)
		for attempt := 0; ; attempt++ {
			resp, err := doStream(ctx, p.cfg, p.cfg.BaseURL+"/v1/messages", body, func(r *http.Request) {
				r.Header.Set("content-type", "application/json")
				r.Header.Set("x-api-key", p.cfg.APIKey)
				r.Header.Set("anthropic-version", p.cfg.APIVersion)
				r.Header.Set("accept", "text/event-stream")
			}, "anthropic")
			if err != nil {
				if !yield(StreamEvent{Type: SEStreamDiagnostics, Diagnostics: &StreamDiagnostics{StreamEnd: StreamEndRequestError}}, nil) {
					return
				}
				yield(StreamEvent{}, incompleteRetryRequestError(ctx, err, attempt))
				return
			}
			scan := newSSEScanner(resp.Body)
			diagnostics := StreamDiagnostics{}
			var stopReason string
			var terminalDelta *StreamEvent
			var incomplete IncompleteResponseReason
			var streamErr error
			var upstreamCause error
			committed, meaningful, observed, consumerStopped := false, false, false, false
			messageStartSeen := false
			var meter anthropicMeter
			var initialUsage Usage
			// One buffer per content-block index: a parallel call's fragments are
			// attributed to its own block, never spliced into a neighbour's JSON.
			calls := newStreamedToolCalls()
			for {
				_, data, serr := scan.next()
				if serr == io.EOF {
					diagnostics.StreamEnd = StreamEndEOF
					break
				}
				if serr != nil {
					if errors.Is(serr, ErrSSEEventTooLarge) {
						diagnostics.StreamEnd = StreamEndProtocolError
						streamErr = serr
						break
					}
					diagnostics.StreamEnd = StreamEndReadError
					incomplete = IncompleteStreamRead
					break
				}
				if strings.TrimSpace(data) == "" {
					continue
				}
				ev, ok, perr, kind, rawUsage := parseAnthropicFrameKind(data)
				if perr != nil {
					diagnostics.StreamEnd = StreamEndProtocolError
					var malformed *IncompleteResponseError
					if errors.As(perr, &malformed) {
						diagnostics.ParseErrors++
						incomplete = IncompleteMalformedFrame
					} else if observed || attempt > 0 {
						incomplete, upstreamCause = IncompleteUpstreamError, perr
					} else {
						streamErr = perr
					}
					break
				}
				if kind == "content_block_stop" && !calls.allValid(rawTools, true) {
					diagnostics.StreamEnd = StreamEndProtocolError
					incomplete = IncompleteInvalidToolInput
					break
				}
				if !ok {
					continue
				}
				if ev.Type == SEMessageStart {
					// A compatible gateway may repeat the start header in one HTTP
					// response. Only its first header defines this attempt's initial
					// usage/boundary; message_delta may later correct that estimate.
					// Ignore duplicates before they can finalize a pending tool.
					if messageStartSeen {
						continue
					}
					messageStartSeen = true
					meter.update(rawUsage)
					meter.output = 0 // The start count is a placeholder.
					initialUsage = meter.usage()
					ev.Usage = initialUsage
				}
				if ev.Type == SEMessageDelta {
					// This event is a tool boundary in the harness. Buffer it until
					// the response is validated; input usage already streamed above.
					if ev.StopReason != "" {
						stopReason = ev.StopReason
						diagnostics.FinishReasonSeen = true
					}
					copy := ev
					copy.StopReason = stopReason
					// Correct the initial estimate once per HTTP attempt. A negative
					// difference is intentional when the final input count is lower.
					meter.update(rawUsage)
					copy.Usage = meter.usage()
					copy.Usage.InputTokens -= initialUsage.InputTokens
					copy.Usage.CacheReadTokens -= initialUsage.CacheReadTokens
					copy.Usage.CacheWriteTokens -= initialUsage.CacheWriteTokens
					terminalDelta = &copy
					continue
				}
				if ev.Type == SEMessageStop {
					diagnostics.StreamEnd = StreamEndDone
					break
				}
				if !toolPhaseEvent(ev.Type) && !calls.allValid(rawTools, true) {
					diagnostics.StreamEnd = StreamEndProtocolError
					incomplete = IncompleteInvalidToolInput
					break
				}
				switch ev.Type {
				case SEToolUseStart:
					calls.start(ev.Index, ev.ToolID, ev.ToolName)
					committed, meaningful, observed = true, true, true
				case SEToolInputJSON:
					committed, observed = true, true
					if c := calls.append(ev.Index, ev.Text); c != nil {
						ev.ToolID = c.id
					} else {
						// Fragments for a block that never started: the stream is
						// out of order in a way no repair is possible for.
						diagnostics.StreamEnd = StreamEndProtocolError
						incomplete = IncompleteInvalidToolInput
					}
				case SETextDelta:
					committed = committed || ev.Text != ""
					observed = observed || ev.Text != ""
					meaningful = meaningful || strings.TrimSpace(ev.Text) != ""
				case SEThinkingDelta, SEThinkingSignature:
					observed = observed || ev.Text != ""
				}
				initialInput := ""
				if ev.Type == SEToolUseStart {
					// Anthropic normally starts with input:{}, then streams JSON.
					// Compatible gateways may put the full input on the start frame.
					initialInput, ev.Text = ev.Text, ""
				}
				if !yield(ev, nil) {
					consumerStopped = true
					break
				}
				if initialInput != "" {
					// Attribute the start-frame input to its own block before it is
					// exposed as a delta, so validation sees one consistent buffer.
					calls.append(ev.Index, initialInput)
					if !yield(StreamEvent{Type: SEToolInputJSON, Text: initialInput, Index: ev.Index, ToolID: ev.ToolID}, nil) {
						consumerStopped = true
						break
					}
				}
				if incomplete != "" {
					break
				}
			}
			resp.Body.Close()
			if consumerStopped {
				return
			}
			if incomplete == "" && streamErr == nil {
				if diagnostics.StreamEnd == StreamEndEOF && !diagnostics.FinishReasonSeen {
					incomplete = IncompleteMissingTerminal
				} else if !calls.allValid(rawTools, true) {
					incomplete = IncompleteInvalidToolInput
				} else if !meaningful && stopReason != "max_tokens" {
					incomplete = IncompleteEmptyOutput
				}
			}
			retryable := incomplete == IncompleteEmptyOutput || incomplete == IncompleteMissingTerminal || incomplete == IncompleteStreamRead
			retryIncomplete := retryable && !committed && isEmptyResponseRetryable(stopReason) && attempt < p.cfg.emptyRetries() && ctx.Err() == nil
			diagnostics.DiscardThinking = retryIncomplete
			// A failed attempt reports its buffered metering corrections via metadata,
			// which cannot dispatch the still-pending tool.
			var pendingUsage Usage
			if terminalDelta != nil {
				pendingUsage = terminalDelta.Usage
			}
			if incomplete == "" && streamErr == nil && ctx.Err() == nil && terminalDelta != nil {
				if !yield(*terminalDelta, nil) {
					return
				}
				pendingUsage = Usage{}
			}
			if !yield(StreamEvent{Type: SEStreamDiagnostics, StopReason: stopReason, Usage: pendingUsage, Diagnostics: &diagnostics}, nil) {
				return
			}
			if ctx.Err() != nil {
				yield(StreamEvent{}, ctx.Err())
				return
			}
			if streamErr != nil {
				yield(StreamEvent{}, streamErr)
				return
			}
			if retryIncomplete {
				if !backoffSleep(ctx, p.cfg.emptyRetryDelay(attempt)) {
					yield(StreamEvent{}, ctx.Err())
					return
				}
				continue
			}
			if incomplete != "" {
				yield(StreamEvent{}, &IncompleteResponseError{Reason: incomplete, StopReason: stopReason, Diagnostics: diagnostics, cause: upstreamCause})
				return
			}
			yield(StreamEvent{Type: SEMessageStop}, nil)
			return
		}
	}
}

// Complete preserves the same bounded incomplete-response handling as Stream.
func (p *anthropicProvider) Complete(ctx context.Context, req CompletionRequest) (Message, string, Usage, error) {
	body, err := p.buildBody(req, false)
	if err != nil {
		return Message{}, "", Usage{}, err
	}
	var totalUsage Usage
	var lastPartial Message
	for attempt := 0; ; attempt++ {
		resp, err := doStream(ctx, p.cfg, p.cfg.BaseURL+"/v1/messages", body, func(r *http.Request) {
			r.Header.Set("content-type", "application/json")
			r.Header.Set("x-api-key", p.cfg.APIKey)
			r.Header.Set("anthropic-version", p.cfg.APIVersion)
			r.Header.Set("accept", "application/json")
		}, "anthropic")
		if err != nil {
			return lastPartial, "", totalUsage, incompleteRetryRequestError(ctx, err, attempt)
		}
		raw, rerr := io.ReadAll(io.LimitReader(resp.Body, maxResponseBodyBytes))
		resp.Body.Close()
		if rerr != nil {
			if ctx.Err() != nil {
				return lastPartial, "", totalUsage, ctx.Err()
			}
			return lastPartial, "", totalUsage, &IncompleteResponseError{Reason: IncompleteStreamRead, Diagnostics: StreamDiagnostics{StreamEnd: StreamEndReadError}}
		}
		msg, stop, usage, perr := parseAnthropicResponse(raw, rawInputToolSet(req.Tools))
		totalUsage.Add(usage)
		if ctx.Err() != nil {
			return msg, stop, totalUsage, ctx.Err()
		}
		if perr != nil {
			var incomplete *IncompleteResponseError
			if attempt > 0 && !errors.As(perr, &incomplete) {
				return lastPartial, stop, totalUsage, &IncompleteResponseError{Reason: IncompleteRetryRequest, StopReason: stop, Diagnostics: StreamDiagnostics{StreamEnd: StreamEndEOF}, cause: perr}
			}
			return msg, stop, totalUsage, perr
		}
		empty := strings.TrimSpace(msg.Text()) == "" && len(msg.ToolUses()) == 0 && stop != "max_tokens"
		if empty && isEmptyResponseRetryable(stop) && attempt < p.cfg.emptyRetries() {
			lastPartial = msg
			if !backoffSleep(ctx, p.cfg.emptyRetryDelay(attempt)) {
				return msg, stop, totalUsage, ctx.Err()
			}
			continue
		}
		if empty {
			return msg, stop, totalUsage, &IncompleteResponseError{Reason: IncompleteEmptyOutput, StopReason: stop, Diagnostics: StreamDiagnostics{FinishReasonSeen: stop != "", StreamEnd: StreamEndEOF}}
		}
		return msg, stop, totalUsage, nil
	}
}

// parseAnthropicResponse decodes a non-streaming Messages API response into the
// neutral Message model. Anthropic already speaks the content-block shape, so
// text/thinking/tool_use blocks map across directly.
func parseAnthropicResponse(raw []byte, rawTools map[string]bool) (Message, string, Usage, error) {
	var r struct {
		Type    string `json:"type"`
		Content []struct {
			Type      string          `json:"type"`
			Text      string          `json:"text"`
			Thinking  string          `json:"thinking"`
			Signature string          `json:"signature"`
			ID        string          `json:"id"`
			Name      string          `json:"name"`
			Input     json.RawMessage `json:"input"`
		} `json:"content"`
		StopReason string          `json:"stop_reason"`
		Usage      *anthropicUsage `json:"usage"`
		Error      *struct {
			Type    string `json:"type"`
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.Unmarshal(raw, &r); err != nil {
		return Message{}, "", Usage{}, &IncompleteResponseError{Reason: IncompleteMalformedFrame, Diagnostics: StreamDiagnostics{StreamEnd: StreamEndProtocolError, ParseErrors: 1}}
	}
	if r.Error != nil || r.Type == "error" {
		msg := "error response"
		if r.Error != nil {
			msg = r.Error.Message
		}
		return Message{}, "", Usage{}, fmt.Errorf("anthropic: %s", msg)
	}
	var usage Usage
	if r.Usage != nil {
		usage = r.Usage.norm()
	}
	var blocks []ContentBlock
	invalidToolInput := false
	for _, b := range r.Content {
		switch b.Type {
		case "text":
			if b.Text != "" {
				blocks = append(blocks, TextBlock(b.Text))
			}
		case "thinking":
			blocks = append(blocks, ContentBlock{Type: BlockThinking, Thinking: b.Thinking, Signature: b.Signature})
		case "tool_use":
			in := b.Input
			if len(in) == 0 {
				in = json.RawMessage("{}")
			}
			if raw := strings.TrimSpace(string(in)); (!json.Valid(in) || !strings.HasPrefix(raw, "{")) && !rawTools[b.Name] {
				invalidToolInput = true
			}
			blocks = append(blocks, ContentBlock{Type: BlockToolUse, ID: b.ID, Name: b.Name, Input: in})
		}
	}
	msg := Message{Role: RoleAssistant, Content: blocks}
	if invalidToolInput {
		return msg, r.StopReason, usage, &IncompleteResponseError{Reason: IncompleteInvalidToolInput, StopReason: r.StopReason, Diagnostics: StreamDiagnostics{StreamEnd: StreamEndEOF, FinishReasonSeen: r.StopReason != ""}}
	}
	return msg, r.StopReason, usage, nil
}

func parseAnthropicFrame(data string) (StreamEvent, bool, error) {
	ev, ok, err, _, _ := parseAnthropicFrameKind(data)
	return ev, ok, err
}

func parseAnthropicFrameKind(data string) (ev StreamEvent, ok bool, err error, kind string, usage *anthropicUsage) {
	var f struct {
		Type string `json:"type"`
		// Index is the content block's position in the message. Argument deltas
		// carry only this, so it is what attributes them to the right tool call.
		Index        int `json:"index"`
		ContentBlock struct {
			Type     string          `json:"type"`
			ID       string          `json:"id"`
			Name     string          `json:"name"`
			Input    json.RawMessage `json:"input"`
			Text     string          `json:"text"`
			Thinking string          `json:"thinking"`
		} `json:"content_block"`
		Delta struct {
			Type        string `json:"type"`
			Text        string `json:"text"`
			PartialJSON string `json:"partial_json"`
			Thinking    string `json:"thinking"`
			Signature   string `json:"signature"`
			StopReason  string `json:"stop_reason"`
		} `json:"delta"`
		Usage   *anthropicUsage `json:"usage"`
		Message struct {
			Usage *anthropicUsage `json:"usage"`
		} `json:"message"`
		Error *struct {
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.Unmarshal([]byte(data), &f); err != nil {
		return StreamEvent{}, false, &IncompleteResponseError{Reason: IncompleteMalformedFrame}, "", nil
	}
	switch f.Type {
	case "message_start":
		if f.Message.Usage != nil {
			// Emit the initial input estimate immediately. Stream reconciles any
			// later cumulative usage; the initial output count is a placeholder.
			u := f.Message.Usage.norm()
			u.OutputTokens = 0
			return StreamEvent{Type: SEMessageStart, Usage: u}, true, nil, f.Type, f.Message.Usage
		}
		// The attempt boundary is meaningful even when a compatible gateway
		// omits usage; it clears stale stop evidence without inventing tokens.
		return StreamEvent{Type: SEMessageStart}, true, nil, f.Type, nil
	case "content_block_start":
		if f.ContentBlock.Type == "tool_use" {
			initial := strings.TrimSpace(string(f.ContentBlock.Input))
			var initialObject map[string]json.RawMessage
			if json.Unmarshal(f.ContentBlock.Input, &initialObject) == nil && initialObject != nil && len(initialObject) == 0 {
				initial = ""
			}
			// Text is internal to this parser until Stream emits the start and
			// its initial input as separate normalized events.
			return StreamEvent{Type: SEToolUseStart, ToolID: f.ContentBlock.ID, ToolName: f.ContentBlock.Name, Text: initial, Index: f.Index}, true, nil, f.Type, nil
		}
		if f.ContentBlock.Type == "text" && f.ContentBlock.Text != "" {
			return StreamEvent{Type: SETextDelta, Text: f.ContentBlock.Text}, true, nil, f.Type, nil
		}
		if f.ContentBlock.Type == "thinking" && f.ContentBlock.Thinking != "" {
			return StreamEvent{Type: SEThinkingDelta, Text: f.ContentBlock.Thinking}, true, nil, f.Type, nil
		}
	case "content_block_delta":
		switch f.Delta.Type {
		case "text_delta":
			return StreamEvent{Type: SETextDelta, Text: f.Delta.Text}, true, nil, f.Type, nil
		case "thinking_delta":
			return StreamEvent{Type: SEThinkingDelta, Text: f.Delta.Thinking}, true, nil, f.Type, nil
		case "signature_delta":
			return StreamEvent{Type: SEThinkingSignature, Text: f.Delta.Signature}, true, nil, f.Type, nil
		case "input_json_delta":
			return StreamEvent{Type: SEToolInputJSON, Text: f.Delta.PartialJSON, Index: f.Index}, true, nil, f.Type, nil
		}
	case "message_delta":
		ev := StreamEvent{Type: SEMessageDelta, StopReason: f.Delta.StopReason}
		if f.Usage != nil {
			ev.Usage = f.Usage.norm()
		}
		return ev, true, nil, f.Type, f.Usage
	case "message_stop":
		return StreamEvent{Type: SEMessageStop}, true, nil, f.Type, nil
	case "error":
		msg := "stream error"
		if f.Error != nil {
			msg = f.Error.Message
		}
		return StreamEvent{}, false, fmt.Errorf("anthropic: %s", msg), f.Type, nil
	}
	return StreamEvent{}, false, nil, f.Type, nil
}

// filterThinkingBlocks normalizes message history before it is sent to the
// Anthropic Messages API. It strips thinking-type content blocks when thinking
// is disabled (Anthropic rejects replayed thinking blocks without the thinking
// parameter enabled), and drops any message left with no content blocks —
// Anthropic rejects an empty content array. An empty message arrives here two
// ways: a thinking-only turn that collapses to empty once thinking is stripped,
// or an empty/truncated assistant turn (only reasoning, or nothing) that was
// recorded with no text or tool_use. (A thinking-only turn WITH thinking
// enabled keeps its thinking block — that is valid content and must be
// replayed.)
func filterThinkingBlocks(msgs []Message, thinkingEnabled bool) []Message {
	out := make([]Message, 0, len(msgs))
	for _, m := range msgs {
		content := m.Content
		if !thinkingEnabled {
			filtered := make([]ContentBlock, 0, len(content))
			for _, b := range content {
				if b.Type != BlockThinking {
					filtered = append(filtered, b)
				}
			}
			content = filtered
		}
		if len(content) == 0 {
			continue // empty content array is rejected by Anthropic — drop it
		}
		if len(content) == len(m.Content) {
			out = append(out, m)
		} else {
			out = append(out, Message{Role: m.Role, Content: content})
		}
	}
	return out
}

// mergeAdjacentSameRole coalesces consecutive same-role messages into one by
// concatenating their content blocks. Anthropic requires messages to alternate
// user/assistant; dropping an empty turn in filterThinkingBlocks can leave two
// adjacent user messages (e.g. a tool result followed by a resume nudge, once
// the empty assistant between them is gone), which the API would reject with
// "roles must alternate". Merging preserves alternation without losing content.
// A fresh content slice is built on merge so the caller's message backing
// arrays are never mutated.
func mergeAdjacentSameRole(msgs []Message) []Message {
	out := make([]Message, 0, len(msgs))
	for _, m := range msgs {
		if n := len(out); n > 0 && out[n-1].Role == m.Role {
			merged := make([]ContentBlock, 0, len(out[n-1].Content)+len(m.Content))
			merged = append(merged, out[n-1].Content...)
			merged = append(merged, m.Content...)
			out[n-1].Content = merged
			continue
		}
		out = append(out, m)
	}
	return out
}
