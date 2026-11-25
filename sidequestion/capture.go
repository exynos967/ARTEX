// Package sidequestion captures immutable main-agent checkpoints. It never owns
// an agent session or a tool executor.
package sidequestion

import (
	"context"
	"encoding/json"
	"fmt"
	"iter"
	"reflect"
	"regexp"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/RC-CHN/ARTEX/norma/harness"
	"github.com/RC-CHN/ARTEX/norma/llm"
	"github.com/RC-CHN/ARTEX/norma/transcript"
)

type Parent struct {
	ConversationID int64 `json:"conversation_id,omitempty"`
	TaskID         int64 `json:"task_id,omitempty"`
	ExplorationID  int64 `json:"exploration_id,omitempty"`
	IntentID       int64 `json:"intent_id,omitempty"`
}

func (p Parent) Key() string {
	if p.ConversationID > 0 {
		return fmt.Sprintf("conv-%d", p.ConversationID)
	}
	if p.IntentID > 0 {
		return fmt.Sprintf("task-%d-exp-%d-worker-i%d", p.TaskID, p.ExplorationID, p.IntentID)
	}
	return fmt.Sprintf("task-%d-exp-%d-main", p.TaskID, p.ExplorationID)
}

// Model contains only configuration identity, never credentials or proxy URLs.
type Model struct {
	ProfileID    int64  `json:"profile_id"`
	Name         string `json:"name"`
	Format       string `json:"format"`
	Model        string `json:"model"`
	Identity     string `json:"identity"`
	Streaming    bool   `json:"streaming"`
	WindowTokens int    `json:"window_tokens"`
}

type Snapshot struct {
	Parent     Parent                `json:"parent"`
	SessionID  string                `json:"session_id,omitempty"`
	RunID      int64                 `json:"run_id"`
	Version    int64                 `json:"version"`
	CapturedAt time.Time             `json:"captured_at"`
	Model      Model                 `json:"model"`
	Request    llm.CompletionRequest `json:"request"`
	Terminal   bool                  `json:"-"`
}

// CloneRequest returns a deep structural copy of req without JSON round-trip overhead.
func CloneRequest(req llm.CompletionRequest) (llm.CompletionRequest, error) {
	return cloneCompletionRequest(req), nil
}

func cloneCompletionRequest(req llm.CompletionRequest) llm.CompletionRequest {
	out := req
	out.System = slices.Clone(req.System)
	out.Stop = slices.Clone(req.Stop)
	if req.Temperature != nil {
		temp := *req.Temperature
		out.Temperature = &temp
	}
	out.Messages = cloneMessages(req.Messages)
	if req.Tools != nil {
		tools := make([]llm.ToolSchema, len(req.Tools))
		for i, tool := range req.Tools {
			tools[i] = cloneToolSchema(tool)
		}
		out.Tools = tools
	}
	return out
}

func cloneMessages(msgs []llm.Message) []llm.Message {
	if msgs == nil {
		return nil
	}
	out := make([]llm.Message, len(msgs))
	for i, m := range msgs {
		out[i] = cloneMessage(m)
	}
	return out
}

func cloneMessage(m llm.Message) llm.Message {
	if m.Content != nil {
		blocks := make([]llm.ContentBlock, len(m.Content))
		for i, b := range m.Content {
			blocks[i] = cloneContentBlock(b)
		}
		m.Content = blocks
	}
	return m
}

func cloneContentBlock(b llm.ContentBlock) llm.ContentBlock {
	if b.Input != nil {
		b.Input = slices.Clone(b.Input)
	}
	if b.Content != nil {
		children := make([]llm.ContentBlock, len(b.Content))
		for i, child := range b.Content {
			children[i] = cloneContentBlock(child)
		}
		b.Content = children
	}
	return b
}

func cloneToolSchema(t llm.ToolSchema) llm.ToolSchema {
	t.InputSchema = cloneStringAnyMap(t.InputSchema)
	return t
}

func cloneStringAnyMap(in map[string]any) map[string]any {
	if in == nil {
		return nil
	}
	out := make(map[string]any, len(in))
	for k, v := range in {
		out[k] = cloneSchemaValue(v)
	}
	return out
}

func cloneSchemaValue(v any) any {
	switch x := v.(type) {
	case nil, string, bool, int, int8, int16, int32, int64, uint, uint8, uint16, uint32, uint64, float32, float64, json.Number:
		return x
	case map[string]any:
		return cloneStringAnyMap(x)
	case []any:
		if x == nil {
			return nil
		}
		out := make([]any, len(x))
		for i, elem := range x {
			out[i] = cloneSchemaValue(elem)
		}
		return out
	case []string:
		return slices.Clone(x)
	case []byte:
		return slices.Clone(x)
	case json.RawMessage:
		return slices.Clone(x)
	case []int:
		return slices.Clone(x)
	case []int64:
		return slices.Clone(x)
	case []float64:
		return slices.Clone(x)
	case []bool:
		return slices.Clone(x)
	case []map[string]any:
		if x == nil {
			return nil
		}
		out := make([]map[string]any, len(x))
		for i, elem := range x {
			out[i] = cloneStringAnyMap(elem)
		}
		return out
	default:
		return cloneReflectValue(reflect.ValueOf(v)).Interface()
	}
}

func cloneReflectValue(rv reflect.Value) reflect.Value {
	if !rv.IsValid() {
		return rv
	}
	switch rv.Kind() {
	case reflect.Map:
		if rv.IsNil() {
			return rv
		}
		out := reflect.MakeMapWithSize(rv.Type(), rv.Len())
		iter := rv.MapRange()
		for iter.Next() {
			out.SetMapIndex(iter.Key(), cloneReflectValue(iter.Value()))
		}
		return out
	case reflect.Slice:
		if rv.IsNil() {
			return rv
		}
		out := reflect.MakeSlice(rv.Type(), rv.Len(), rv.Len())
		for i := 0; i < rv.Len(); i++ {
			out.Index(i).Set(cloneReflectValue(rv.Index(i)))
		}
		return out
	case reflect.Pointer:
		if rv.IsNil() {
			return rv
		}
		out := reflect.New(rv.Type().Elem())
		out.Elem().Set(cloneReflectValue(rv.Elem()))
		return out
	case reflect.Interface:
		if rv.IsNil() {
			return rv
		}
		return cloneReflectValue(rv.Elem())
	default:
		return rv
	}
}

type Publisher func(Snapshot)
type publisherKey struct{}
type sessionIDKey struct{}
type captureKey struct{}
type attemptKey struct{}

func WithPublisher(ctx context.Context, publish Publisher) context.Context {
	return context.WithValue(ctx, publisherKey{}, publish)
}

// WithSessionID attaches the parent agent's exact session ID so captured
// snapshots can preserve sticky routing and KV-cache locality on /btw runs.
func WithSessionID(ctx context.Context, sessionID string) context.Context {
	sessionID = strings.TrimSpace(sessionID)
	if sessionID == "" {
		return ctx
	}
	return context.WithValue(ctx, sessionIDKey{}, sessionID)
}

func sessionIDFromContext(ctx context.Context) string {
	if ctx == nil {
		return ""
	}
	if id, _ := ctx.Value(sessionIDKey{}).(string); strings.TrimSpace(id) != "" {
		return strings.TrimSpace(id)
	}
	return strings.TrimSpace(transcript.SessionIDFrom(ctx))
}

type Capture struct {
	mu        sync.Mutex
	parent    Parent
	sessionID string
	runID     int64
	version   int64
	publish   Publisher
	last      *Snapshot
	lastSent  []llm.Message
	lastResp  *llm.Message
}

// Attach uses QueryDeps rather than a global provider hook so compaction and
// other auxiliary completions cannot replace the main conversation checkpoint.
func Attach(ctx context.Context, parent Parent, deps harness.QueryDeps, provider llm.Provider) (context.Context, harness.QueryDeps) {
	publish, _ := ctx.Value(publisherKey{}).(Publisher)
	if publish == nil {
		return ctx, deps
	}
	c := &Capture{
		parent:    parent,
		sessionID: sessionIDFromContext(ctx),
		runID:     time.Now().UnixNano(),
		publish:   publish,
	}
	stream, complete := deps.CallModel, deps.CallModelSync
	if stream == nil {
		stream = provider.Stream
	}
	if complete == nil {
		complete = provider.Complete
	}
	deps.CallModel = func(ctx context.Context, req llm.CompletionRequest) iter.Seq2[llm.StreamEvent, error] {
		c.observeSessionID(ctx, req)
		return stream(context.WithValue(ctx, attemptKey{}, c), req)
	}
	deps.CallModelSync = func(ctx context.Context, req llm.CompletionRequest) (llm.Message, string, llm.Usage, error) {
		c.observeSessionID(ctx, req)
		return complete(context.WithValue(ctx, attemptKey{}, c), req)
	}
	return context.WithValue(ctx, captureKey{}, c), deps
}

func (c *Capture) observeSessionID(ctx context.Context, req llm.CompletionRequest) {
	id := sessionIDFromContext(ctx)
	if id == "" {
		id = strings.TrimSpace(req.PromptCacheKey)
	}
	if id == "" {
		return
	}
	c.mu.Lock()
	if c.sessionID == "" {
		c.sessionID = id
	}
	c.mu.Unlock()
}

func (c *Capture) save(req llm.CompletionRequest, model Model, terminal bool) {
	copied := cloneCompletionRequest(req)
	c.mu.Lock()
	c.version++
	s := Snapshot{
		Parent:     c.parent,
		SessionID:  c.sessionID,
		RunID:      c.runID,
		Version:    c.version,
		CapturedAt: time.Now().UTC(),
		Model:      model,
		Request:    copied,
		Terminal:   terminal,
	}
	c.last = &s
	c.mu.Unlock()
	c.publish(s)
}

func (c *Capture) saveRequest(req llm.CompletionRequest, model Model) {
	copied := cloneCompletionRequest(req)
	c.mu.Lock()
	c.version++
	c.lastSent = cloneMessages(copied.Messages)
	c.lastResp = nil
	s := Snapshot{
		Parent:     c.parent,
		SessionID:  c.sessionID,
		RunID:      c.runID,
		Version:    c.version,
		CapturedAt: time.Now().UTC(),
		Model:      model,
		Request:    copied,
	}
	c.last = &s
	c.mu.Unlock()
	c.publish(s)
}

func (c *Capture) saveResponse(req llm.CompletionRequest, msg llm.Message, model Model) {
	respCopy := cloneMessage(msg)
	combined := make([]llm.Message, len(req.Messages)+1)
	copy(combined, req.Messages)
	combined[len(req.Messages)] = msg
	req.Messages = llm.MessagesForAPI(combined)
	copied := cloneCompletionRequest(req)
	c.mu.Lock()
	c.version++
	c.lastResp = &respCopy
	s := Snapshot{
		Parent:     c.parent,
		SessionID:  c.sessionID,
		RunID:      c.runID,
		Version:    c.version,
		CapturedAt: time.Now().UTC(),
		Model:      model,
		Request:    copied,
	}
	c.last = &s
	c.mu.Unlock()
	c.publish(s)
}

var trailingNoaRefRE = regexp.MustCompile(`(?:^|\n)<noa-ref\s+id="[^"]+"[^>]*/>\s*$`)

func hasNoaProjection(msgs []llm.Message) bool {
	for _, m := range msgs {
		if messageHasNoaTag(m) {
			return true
		}
	}
	return false
}

func messageHasNoaTag(m llm.Message) bool {
	for _, b := range m.Content {
		if blockHasNoaTag(b) {
			return true
		}
	}
	return false
}

func blockHasNoaTag(b llm.ContentBlock) bool {
	if strings.Contains(b.Text, "<noa-") {
		return true
	}
	for _, child := range b.Content {
		if blockHasNoaTag(child) {
			return true
		}
	}
	return false
}

func stripTrailingNoaRef(s string) string {
	return trailingNoaRefRE.ReplaceAllString(s, "")
}

func messagesEqual(a, b llm.Message) bool {
	if a.Role != b.Role || len(a.Content) != len(b.Content) {
		return false
	}
	for i := range a.Content {
		if !contentBlocksEqual(a.Content[i], b.Content[i], false) {
			return false
		}
	}
	return true
}

func noaProjectedMatchesRaw(projected, raw llm.Message) bool {
	if projected.Role != raw.Role || len(projected.Content) != len(raw.Content) {
		return false
	}
	for i := range projected.Content {
		if !contentBlocksEqual(projected.Content[i], raw.Content[i], true) {
			return false
		}
	}
	return true
}

func contentBlocksEqual(a, b llm.ContentBlock, stripNoa bool) bool {
	if a.Type != b.Type || a.ID != b.ID || a.Name != b.Name || a.ToolUseID != b.ToolUseID ||
		a.IsError != b.IsError || a.Thinking != b.Thinking || a.Signature != b.Signature ||
		string(a.Input) != string(b.Input) {
		return false
	}
	if stripNoa && a.Type == llm.BlockToolResult && a.ToolUseID != "" {
		// ToolUseID uniquely identifies the tool result even when noa truncated
		// or tagged its body.
		return true
	}
	at, bt := a.Text, b.Text
	if stripNoa && a.Type == llm.BlockText {
		at = stripTrailingNoaRef(at)
	}
	if at != bt || len(a.Content) != len(b.Content) {
		return false
	}
	for i := range a.Content {
		if !contentBlocksEqual(a.Content[i], b.Content[i], stripNoa) {
			return false
		}
	}
	return true
}

func sharesToolUseID(a, b llm.Message) bool {
	ids := map[string]bool{}
	for _, blk := range a.Content {
		if blk.Type == llm.BlockToolUse && blk.ID != "" {
			ids[blk.ID] = true
		}
	}
	if len(ids) == 0 {
		return false
	}
	for _, blk := range b.Content {
		if blk.Type == llm.BlockToolUse && ids[blk.ID] {
			return true
		}
	}
	return false
}

func mergeNoaTerminalMessages(basePrefix, fallback []llm.Message, lastResp *llm.Message, rawMessages []llm.Message) []llm.Message {
	apiMsgs := llm.MessagesForAPI(rawMessages)
	if len(apiMsgs) == 0 {
		return cloneMessages(fallback)
	}

	// Anchor 1: match the last assistant message in apiMsgs against the exact
	// model response captured on the final request. Any messages at or after it
	// (the assistant message with its full tool_use blocks + subsequent tool
	// results) are the exact trailing delta after basePrefix.
	if lastResp != nil {
		for i := len(apiMsgs) - 1; i >= 0; i-- {
			if apiMsgs[i].Role == llm.RoleAssistant {
				if messagesEqual(apiMsgs[i], *lastResp) || sharesToolUseID(apiMsgs[i], *lastResp) {
					out := make([]llm.Message, 0, len(basePrefix)+len(apiMsgs)-i)
					out = append(out, cloneMessages(basePrefix)...)
					out = append(out, cloneMessages(apiMsgs[i:])...)
					return llm.PairToolBlocks(out)
				}
				break
			}
		}
	}

	// Anchor 2: locate the last non-synthetic message of basePrefix inside
	// apiMsgs (tolerating trailing <noa-ref .../> tags and noa-truncated tool
	// results) and append only what arrived strictly after it.
	for bi := len(basePrefix) - 1; bi >= 0; bi-- {
		m := basePrefix[bi]
		text := m.Text()
		if strings.HasPrefix(text, "<system-reminder>") || strings.Contains(text, "<noa-archive") {
			continue
		}
		for ri := len(apiMsgs) - 1; ri >= 0; ri-- {
			if noaProjectedMatchesRaw(m, apiMsgs[ri]) {
				out := make([]llm.Message, 0, len(basePrefix)+len(apiMsgs)-ri-1)
				out = append(out, cloneMessages(basePrefix)...)
				out = append(out, cloneMessages(apiMsgs[ri+1:])...)
				return llm.PairToolBlocks(out)
			}
		}
	}

	// Never clobber a noa-projected prefix with raw uncompressed history when no
	// anchor matched (e.g. every prior message was folded into <noa-archive>).
	return cloneMessages(fallback)
}

// Finish adds tool results that landed after the final model request. Norma's
// first API message is its host reminder, absent from Terminal.Messages.
func Finish(ctx context.Context, messages []llm.Message) {
	c, _ := ctx.Value(captureKey{}).(*Capture)
	if c == nil {
		return
	}
	c.mu.Lock()
	s := c.last
	lastSent := cloneMessages(c.lastSent)
	var lastResp *llm.Message
	if c.lastResp != nil {
		cp := cloneMessage(*c.lastResp)
		lastResp = &cp
	}
	c.mu.Unlock()
	if s == nil {
		return
	}
	req := cloneCompletionRequest(s.Request)
	if hasNoaProjection(req.Messages) || hasNoaProjection(lastSent) {
		basePrefix := lastSent
		if len(basePrefix) == 0 {
			basePrefix = req.Messages
		}
		req.Messages = mergeNoaTerminalMessages(basePrefix, req.Messages, lastResp, messages)
		c.save(req, s.Model, true)
		return
	}
	var prefix []llm.Message
	if len(req.Messages) > 0 && strings.HasPrefix(req.Messages[0].Text(), "<system-reminder>") {
		prefix = append(prefix, req.Messages[0])
	}
	req.Messages = append(prefix, llm.MessagesForAPI(messages)...)
	c.save(req, s.Model, true)
}

type boundProvider struct {
	inner llm.Provider
	model Model
}

// Bind belongs immediately around a concrete provider, inside any routing pool.
func Bind(inner llm.Provider, model Model) llm.Provider { return &boundProvider{inner, model} }

func (p *boundProvider) Stream(ctx context.Context, req llm.CompletionRequest) iter.Seq2[llm.StreamEvent, error] {
	return func(yield func(llm.StreamEvent, error) bool) {
		c, _ := ctx.Value(attemptKey{}).(*Capture)
		if c == nil {
			for ev, err := range p.inner.Stream(ctx, req) {
				if !yield(ev, err) {
					return
				}
			}
			return
		}
		c.saveRequest(req, p.model)
		acc := llm.NewAccumulator()
		failed := false
		complete := false
		for ev, err := range p.inner.Stream(ctx, req) {
			if err != nil {
				failed = true
			} else {
				acc.Add(ev)
				if ev.Type == llm.SEMessageStop {
					complete = true
				}
			}
			if !yield(ev, err) {
				return
			}
		}
		if !failed && complete && ctx.Err() == nil {
			c.saveResponse(req, acc.Message(), p.model)
		}
	}
}

func (p *boundProvider) Complete(ctx context.Context, req llm.CompletionRequest) (llm.Message, string, llm.Usage, error) {
	c, _ := ctx.Value(attemptKey{}).(*Capture)
	if c != nil {
		c.saveRequest(req, p.model)
	}
	msg, stop, usage, err := p.inner.Complete(ctx, req)
	if c != nil && err == nil && ctx.Err() == nil {
		c.saveResponse(req, msg, p.model)
	}
	return msg, stop, usage, err
}
