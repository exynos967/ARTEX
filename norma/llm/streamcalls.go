package llm

import (
	"encoding/json"
	"strings"
)

// toolCallBuffer holds one tool call while a response streams.
//
// Calls are keyed by their wire index (OpenAI tool_calls[].index, Anthropic
// content block index) because that is all a late argument delta carries. The
// id is what everything downstream routes by.
type toolCallBuffer struct {
	id   string
	name string
	args strings.Builder
}

// streamedToolCalls indexes the tool calls of ONE stream attempt.
//
// A single "current call" buffer is not enough: compatible gateways may
// interleave the argument deltas of parallel calls, and one call's tail then
// lands in another call's JSON — valid responses turn into invalid tool input.
// Per-index buffers make each call assemble from its own fragments regardless
// of the order they arrive in.
type streamedToolCalls struct {
	byIndex map[int]*toolCallBuffer
}

func newStreamedToolCalls() *streamedToolCalls {
	return &streamedToolCalls{byIndex: map[int]*toolCallBuffer{}}
}

// start registers a tool call announced at index. A repeated start for the same
// index keeps the accumulated arguments (some gateways repeat the header).
func (t *streamedToolCalls) start(index int, id, name string) *toolCallBuffer {
	c := t.byIndex[index]
	if c == nil {
		c = &toolCallBuffer{}
		t.byIndex[index] = c
	}
	if id != "" {
		c.id = id
	}
	if name != "" {
		c.name = name
	}
	return c
}

// append adds an argument fragment to the call at index. It returns nil when no
// call was ever started there, so the caller can leave the event unattributed
// instead of guessing.
func (t *streamedToolCalls) append(index int, text string) *toolCallBuffer {
	c := t.byIndex[index]
	if c == nil {
		return nil
	}
	c.args.WriteString(text)
	return c
}

// allValid reports whether every call's arguments may leave the provider
// boundary. A raw-input tool may always: its arguments are its own business.
// requireObject additionally demands a JSON object, which the Anthropic wire
// format does (its tool input is a map, never a bare string or array).
func (t *streamedToolCalls) allValid(rawTools map[string]bool, requireObject bool) bool {
	for _, c := range t.byIndex {
		raw := strings.TrimSpace(c.args.String())
		if raw == "" || rawTools[c.name] {
			continue
		}
		if json.Valid([]byte(raw)) && (!requireObject || strings.HasPrefix(raw, "{")) {
			continue
		}
		return false
	}
	return true
}

// toolPhaseEvent reports whether an event belongs to the tool-call phase. Only
// the end of that phase (text, a stop reason, a terminal marker) makes the
// consumer dispatch, so validation must not run before it: a parallel call may
// still be receiving fragments.
func toolPhaseEvent(t StreamEventType) bool {
	return t == SEToolUseStart || t == SEToolInputJSON
}
