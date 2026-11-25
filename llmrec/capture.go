package llmrec

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"sync"
	"unicode/utf8"

	"github.com/RC-CHN/ARTEX/norma/llm"
)

const (
	// MaxCaptureRequestBytes bounds the captured/stored request payload per LLM call.
	MaxCaptureRequestBytes = 4 << 20 // 4 MiB
	// MaxCaptureAttemptBytes bounds captured response bytes for a single HTTP attempt.
	MaxCaptureAttemptBytes = 2 << 20 // 2 MiB
	// MaxCaptureTotalResponseBytes bounds total captured response bytes across all
	// retry attempts of one logical LLM call (and normalized ResponseBody storage).
	MaxCaptureTotalResponseBytes = 4 << 20 // 4 MiB

	requestTruncatedMarker       = "\n...[truncated by llmrec: exceeded 4 MiB]"
	attemptTruncatedMarker       = "\n...[truncated by llmrec: exceeded 2 MiB]"
	totalResponseTruncatedMarker = "\n...[truncated by llmrec: exceeded 4 MiB]"
)

type captureContextKey struct{}

// Capture collects the untouched wire bodies of one logical LLM call. The
// Recorder creates it and puts it on the context; the HTTP transport that norma
// dials through (agent.quotaAwareTransport) finds it there and fills it in.
//
// This exists because everything the Recorder itself sees is already normalized:
// llm.CompletionRequest is re-serialized rather than the body buildBody() sent,
// and the response arrives as decoded StreamEvents, not the SSE frames. For
// debugging a live provider, the bytes on the wire are the only ground truth.
//
// norma's doStream retries the request-establishment phase, so one Stream can
// issue several HTTP attempts. Each attempt is kept: the discarded ones (see
// norma/llm/retry.go, which closes non-final bodies unread) are exactly what
// makes rate-limit and gateway failures diagnosable.
//
// The transport writes from norma's stream-reading goroutine while the Recorder
// snapshots at stream end, so all state is mutex-guarded.
type Capture struct {
	mu             sync.Mutex
	request        string
	attempts       []*attempt
	totalRespBytes int
	totalTruncated bool
}

type attempt struct {
	status    int
	body      strings.Builder
	written   int
	truncated bool
}

// NewCapture returns a context carrying a fresh Capture, plus the Capture itself.
func NewCapture(ctx context.Context) (context.Context, *Capture) {
	c := &Capture{}
	return context.WithValue(ctx, captureContextKey{}, c), c
}

// CaptureFrom returns the Capture attached to ctx, or nil when raw capture is
// off. Callers must tolerate nil — recording is a toggle, and non-recorded
// providers dial through the same transport.
func CaptureFrom(ctx context.Context) *Capture {
	if ctx == nil {
		return nil
	}
	c, _ := ctx.Value(captureContextKey{}).(*Capture)
	return c
}

// SetRequest stores the outgoing request body, capping oversized payloads at
// MaxCaptureRequestBytes on a UTF-8 boundary. Retries re-send identical bytes,
// so only the first attempt's body is kept.
func (c *Capture) SetRequest(body string) {
	if c == nil || body == "" {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.request == "" {
		c.request = capRequestBody(body)
	}
}

// TeeResponse opens a new attempt and wraps rc so everything read from it is
// mirrored into that attempt. It tees rather than reads because a successful
// response is an SSE stream that must keep streaming to the caller.
func (c *Capture) TeeResponse(status int, rc io.ReadCloser) io.ReadCloser {
	if c == nil || rc == nil {
		return rc
	}
	a := &attempt{status: status}
	c.mu.Lock()
	c.attempts = append(c.attempts, a)
	c.mu.Unlock()
	return &teeBody{rc: rc, c: c, a: a}
}

// RawRequest returns the request body as sent, or "" if nothing was captured.
func (c *Capture) RawRequest() string {
	if c == nil {
		return ""
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.request
}

// RawResponse returns the response bytes as received. A single attempt yields
// the untouched original (copy-pasteable straight into a replay); multiple
// attempts are concatenated behind per-attempt header lines so a retry sequence
// stays readable.
func (c *Capture) RawResponse() string {
	if c == nil {
		return ""
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	switch len(c.attempts) {
	case 0:
		return ""
	case 1:
		return c.attempts[0].body.String()
	}
	var b strings.Builder
	for i, a := range c.attempts {
		fmt.Fprintf(&b, "===== attempt %d/%d — HTTP %d =====\n", i+1, len(c.attempts), a.status)
		body := a.body.String()
		b.WriteString(body)
		if !strings.HasSuffix(body, "\n") {
			b.WriteByte('\n')
		}
	}
	return b.String()
}

// Attempt is one HTTP round trip's status code and response bytes.
type Attempt struct {
	Status int
	Body   string
}

// Attempts returns every round trip in order. Unlike RawResponse — which drops
// the header line for a lone attempt so the bytes stay replayable — this always
// carries the status code, for callers that must report "HTTP 401 + body".
func (c *Capture) Attempts() []Attempt {
	if c == nil {
		return nil
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make([]Attempt, 0, len(c.attempts))
	for _, a := range c.attempts {
		out = append(out, Attempt{Status: a.status, Body: a.body.String()})
	}
	return out
}

// teeBody mirrors reads into a Capture attempt, guarded by the Capture's mutex
// so a snapshot taken mid-stream never races the writer. Capture caps never
// alter the (n, err) stream delivered to the caller.
type teeBody struct {
	rc io.ReadCloser
	c  *Capture
	a  *attempt
}

func (t *teeBody) Read(p []byte) (int, error) {
	n, err := t.rc.Read(p)
	if n > 0 {
		t.c.mu.Lock()
		if !t.a.truncated {
			remAttempt := MaxCaptureAttemptBytes - t.a.written
			remTotal := MaxCaptureTotalResponseBytes - t.c.totalRespBytes
			if t.c.totalTruncated {
				remTotal = 0
			}
			rem := remAttempt
			hitTotal := false
			if remTotal < rem {
				rem = remTotal
				hitTotal = true
			}
			switch {
			case rem <= 0:
				marker := attemptTruncatedMarker
				if hitTotal || remTotal <= 0 && remAttempt > 0 {
					marker = totalResponseTruncatedMarker
					t.c.totalTruncated = true
				}
				t.a.body.WriteString(marker)
				t.a.truncated = true
			case n <= rem:
				t.a.body.Write(p[:n])
				t.a.written += n
				t.c.totalRespBytes += n
			default:
				chunk := truncateUTF8Bytes(p[:n], rem)
				t.a.body.Write(chunk)
				t.a.written += len(chunk)
				t.c.totalRespBytes += len(chunk)
				marker := attemptTruncatedMarker
				if hitTotal {
					marker = totalResponseTruncatedMarker
					t.c.totalTruncated = true
				}
				t.a.body.WriteString(marker)
				t.a.truncated = true
			}
		}
		t.c.mu.Unlock()
	}
	return n, err
}

func (t *teeBody) Close() error { return t.rc.Close() }

// capRequestBody bounds body to at most MaxCaptureRequestBytes (including its
// truncation marker) on a UTF-8 rune boundary, making it strictly idempotent.
func capRequestBody(body string) string {
	if len(body) <= MaxCaptureRequestBytes {
		return body
	}
	budget := MaxCaptureRequestBytes - len(requestTruncatedMarker)
	if budget < 0 {
		budget = 0
	}
	return truncateUTF8(body, budget) + requestTruncatedMarker
}

func appendCappedShared(b *strings.Builder, s string, remaining *int, truncated *bool, marker string) {
	if *truncated || s == "" {
		return
	}
	if *remaining <= 0 {
		b.WriteString(marker)
		*truncated = true
		return
	}
	if len(s) <= *remaining {
		b.WriteString(s)
		*remaining -= len(s)
		return
	}
	cut := truncateUTF8(s, *remaining)
	b.WriteString(cut)
	*remaining -= len(cut)
	b.WriteString(marker)
	*truncated = true
}

// marshalCappedResponseBody caps text and thinking within a shared
// MaxCaptureTotalResponseBytes budget BEFORE json.Marshal so ResponseBody is
// always valid JSON and valid UTF-8.
func marshalCappedResponseBody(text, thinking, stopReason string, usage llm.Usage) string {
	mk := func(txt, thk string) []byte {
		resp := map[string]any{
			"text":        txt,
			"stop_reason": stopReason,
			"usage": map[string]int{
				"input_tokens":       usage.InputTokens,
				"output_tokens":      usage.OutputTokens,
				"cache_read_tokens":  usage.CacheReadTokens,
				"cache_write_tokens": usage.CacheWriteTokens,
			},
		}
		if thk != "" {
			resp["thinking"] = thk
		}
		b, _ := json.Marshal(resp)
		return b
	}

	baseThink := ""
	if thinking != "" {
		baseThink = "x"
	}
	overhead := len(mk("", baseThink)) + 32
	budget := MaxCaptureTotalResponseBytes - overhead
	if budget < 0 {
		budget = 0
	}

	curText, curThink := fitPairToBudget(text, thinking, budget)
	encoded := mk(curText, curThink)
	for range 4 {
		if len(encoded) <= MaxCaptureTotalResponseBytes {
			return string(encoded)
		}
		encodedFields := len(encoded) - overhead
		if encodedFields <= 0 || budget <= 0 {
			break
		}
		avail := MaxCaptureTotalResponseBytes - overhead
		nextBudget := int(int64(budget) * int64(avail) / int64(encodedFields))
		nextBudget -= 256
		if nextBudget >= budget {
			nextBudget = budget / 2
		}
		if nextBudget < 0 {
			nextBudget = 0
		}
		budget = nextBudget
		curText, curThink = fitPairToBudget(text, thinking, budget)
		encoded = mk(curText, curThink)
	}
	if len(encoded) > MaxCaptureTotalResponseBytes {
		encoded = mk("", "")
	}
	return string(encoded)
}

func fitPairToBudget(text, thinking string, budget int) (string, string) {
	if len(text)+len(thinking) <= budget {
		return text, thinking
	}
	half := budget / 2
	var textCap, thinkCap int
	switch {
	case len(text) <= half:
		textCap = len(text)
		thinkCap = budget - textCap
	case len(thinking) <= half:
		thinkCap = len(thinking)
		textCap = budget - thinkCap
	default:
		textCap = half
		thinkCap = budget - half
	}
	return capFieldWithMarker(text, textCap, totalResponseTruncatedMarker),
		capFieldWithMarker(thinking, thinkCap, totalResponseTruncatedMarker)
}

func capFieldWithMarker(s string, maxBytes int, marker string) string {
	if len(s) <= maxBytes {
		return s
	}
	if maxBytes <= 0 {
		return ""
	}
	s = strings.TrimSuffix(s, marker)
	if maxBytes <= len(marker) {
		return truncateUTF8(s, maxBytes)
	}
	return truncateUTF8(s, maxBytes-len(marker)) + marker
}

func truncateUTF8(s string, maxBytes int) string {
	if maxBytes <= 0 {
		return ""
	}
	if len(s) <= maxBytes {
		return s
	}
	cut := maxBytes
	for cut > 0 && maxBytes-cut < utf8.UTFMax && !utf8.RuneStart(s[cut]) {
		cut--
	}
	return s[:cut]
}

func truncateUTF8Bytes(b []byte, maxBytes int) []byte {
	if maxBytes <= 0 {
		return nil
	}
	if len(b) <= maxBytes {
		return b
	}
	cut := maxBytes
	for cut > 0 && maxBytes-cut < utf8.UTFMax && !utf8.RuneStart(b[cut]) {
		cut--
	}
	return b[:cut]
}
