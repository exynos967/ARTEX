package llmrec

import (
	"context"
	"encoding/json"
	"io"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/RC-CHN/ARTEX/norma/llm"
)

func TestCaptureFromNilAndMissing(t *testing.T) {
	var nilCtx context.Context // the transport reaches here on any unrecorded call
	if CaptureFrom(nilCtx) != nil {
		t.Fatal("nil context should yield no capture")
	}
	if CaptureFrom(context.Background()) != nil {
		t.Fatal("bare context should yield no capture")
	}
}

// A nil *Capture is the "recording off" path: the transport calls these on every
// request, so they must all be no-ops rather than panics.
func TestNilCaptureIsInert(t *testing.T) {
	var c *Capture
	c.SetRequest("body")
	if got := c.RawRequest(); got != "" {
		t.Fatalf("RawRequest()=%q want empty", got)
	}
	if got := c.RawResponse(); got != "" {
		t.Fatalf("RawResponse()=%q want empty", got)
	}
	rc := io.NopCloser(strings.NewReader("x"))
	if c.TeeResponse(200, rc) != rc {
		t.Fatal("nil capture must pass the body through untouched")
	}
}

func TestCaptureSingleAttemptKeepsBytesVerbatim(t *testing.T) {
	ctx, c := NewCapture(context.Background())
	if CaptureFrom(ctx) != c {
		t.Fatal("capture not retrievable from its own context")
	}
	c.SetRequest(`{"model":"x"}`)
	// Retries re-send identical bytes; only the first is kept.
	c.SetRequest(`{"model":"ignored"}`)

	const sse = "event: message_start\ndata: {\"type\":\"message_start\"}\n\nevent: message_stop\ndata: {}\n\n"
	body := c.TeeResponse(200, io.NopCloser(strings.NewReader(sse)))
	got, err := io.ReadAll(body)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(got) != sse {
		t.Fatal("tee altered the stream delivered to the caller")
	}
	if err := body.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	if c.RawRequest() != `{"model":"x"}` {
		t.Fatalf("RawRequest()=%q", c.RawRequest())
	}
	// A lone attempt must stay byte-identical — no headers, no framing added, so
	// it can be replayed as-is.
	if c.RawResponse() != sse {
		t.Fatalf("RawResponse()=%q want verbatim SSE", c.RawResponse())
	}
}

// norma's doStream discards the bodies of retried attempts (retry.go closes them
// unread), so the capture is the only place a 429 body survives.
func TestCaptureRetriedAttemptsAreAllKept(t *testing.T) {
	_, c := NewCapture(context.Background())

	first := c.TeeResponse(429, io.NopCloser(strings.NewReader(`{"error":"rate_limit"}`)))
	if _, err := io.ReadAll(first); err != nil {
		t.Fatalf("read first: %v", err)
	}
	second := c.TeeResponse(200, io.NopCloser(strings.NewReader("data: ok\n")))
	if _, err := io.ReadAll(second); err != nil {
		t.Fatalf("read second: %v", err)
	}

	raw := c.RawResponse()
	if !strings.Contains(raw, `{"error":"rate_limit"}`) {
		t.Fatalf("dropped the retried attempt body: %q", raw)
	}
	if !strings.Contains(raw, "data: ok") {
		t.Fatalf("dropped the final attempt body: %q", raw)
	}
	if !strings.Contains(raw, "attempt 1/2 — HTTP 429") || !strings.Contains(raw, "attempt 2/2 — HTTP 200") {
		t.Fatalf("attempts not delimited: %q", raw)
	}
	if strings.Index(raw, "rate_limit") > strings.Index(raw, "data: ok") {
		t.Fatal("attempts stored out of order")
	}
}

func TestCaptureEmptyWhenNoHTTPHappened(t *testing.T) {
	_, c := NewCapture(context.Background())
	if c.RawRequest() != "" || c.RawResponse() != "" {
		t.Fatal("unused capture should be empty")
	}
}

func TestCaptureRequestCapTruncatesOnUTF8Boundary(t *testing.T) {
	_, c := NewCapture(context.Background())
	// Place a 3-byte UTF-8 rune ('中') right across the request budget boundary
	// (MaxCaptureRequestBytes - len(requestTruncatedMarker) - 1), padded to 10 MiB.
	budget := MaxCaptureRequestBytes - len(requestTruncatedMarker)
	var b strings.Builder
	b.Grow(10 << 20)
	b.WriteString(strings.Repeat("a", budget-1))
	b.WriteString("中")
	b.WriteString(strings.Repeat("b", (10<<20)-b.Len()))
	c.SetRequest(b.String())

	got := c.RawRequest()
	if len(got) > MaxCaptureRequestBytes {
		t.Fatalf("len(RawRequest)=%d > MaxCaptureRequestBytes=%d", len(got), MaxCaptureRequestBytes)
	}
	if !strings.HasSuffix(got, requestTruncatedMarker) {
		t.Fatalf("missing request truncation marker at end of RawRequest (len=%d)", len(got))
	}
	if !utf8.ValidString(got) {
		t.Fatal("truncated RawRequest split a multi-byte UTF-8 rune")
	}
	prefix := strings.TrimSuffix(got, requestTruncatedMarker)
	if len(prefix) != budget-1 {
		t.Fatalf("UTF-8 boundary cut=%d, want %d (just before straddling rune)", len(prefix), budget-1)
	}
	// capRequestBody must be strictly idempotent and never append a second marker.
	if again := capRequestBody(got); again != got {
		t.Fatalf("capRequestBody is not idempotent: len1=%d len2=%d", len(got), len(again))
	}
}

func TestCaptureSingleResponseCapPreservesLiveStream(t *testing.T) {
	_, c := NewCapture(context.Background())
	const totalBytes = 6 << 20 // 6 MiB
	payload := strings.Repeat("0123456789abcdef", totalBytes/16)

	rc := c.TeeResponse(200, io.NopCloser(strings.NewReader(payload)))
	gotStream, err := io.ReadAll(rc)
	if err != nil {
		t.Fatalf("read live stream: %v", err)
	}
	if err := rc.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	// Live stream delivered to the caller MUST be 100% intact.
	if len(gotStream) != totalBytes || string(gotStream) != payload {
		t.Fatalf("live stream altered: got %d bytes, want %d", len(gotStream), totalBytes)
	}

	raw := c.RawResponse()
	if !strings.HasSuffix(raw, attemptTruncatedMarker) {
		t.Fatalf("missing per-attempt truncation marker in RawResponse (len=%d)", len(raw))
	}
	if strings.Count(raw, attemptTruncatedMarker) != 1 {
		t.Fatalf("marker appended %d times, want 1", strings.Count(raw, attemptTruncatedMarker))
	}
	if len(raw) > MaxCaptureAttemptBytes+len(attemptTruncatedMarker) {
		t.Fatalf("RawResponse len=%d exceeds cap %d", len(raw), MaxCaptureAttemptBytes+len(attemptTruncatedMarker))
	}
}

func TestCaptureRetryAttemptsCapTotalResponseBytes(t *testing.T) {
	_, c := NewCapture(context.Background())
	const perAttempt = 1536 << 10 // 1.5 MiB
	const attemptCount = 5

	for i := 0; i < attemptCount; i++ {
		bodyStr := strings.Repeat(string(rune('A'+i)), perAttempt)
		rc := c.TeeResponse(502, io.NopCloser(strings.NewReader(bodyStr)))
		got, err := io.ReadAll(rc)
		if err != nil {
			t.Fatalf("attempt %d read: %v", i+1, err)
		}
		_ = rc.Close()
		if len(got) != perAttempt || string(got) != bodyStr {
			t.Fatalf("attempt %d live stream altered: len=%d want %d", i+1, len(got), perAttempt)
		}
	}

	attempts := c.Attempts()
	if len(attempts) != attemptCount {
		t.Fatalf("attempts=%d want %d", len(attempts), attemptCount)
	}
	// Attempts 1 & 2 (1.5 + 1.5 = 3.0 MiB) fit verbatim.
	if len(attempts[0].Body) != perAttempt || len(attempts[1].Body) != perAttempt {
		t.Fatalf("attempts 1/2 unexpectedly truncated: %d, %d", len(attempts[0].Body), len(attempts[1].Body))
	}
	// Attempt 3 hits the 4 MiB total cap after 1.0 MiB.
	if !strings.HasSuffix(attempts[2].Body, totalResponseTruncatedMarker) {
		t.Fatalf("attempt 3 missing total truncation marker")
	}
	if len(attempts[2].Body) != (1<<20)+len(totalResponseTruncatedMarker) {
		t.Fatalf("attempt 3 len=%d want %d", len(attempts[2].Body), (1<<20)+len(totalResponseTruncatedMarker))
	}
	// Attempts 4 & 5 capture 0 payload bytes (marker only).
	for i := 3; i < attemptCount; i++ {
		if attempts[i].Body != totalResponseTruncatedMarker {
			t.Fatalf("attempt %d body=%q want marker only", i+1, attempts[i].Body)
		}
	}

	// Overall RawResponse stays bounded at <= 4 MiB + small headers & markers.
	raw := c.RawResponse()
	maxExpected := MaxCaptureTotalResponseBytes + attemptCount*(len(totalResponseTruncatedMarker)+64)
	if len(raw) > maxExpected {
		t.Fatalf("RawResponse len=%d exceeds total budget %d", len(raw), maxExpected)
	}
}

func TestCaptureExactCapLimitsNotMarkedTruncated(t *testing.T) {
	_, c := NewCapture(context.Background())
	exactReq := strings.Repeat("r", MaxCaptureRequestBytes)
	c.SetRequest(exactReq)
	if c.RawRequest() != exactReq {
		t.Fatalf("exact-cap request was altered: len=%d", len(c.RawRequest()))
	}

	exactResp := strings.Repeat("s", MaxCaptureAttemptBytes)
	rc := c.TeeResponse(200, io.NopCloser(strings.NewReader(exactResp)))
	got, err := io.ReadAll(rc)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	_ = rc.Close()
	if string(got) != exactResp {
		t.Fatal("exact-cap response stream altered")
	}
	if c.RawResponse() != exactResp {
		t.Fatalf("exact-cap response was falsely truncated: len=%d", len(c.RawResponse()))
	}
}

func TestRecorderCapsSerializedRequestAndResponseBodies(t *testing.T) {
	rec := Wrap(completeProvider{}, nil, "test-model", "prof", "", "", func() bool { return true })

	hugeMsg := llm.UserText(strings.Repeat("x", 10<<20))
	req := llm.CompletionRequest{Messages: []llm.Message{hugeMsg}}
	reqBody := rec.serializeRequest(req)
	if len(reqBody) > MaxCaptureRequestBytes {
		t.Fatalf("serializeRequest len=%d exceeds MaxCaptureRequestBytes=%d", len(reqBody), MaxCaptureRequestBytes)
	}
	if !strings.HasSuffix(reqBody, requestTruncatedMarker) {
		t.Fatal("serializeRequest missing truncation marker")
	}
	if strings.Count(reqBody, requestTruncatedMarker) != 1 {
		t.Fatalf("marker count=%d, want 1", strings.Count(reqBody, requestTruncatedMarker))
	}

	// Both huge text and huge thinking (including multi-byte UTF-8 runes) must
	// share the 4 MiB cap BEFORE json.Marshal so ResponseBody stays valid JSON.
	hugeText := strings.Repeat("中文t", 2<<20)     // ~14 MiB UTF-8
	hugeThinking := strings.Repeat("思考k", 2<<20) // ~14 MiB UTF-8
	row := rec.buildRecord(req, "sess", "task", "worker", reqBody, nil, time.Now(), hugeText, hugeThinking, llm.Usage{InputTokens: 12, OutputTokens: 34}, "end_turn", nil)
	if len(row.RequestBody) > MaxCaptureRequestBytes {
		t.Fatalf("row.RequestBody len=%d exceeds cap %d", len(row.RequestBody), MaxCaptureRequestBytes)
	}
	if strings.Count(row.RequestBody, requestTruncatedMarker) != 1 {
		t.Fatalf("row.RequestBody duplicated truncation marker: %d", strings.Count(row.RequestBody, requestTruncatedMarker))
	}
	if len(row.ResponseBody) > MaxCaptureTotalResponseBytes {
		t.Fatalf("row.ResponseBody len=%d exceeds cap %d", len(row.ResponseBody), MaxCaptureTotalResponseBytes)
	}
	if !utf8.ValidString(row.ResponseBody) {
		t.Fatal("row.ResponseBody is not valid UTF-8")
	}
	if !json.Valid([]byte(row.ResponseBody)) {
		t.Fatal("row.ResponseBody is not valid JSON after truncation")
	}
	var decoded struct {
		Text       string `json:"text"`
		Thinking   string `json:"thinking"`
		StopReason string `json:"stop_reason"`
	}
	if err := json.Unmarshal([]byte(row.ResponseBody), &decoded); err != nil {
		t.Fatalf("unmarshal ResponseBody: %v", err)
	}
	if !strings.HasSuffix(decoded.Text, totalResponseTruncatedMarker) {
		t.Fatal("decoded.Text missing truncation marker")
	}
	if !strings.HasSuffix(decoded.Thinking, totalResponseTruncatedMarker) {
		t.Fatal("decoded.Thinking missing truncation marker")
	}
	if decoded.StopReason != "end_turn" {
		t.Fatalf("decoded.StopReason=%q, want end_turn", decoded.StopReason)
	}

	// Heavy JSON-escaping payload (every byte doubles on marshal) must still stay
	// valid JSON and <= MaxCaptureTotalResponseBytes.
	quoteFlood := strings.Repeat(`"`, 5<<20)
	rowEsc := rec.buildRecord(req, "sess", "task", "worker", reqBody, nil, time.Now(), quoteFlood, "", llm.Usage{}, "end_turn", nil)
	if len(rowEsc.ResponseBody) > MaxCaptureTotalResponseBytes {
		t.Fatalf("escaped ResponseBody len=%d exceeds cap %d", len(rowEsc.ResponseBody), MaxCaptureTotalResponseBytes)
	}
	if !json.Valid([]byte(rowEsc.ResponseBody)) {
		t.Fatal("escaped ResponseBody is not valid JSON")
	}
}
