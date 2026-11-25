package llm

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestSSEScannerNormalMultilineAndEOF(t *testing.T) {
	// Include a line larger than the 64 KiB bufio buffer to exercise multi-slice reads.
	longPayload := strings.Repeat("x", 80*1024)
	stream := strings.Join([]string{
		"event: message_start",
		"data: line1",
		"data: line2",
		"",
		"data: " + longPayload,
		"",
		"data: [DONE]", // EOF without trailing newline
	}, "\n")

	sc := newSSEScanner(strings.NewReader(stream))

	ev, data, err := sc.next()
	if err != nil || ev != "message_start" || data != "line1\nline2" {
		t.Fatalf("event 1 = (%q, %q, %v)", ev, data, err)
	}

	ev, data, err = sc.next()
	if err != nil || ev != "" || data != longPayload {
		t.Fatalf("event 2 = (%q, len=%d, %v)", ev, len(data), err)
	}

	ev, data, err = sc.next()
	if err != nil || ev != "" || data != "[DONE]" {
		t.Fatalf("event 3 = (%q, %q, %v)", ev, data, err)
	}

	_, _, err = sc.next()
	if !errors.Is(err, io.EOF) {
		t.Fatalf("expected io.EOF, got %v", err)
	}
}

func TestSSEScannerLineCap(t *testing.T) {
	t.Run("custom small line cap", func(t *testing.T) {
		sc := newSSEScanner(strings.NewReader("data: " + strings.Repeat("A", 300) + "\n\n"))
		sc.maxLineBytes = 128
		_, _, err := sc.next()
		if !errors.Is(err, ErrSSEEventTooLarge) {
			t.Fatalf("got err=%v, want ErrSSEEventTooLarge", err)
		}
	})

	t.Run("unterminated line exceeding default 4 MiB cap", func(t *testing.T) {
		oversized := "data: " + strings.Repeat("B", maxSSELineBytes+128)
		sc := newSSEScanner(strings.NewReader(oversized))
		_, _, err := sc.next()
		if !errors.Is(err, ErrSSEEventTooLarge) {
			t.Fatalf("got err=%v, want ErrSSEEventTooLarge", err)
		}
	})
}

func TestSSEScannerEventCap(t *testing.T) {
	t.Run("custom small event cap across multiple data lines", func(t *testing.T) {
		var b strings.Builder
		for range 5 {
			b.WriteString("data: ")
			b.WriteString(strings.Repeat("C", 80))
			b.WriteByte('\n')
		}
		b.WriteByte('\n')
		sc := newSSEScanner(strings.NewReader(b.String()))
		sc.maxLineBytes = 256
		sc.maxEventBytes = 256
		_, _, err := sc.next()
		if !errors.Is(err, ErrSSEEventTooLarge) {
			t.Fatalf("got err=%v, want ErrSSEEventTooLarge", err)
		}
	})

	t.Run("default 8 MiB event cap across valid 3 MiB lines", func(t *testing.T) {
		chunk := "data: " + strings.Repeat("D", 3<<20) + "\n"
		sc := newSSEScanner(strings.NewReader(chunk + chunk + chunk + "\n"))
		_, _, err := sc.next()
		if !errors.Is(err, ErrSSEEventTooLarge) {
			t.Fatalf("got err=%v, want ErrSSEEventTooLarge", err)
		}
	})
}

func TestStreamFailsFastOnErrSSEEventTooLargeWithoutRetry(t *testing.T) {
	oversized := "data: " + strings.Repeat("X", maxSSELineBytes+64) + "\n\n"
	for _, format := range []Format{FormatAnthropic, FormatOpenAI, FormatOpenAIResponses} {
		t.Run(string(format), func(t *testing.T) {
			var hits atomic.Int32
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				hits.Add(1)
				w.Header().Set("content-type", "text/event-stream")
				_, _ = io.WriteString(w, oversized)
			}))
			defer srv.Close()

			p, err := NewProvider(Config{
				Format:                format,
				BaseURL:               srv.URL,
				APIKey:                "k",
				Model:                 "m",
				EmptyResponseRetries:  2,
				EmptyResponseInterval: time.Nanosecond,
			})
			if err != nil {
				t.Fatal(err)
			}
			var gotErr error
			for _, serr := range p.Stream(context.Background(), CompletionRequest{Messages: []Message{UserText("hi")}}) {
				if serr != nil {
					gotErr = serr
					break
				}
			}
			if !errors.Is(gotErr, ErrSSEEventTooLarge) {
				t.Fatalf("err=%v, want ErrSSEEventTooLarge", gotErr)
			}
			if got := hits.Load(); got != 1 {
				t.Fatalf("hits=%d, want 1 (must fail fast without empty-response retries)", got)
			}
		})
	}
}
