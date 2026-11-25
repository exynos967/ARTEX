package llm

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"strings"
)

const (
	// maxSSELineBytes caps a single SSE line to prevent unbounded allocation
	// when a peer streams an unterminated or oversized line.
	maxSSELineBytes = 4 << 20 // 4 MiB
	// maxSSEEventBytes caps the total accumulated data payload of one SSE event.
	maxSSEEventBytes = 8 << 20 // 8 MiB
)

// ErrSSEEventTooLarge is returned when an SSE line or accumulated event exceeds
// the scanner's safety ceiling.
var ErrSSEEventTooLarge = errors.New("sse event too large")

// sseScanner reads Server-Sent Events from a response body, yielding the
// (event, data) pair of each message. Anthropic uses named events; OpenAI uses
// bare data lines. Both are handled.
type sseScanner struct {
	r             *bufio.Reader
	maxLineBytes  int
	maxEventBytes int
}

func newSSEScanner(body io.Reader) *sseScanner {
	return &sseScanner{
		r:             bufio.NewReaderSize(body, 64*1024),
		maxLineBytes:  maxSSELineBytes,
		maxEventBytes: maxSSEEventBytes,
	}
}

func (s *sseScanner) lineLimit() int {
	if s.maxLineBytes > 0 {
		return s.maxLineBytes
	}
	return maxSSELineBytes
}

func (s *sseScanner) eventLimit() int {
	if s.maxEventBytes > 0 {
		return s.maxEventBytes
	}
	return maxSSEEventBytes
}

// readLine reads a single '\n'-terminated line bounded by lineLimit bytes.
func (s *sseScanner) readLine() (string, error) {
	limit := s.lineLimit()
	var b strings.Builder
	for {
		frag, err := s.r.ReadSlice('\n')
		if b.Len()+len(frag) > limit {
			return "", fmt.Errorf("%w: line exceeds %d bytes", ErrSSEEventTooLarge, limit)
		}
		if err == bufio.ErrBufferFull {
			b.Write(frag)
			continue
		}
		if b.Len() == 0 {
			return string(frag), err
		}
		b.Write(frag)
		return b.String(), err
	}
}

// next returns the next event's (type, data). event is "" for bare-data streams.
// Returns io.EOF at end of stream.
func (s *sseScanner) next() (event, data string, err error) {
	var buf bytes.Buffer
	eventLimit := s.eventLimit()
	for {
		line, rerr := s.readLine()
		if rerr != nil && rerr != io.EOF {
			return "", "", rerr
		}
		if rerr == io.EOF && line == "" {
			if buf.Len() > 0 || event != "" {
				return event, strings.TrimRight(buf.String(), "\n"), nil
			}
			return "", "", rerr
		}
		line = strings.TrimRight(line, "\r\n")
		if line == "" {
			if buf.Len() > 0 || event != "" {
				return event, strings.TrimRight(buf.String(), "\n"), nil
			}
			continue
		}
		switch {
		case strings.HasPrefix(line, "event:"):
			event = strings.TrimSpace(line[len("event:"):])
		case strings.HasPrefix(line, "data:"):
			d := line[len("data:"):]
			d = strings.TrimPrefix(d, " ")
			if buf.Len()+len(d)+1 > eventLimit {
				return "", "", fmt.Errorf("%w: event exceeds %d bytes", ErrSSEEventTooLarge, eventLimit)
			}
			buf.WriteString(d)
			buf.WriteByte('\n')
		default:
			// comment / unknown field — ignore
		}
		// readLine can return data together with EOF. Decode that last line
		// before reporting EOF; otherwise a final finish_reason/[DONE] is lost.
		if rerr == io.EOF {
			if buf.Len() > 0 || event != "" {
				return event, strings.TrimRight(buf.String(), "\n"), nil
			}
			return "", "", io.EOF
		}
	}
}
