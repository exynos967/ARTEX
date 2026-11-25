package server

import (
	"bytes"
	"context"
	"io"
	"log"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/RC-CHN/ARTEX/db"
)

// LogLine is one captured backend log entry exposed by the /api/logs endpoints.
type LogLine struct {
	Seq   int64  `json:"seq"`
	DBID  int64  `json:"db_id,omitempty"` // server_logs.id; 0 for pre-persistence entries
	TS    string `json:"ts"`
	Level string `json:"level"` // info | warn | error
	Tag   string `json:"tag"`   // the leading [tag] (pg / planner / activity / …), if any
	Text  string `json:"text"`
}

// dbWriteReq carries a log line to the async DB writer.
type dbWriteReq struct {
	seq int64
	ll  LogLine
}

// logSinkT tees the standard logger into an in-memory ring buffer and fans new
// lines out to SSE subscribers, so the UI can show a live backend log stream.
// It still passes everything through to stderr (the terminal keeps working).
type logSinkT struct {
	mu   sync.Mutex
	ring []LogLine
	cap  int
	seq  int64
	subs map[chan LogLine]struct{}
	out  io.Writer // passthrough (stderr)

	dbRunning bool
	dbCh      chan dbWriteReq // buffered async channel; nil until SetDB is called
}

var logSink = &logSinkT{cap: 3000, subs: map[chan LogLine]struct{}{}, out: os.Stderr}

// StartLogCapture redirects the standard log package through the in-memory sink
// (still writing to stderr). Call once at startup, as early as possible.
func StartLogCapture() { log.SetOutput(logSink) }

const (
	logBatchMaxSize      = 64
	logBatchFlushWindow  = 500 * time.Millisecond
	logBatchWriteTimeout = time.Second
	logBackoffInitial    = time.Second
	logBackoffMax        = 30 * time.Second
)

type logBatchWriter interface {
	RecentLogsContext(ctx context.Context, limit int) ([]*db.DBLog, error)
	InsertLogsBatchContext(ctx context.Context, entries []db.LogBatchEntry) ([]int64, error)
}

type logWriterOptions struct {
	batchMax     int
	flushWindow  time.Duration
	writeTimeout time.Duration
	backoffBase  time.Duration
	backoffMax   time.Duration
	errOut       io.Writer
}

func defaultLogWriterOptions() logWriterOptions {
	return logWriterOptions{
		batchMax:     logBatchMaxSize,
		flushWindow:  logBatchFlushWindow,
		writeTimeout: logBatchWriteTimeout,
		backoffBase:  logBackoffInitial,
		backoffMax:   logBackoffMax,
		errOut:       os.Stderr,
	}
}

func (o logWriterOptions) normalized() logWriterOptions {
	if o.batchMax <= 0 {
		o.batchMax = logBatchMaxSize
	}
	if o.flushWindow <= 0 {
		o.flushWindow = logBatchFlushWindow
	}
	if o.writeTimeout <= 0 {
		o.writeTimeout = logBatchWriteTimeout
	}
	if o.backoffBase <= 0 {
		o.backoffBase = logBackoffInitial
	}
	if o.backoffMax < o.backoffBase {
		o.backoffMax = max(logBackoffMax, o.backoffBase)
	}
	if o.errOut == nil {
		o.errOut = os.Stderr
	}
	return o
}

// SetDB wires a postgres DB into the sink once (idempotent). It:
//  1. Restores the last 100 log rows from DB into the ring so the /logs page
//     shows history immediately after restart.
//  2. Starts an async goroutine that micro-batches subsequent log lines to DB
//     with an exponential-backoff circuit breaker on persistent DB failures.
func (s *logSinkT) SetDB(ctx context.Context, pg *db.DB) <-chan struct{} {
	if pg == nil {
		return nil
	}
	return s.setLogWriter(ctx, pg, defaultLogWriterOptions())
}

func (s *logSinkT) setLogWriter(ctx context.Context, writer logBatchWriter, opts logWriterOptions) <-chan struct{} {
	if writer == nil {
		return nil
	}
	opts = opts.normalized()
	s.mu.Lock()
	if s.dbRunning {
		s.mu.Unlock()
		return nil
	}
	s.dbRunning = true
	s.mu.Unlock()

	done := make(chan struct{})
	ch := make(chan dbWriteReq, 2000)

	// Restore last 100 rows from DB → prepend to ring as history context BEFORE
	// exposing s.dbCh so renumbering s.ring 1..N stays strictly monotonic and
	// matches every subsequently enqueued dbWriteReq.seq.
	if logs, err := writer.RecentLogsContext(ctx, 100); err == nil && len(logs) > 0 {
		s.mu.Lock()
		restored := make([]LogLine, 0, len(logs))
		for _, l := range logs {
			restored = append(restored, LogLine{
				DBID:  l.ID,
				TS:    l.CreatedAt.Format(time.RFC3339),
				Level: l.Level,
				Tag:   l.Tag,
				Text:  l.Text,
			})
		}
		// Prepend history before any in-memory startup logs already in ring,
		// trim to cap, and renumber Seq monotonically 1..N so cursor queries stay ordered.
		s.ring = append(restored, s.ring...)
		s.trimRingLocked()
		for i := range s.ring {
			s.ring[i].Seq = int64(i + 1)
		}
		s.seq = int64(len(s.ring))
		s.dbCh = ch
		s.mu.Unlock()
	} else {
		s.mu.Lock()
		s.dbCh = ch
		s.mu.Unlock()
	}

	// Async writer: micro-batches lines from channel and inserts into server_logs.
	// Uses opts.errOut (os.Stderr in prod) directly to avoid recursive log calls.
	go func() {
		defer func() {
			s.mu.Lock()
			if s.dbCh == ch {
				s.dbCh = nil
			}
			s.dbRunning = false
			s.mu.Unlock()
			close(done)
		}()

		batch := make([]dbWriteReq, 0, opts.batchMax)
		var (
			flushTimer   *time.Timer
			flushCh      <-chan time.Time
			circuitTimer *time.Timer
			circuitCh    <-chan time.Time
			backoff      time.Duration
		)
		stopTimer := func(t *time.Timer) {
			if t == nil {
				return
			}
			if !t.Stop() {
				select {
				case <-t.C:
				default:
				}
			}
		}
		defer func() {
			stopTimer(flushTimer)
			stopTimer(circuitTimer)
		}()
		armTimer := func(t **time.Timer, d time.Duration) <-chan time.Time {
			if *t == nil {
				*t = time.NewTimer(d)
			} else {
				stopTimer(*t)
				(*t).Reset(d)
			}
			return (*t).C
		}

		flushWith := func(parentCtx context.Context, timeout time.Duration, shutdown bool) bool {
			if len(batch) == 0 {
				return true
			}
			entries := make([]db.LogBatchEntry, len(batch))
			for i, req := range batch {
				entries[i] = db.LogBatchEntry{
					Level: req.ll.Level,
					Tag:   req.ll.Tag,
					Text:  req.ll.Text,
				}
			}
			writeCtx, cancel := context.WithTimeout(parentCtx, timeout)
			ids, err := writer.InsertLogsBatchContext(writeCtx, entries)
			cancel()
			if err != nil {
				if shutdown || ctx.Err() != nil {
					clear(batch)
					batch = batch[:0]
					return false
				}
				if backoff == 0 {
					backoff = opts.backoffBase
				} else {
					backoff *= 2
					if backoff > opts.backoffMax {
						backoff = opts.backoffMax
					}
				}
				_, _ = opts.errOut.Write([]byte("[logsink] db write (backoff " + backoff.String() + "): " + err.Error() + "\n"))
				clear(batch)
				batch = batch[:0]
				stopTimer(flushTimer)
				flushCh = nil
				circuitCh = armTimer(&circuitTimer, backoff)
				return true
			}
			backoff = 0
			n := min(len(ids), len(batch))
			if n > 0 {
				s.stampDBIDs(batch[:n], ids[:n])
			}
			clear(batch)
			batch = batch[:0]
			stopTimer(flushTimer)
			flushCh = nil
			return true
		}

		flush := func() bool {
			return flushWith(ctx, opts.writeTimeout, false)
		}

		drainFinal := func() {
			s.mu.Lock()
			if s.dbCh == ch {
				s.dbCh = nil
			}
			s.mu.Unlock()
			// When the circuit breaker is open on shutdown, skip blocking on a dead DB.
			if circuitCh != nil {
				clear(batch)
				batch = batch[:0]
				return
			}
			for {
				select {
				case req, ok := <-ch:
					if !ok {
						flushWith(context.Background(), 2*time.Second, true)
						return
					}
					batch = append(batch, req)
					if len(batch) >= opts.batchMax {
						if !flushWith(context.Background(), 2*time.Second, true) {
							return
						}
					}
				default:
					flushWith(context.Background(), 2*time.Second, true)
					return
				}
			}
		}

		for {
			if ctx.Err() != nil {
				drainFinal()
				return
			}
			if circuitCh != nil {
				select {
				case <-ctx.Done():
					drainFinal()
					return
				case _, ok := <-ch:
					if !ok {
						return
					}
					// Drop incoming entries while circuit is open so writers never block.
				case <-circuitCh:
					circuitCh = nil
				}
				continue
			}
			select {
			case <-ctx.Done():
				drainFinal()
				return
			case req, ok := <-ch:
				if !ok {
					flushWith(context.Background(), 2*time.Second, true)
					return
				}
				batch = append(batch, req)
				if len(batch) == 1 {
					flushCh = armTimer(&flushTimer, opts.flushWindow)
				}
				if len(batch) >= opts.batchMax {
					if !flush() {
						drainFinal()
						return
					}
				}
			case <-flushCh:
				flushCh = nil
				if !flush() {
					drainFinal()
					return
				}
			}
		}
	}()
	return done
}

// stampDBIDs stamps persisted server_logs ids back into s.ring under a single lock.
func (s *logSinkT) stampDBIDs(reqs []dbWriteReq, ids []int64) {
	seqToID := make(map[int64]int64, len(reqs))
	for i, req := range reqs {
		seqToID[req.seq] = ids[i]
	}
	remaining := len(seqToID)
	s.mu.Lock()
	for i := len(s.ring) - 1; i >= 0 && remaining > 0; i-- {
		if id, ok := seqToID[s.ring[i].Seq]; ok {
			s.ring[i].DBID = id
			remaining--
		}
	}
	s.mu.Unlock()
}

// trimRingLocked compacts s.ring in place to at most s.cap newest entries and
// zeroes vacated tail slots so evicted strings are released to GC.
func (s *logSinkT) trimRingLocked() {
	if s.cap <= 0 || len(s.ring) <= s.cap {
		return
	}
	drop := len(s.ring) - s.cap
	copy(s.ring, s.ring[drop:])
	clear(s.ring[s.cap:])
	s.ring = s.ring[:s.cap]
}

// Write implements io.Writer for the log package: one call per log.Printf line.
func (s *logSinkT) Write(p []byte) (int, error) {
	if s.out != nil {
		_, _ = s.out.Write(p) // keep the terminal output
	}
	raw := bytes.TrimRight(p, "\n")
	// Copy only a bounded prefix; the extra byte preserves the truncation signal.
	line := db.LogPreview(string(raw[:min(len(raw), db.LogPreviewBytes+1)]))
	if strings.TrimSpace(line) != "" {
		s.add(parseLog(line))
	}
	return len(p), nil
}

func (s *logSinkT) add(l LogLine) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.seq++
	l.Seq = s.seq
	s.ring = append(s.ring, l)
	s.trimRingLocked()

	// Async DB write (non-blocking; drops if channel is full under extreme load).
	if s.dbCh != nil {
		select {
		case s.dbCh <- dbWriteReq{seq: l.Seq, ll: l}:
		default:
		}
	}

	// Serialize non-blocking sends with unsubscribe, which closes the channel.
	for sub := range s.subs {
		select {
		case sub <- l:
		default:
		}
	}
}

// recent returns ring lines with Seq > since (capped to limit), and the latest seq.
func (s *logSinkT) recent(since int64, limit int) (lines []LogLine, cursor int64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	cursor = s.seq
	if limit <= 0 || limit > s.cap {
		limit = s.cap
	}
	for _, l := range s.ring {
		if l.Seq > since {
			lines = append(lines, l)
		}
	}
	if len(lines) > limit {
		lines = lines[len(lines)-limit:]
	}
	return lines, cursor
}

func (s *logSinkT) subscribe() (<-chan LogLine, func()) {
	ch := make(chan LogLine, 256)
	s.mu.Lock()
	s.subs[ch] = struct{}{}
	s.mu.Unlock()
	var once sync.Once
	return ch, func() {
		once.Do(func() {
			s.mu.Lock()
			delete(s.subs, ch)
			close(ch)
			s.mu.Unlock()
		})
	}
}

// parseLog pulls a level + [tag] out of a standard-logger line; the timestamp is
// the capture time (RFC3339).
func parseLog(line string) LogLine {
	msg := line
	// strip the "2006/01/02 15:04:05" LstdFlags prefix if present
	if len(msg) >= 20 && msg[4] == '/' && msg[7] == '/' && msg[10] == ' ' {
		msg = strings.TrimSpace(msg[19:])
	}
	tag := ""
	if strings.HasPrefix(msg, "[") {
		if i := strings.IndexByte(msg, ']'); i > 1 {
			tag = msg[1:i]
		}
	}
	return LogLine{TS: time.Now().Format(time.RFC3339), Level: levelOf(msg), Tag: tag, Text: msg}
}

func levelOf(msg string) string {
	low := strings.ToLower(msg)
	for _, k := range []string{"fatal", "panic", "error", "err:", "失败", "丢弃", "拒绝", "✕", "不可达"} {
		if strings.Contains(low, k) {
			return "error"
		}
	}
	for _, k := range []string{"warn", "disabled", "禁用", "skip", "stopped", "⚠", "重试"} {
		if strings.Contains(low, k) {
			return "warn"
		}
	}
	return "info"
}
