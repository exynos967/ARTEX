package traffic

import (
	"context"
	"errors"
	"net/http"
	"time"
)

var ErrClosed = errors.New("traffic recorder is closed")

const proxyShutdownGrace = 5 * time.Second

// Start runs the proxy once (blocking). A concurrent Close closes the HTTP
// server even if Start has not reached Serve yet, then joins this call.
func (t *Traffic) Start() error {
	t.lifecycleMu.Lock()
	if t.closing {
		t.lifecycleMu.Unlock()
		return ErrClosed
	}
	if t.started {
		t.lifecycleMu.Unlock()
		return errors.New("traffic proxy already started")
	}
	t.started = true
	t.startDone = make(chan struct{})
	done := t.startDone
	t.lifecycleMu.Unlock()
	defer close(done)
	if t.proxy == nil {
		return ErrClosed
	}
	err := t.proxy.Start()
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}

// Shutdown gracefully stops the recording proxy using ctx's deadline (or
// proxyShutdownGrace when ctx has no deadline), flushes queued exchanges, and
// closes the database.
func (t *Traffic) Shutdown(ctx context.Context) error {
	grace := proxyShutdownGrace
	if ctx != nil {
		if deadline, ok := ctx.Deadline(); ok {
			grace = time.Until(deadline)
			if grace < 0 {
				grace = 0
			}
		}
	}
	return t.closeWithTimeout(grace)
}

// Close stops accepting proxy traffic and gives active HTTP/HTTPS requests a
// bounded grace period to finish. Buffered recordings are flushed cleanly,
// background workers (reclamation, legacy reaping, retention) exit, and then
// the database is closed.
func (t *Traffic) Close() error { return t.closeWithTimeout(proxyShutdownGrace) }

func (t *Traffic) closeWithTimeout(grace time.Duration) error {
	t.closeOnce.Do(func() {
		t.lifecycleMu.Lock()
		t.closing = true
		if t.closed != nil {
			close(t.closed)
		}
		done := t.startDone
		t.lifecycleMu.Unlock()

		if done != nil && t.proxy != nil {
			ctx, cancel := context.WithTimeout(context.Background(), grace)
			err := t.proxy.Shutdown(ctx)
			cancel()
			if err != nil {
				t.closeErr = errors.Join(err, t.proxy.Close())
			}
			<-done
		} else if t.proxy != nil {
			_ = t.proxy.Close()
		}

		// Stop accepting new async ingest items and flush everything already queued
		// before refusing late recordings and closing the database.
		t.stopIngest()

		t.lifecycleMu.Lock()
		t.recordsClosed = true
		t.lifecycleMu.Unlock()

		t.recording.Wait()
		t.reaping.Wait()
		t.retentionWG.Wait()
		if t.db != nil {
			t.closeErr = errors.Join(t.closeErr, t.db.Close())
		}
	})
	return t.closeErr
}

func (t *Traffic) beginRecording() bool {
	t.lifecycleMu.Lock()
	defer t.lifecycleMu.Unlock()
	if t.recordsClosed {
		return false
	}
	t.recording.Add(1)
	return true
}

func (t *Traffic) startReaper(run func()) bool {
	t.lifecycleMu.Lock()
	defer t.lifecycleMu.Unlock()
	if t.closing {
		return false
	}
	t.reaping.Go(run)
	return true
}
