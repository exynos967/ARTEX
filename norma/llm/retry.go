package llm

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"math"
	"math/rand/v2"
	"net/http"
	"strconv"
	"strings"
	"time"
)

const (
	maxRetryAfter        = 60 * time.Second
	retryDrainBytes      = 4096
	maxErrorBodyBytes    = 256 << 10
	maxResponseBodyBytes = 32 << 20
)

// doStream sends the streaming request with retries on transient failures and
// returns a 200 response (caller reads + closes the body). Only the request
// establishment phase is retried — connection reset / timeout / 429 / 5xx before
// any stream data is consumed — so retrying is safe (it can't duplicate
// partially-streamed assistant output). A mid-stream drop is the caller's to
// surface. Context cancellation is never retried and interrupts the backoff.
// Count comes from cfg.retries(), the wait between attempts from
// cfg.retryDelay() (jittered exponential by default, fixed when
// Config.RetryInterval is set), honoring Retry-After when larger.
func doStream(ctx context.Context, cfg Config, url string, body []byte, setHeaders func(*http.Request), errPrefix string) (*http.Response, error) {
	retries := cfg.retries()
	for attempt := 0; ; attempt++ {
		// Rate limit every attempt (including retries) so retry traffic respects
		// the shared upstream budget instead of amplifying rate-limit storms.
		if err := cfg.limiter.Wait(ctx); err != nil {
			return nil, err
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
		if err != nil {
			return nil, err
		}
		setHeaders(req)

		resp, err := cfg.HTTPClient.Do(req)
		if err == nil && resp.StatusCode == http.StatusOK {
			return resp, nil
		}

		retryable := false
		switch {
		case err != nil:
			retryable = ctx.Err() == nil // transient network error (not cancellation)
		case isRetryableStatus(resp.StatusCode):
			retryable = true
		}
		if attempt >= retries || !retryable {
			if err != nil {
				return nil, err
			}
			data, _ := io.ReadAll(io.LimitReader(resp.Body, maxErrorBodyBytes))
			resp.Body.Close()
			return nil, fmt.Errorf("%s: status %d: %s", errPrefix, resp.StatusCode, strings.TrimSpace(string(data)))
		}
		delay := cfg.retryDelay(attempt)
		if resp != nil {
			if ra, ok := parseRetryAfter(resp.Header.Get("Retry-After"), time.Now()); ok && ra > delay {
				delay = ra
			}
			// Drain small error bodies so net/http can reuse the keep-alive socket.
			_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, retryDrainBytes))
			resp.Body.Close()
		}
		if !backoffSleep(ctx, delay) {
			return nil, ctx.Err() // context cancelled during backoff
		}
	}
}

func isRetryableStatus(code int) bool {
	switch code {
	case http.StatusRequestTimeout, // 408
		http.StatusTooManyRequests,     // 429
		http.StatusInternalServerError, // 500
		http.StatusBadGateway,          // 502
		http.StatusServiceUnavailable,  // 503
		http.StatusGatewayTimeout:      // 504
		return true
	}
	return false
}

// parseRetryAfter parses an HTTP Retry-After header (delta-seconds or HTTP-date)
// relative to now and clamps the result to [0, maxRetryAfter].
func parseRetryAfter(val string, now time.Time) (time.Duration, bool) {
	val = strings.TrimSpace(val)
	if val == "" {
		return 0, false
	}
	if secs, err := strconv.ParseFloat(val, 64); err == nil && !math.IsNaN(secs) && !math.IsInf(secs, 0) {
		if secs <= 0 {
			return 0, true
		}
		if secs >= maxRetryAfter.Seconds() {
			return maxRetryAfter, true
		}
		return time.Duration(secs * float64(time.Second)), true
	}
	if t, err := http.ParseTime(val); err == nil {
		d := t.Sub(now)
		if d < 0 {
			return 0, true
		}
		if d > maxRetryAfter {
			return maxRetryAfter, true
		}
		return d, true
	}
	return 0, false
}

// expBackoffBase returns the uncapped-jitter base ladder: 0.5s, 1s, 2s, 4s,
// capped at 8s.
func expBackoffBase(attempt int) time.Duration {
	if attempt < 0 {
		attempt = 0
	}
	if attempt >= 4 {
		return 8 * time.Second
	}
	d := 500 * time.Millisecond << attempt
	if d > 8*time.Second {
		return 8 * time.Second
	}
	return d
}

// expBackoff is the default retry ladder with jitter in [base/2, base] (base
// 0.5s, 1s, 2s, 4s, capped at 8s). Used whenever the caller did not pin a fixed
// interval on the Config.
func expBackoff(attempt int) time.Duration {
	base := expBackoffBase(attempt)
	half := base / 2
	if half <= 0 {
		return base
	}
	return half + time.Duration(rand.Int64N(int64(base-half)+1))
}

// backoffSleep waits d, interruptible by ctx. Returns false if the context was
// cancelled (or d is non-positive, which never happens for a real wait).
func backoffSleep(ctx context.Context, d time.Duration) bool {
	if d <= 0 {
		return ctx.Err() == nil
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-t.C:
		return true
	}
}
