package server

import (
	"context"
	"os"
	"strconv"
	"strings"
	"sync"
)

const (
	defaultMaxConcurrentAgentRuns = 12
	minConcurrentAgentRuns        = 2
	maxConcurrentAgentRuns        = 64
	envMaxConcurrentAgentRuns     = "ARTEX_MAX_CONCURRENT_AGENT_RUNS"
)

// runAdmission is a process-wide, context-aware concurrency gate that caps the
// total number of simultaneous agent runs (planner rounds, worker intents, and
// conversational/triggered agent turns) so bursts cannot overwhelm LLM quotas,
// sandboxes, or memory. A nil receiver is a safe no-op for zero-value test Servers.
type runAdmission struct {
	sem chan struct{}
}

func newRunAdmission(capacity int) *runAdmission {
	if capacity < 1 {
		capacity = defaultMaxConcurrentAgentRuns
	}
	return &runAdmission{sem: make(chan struct{}, capacity)}
}

func maxConcurrentAgentRunsFromEnv() int {
	raw := strings.TrimSpace(os.Getenv(envMaxConcurrentAgentRuns))
	if raw == "" {
		return defaultMaxConcurrentAgentRuns
	}
	n, err := strconv.Atoi(raw)
	if err != nil {
		return defaultMaxConcurrentAgentRuns
	}
	if n < minConcurrentAgentRuns {
		return minConcurrentAgentRuns
	}
	if n > maxConcurrentAgentRuns {
		return maxConcurrentAgentRuns
	}
	return n
}

func newRunAdmissionFromEnv() *runAdmission {
	return newRunAdmission(maxConcurrentAgentRunsFromEnv())
}

func (a *runAdmission) makeRelease() func() {
	var once sync.Once
	return func() {
		once.Do(func() {
			<-a.sem
		})
	}
}

// Acquire waits until an agent-run slot is available or ctx is cancelled. The
// returned release function is idempotent and must be called when the run ends.
func (a *runAdmission) Acquire(ctx context.Context) (func(), error) {
	if a == nil || a.sem == nil {
		return func() {}, nil
	}
	if ctx != nil {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case a.sem <- struct{}{}:
			return a.makeRelease(), nil
		}
	}
	a.sem <- struct{}{}
	return a.makeRelease(), nil
}

// TryAcquire attempts to claim an agent-run slot without blocking.
func (a *runAdmission) TryAcquire() (func(), bool) {
	if a == nil || a.sem == nil {
		return func() {}, true
	}
	select {
	case a.sem <- struct{}{}:
		return a.makeRelease(), true
	default:
		return nil, false
	}
}

// Stats returns the current number of in-flight runs and the configured capacity.
func (a *runAdmission) Stats() (inFlight, capacity int) {
	if a == nil || a.sem == nil {
		return 0, 0
	}
	return len(a.sem), cap(a.sem)
}
