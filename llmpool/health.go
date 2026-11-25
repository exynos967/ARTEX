// Package llmpool implements LLM failover ("轮询"): a Provider decorator that
// walks an ordered chain of LLM profiles and moves to the next one when the
// current one can't serve the request — out of credit, revoked key, rate-limited
// past the SDK's own retries, or down.
//
// The chain is built by the server from llm_profiles (active profile first, then
// by priority), so the whole process shares ONE chain and ONE circuit-breaker
// registry: when a task discovers a profile is out of credit, every other task
// skips it immediately.
package llmpool

import (
	"sync"
	"time"
)

// backoff is the cooling-off ladder, indexed by trip count: the 1st trip cools
// for a minute, the 2nd for five, everything after that for half an hour. A
// profile that is merely rate-limited recovers quickly; one that keeps failing
// stops being probed every round.
var backoff = []time.Duration{time.Minute, 5 * time.Minute, 30 * time.Minute}

// State is one profile's circuit-breaker state.
type State struct {
	Fails     int       // consecutive failures; reset by a success
	Trips     int       // total trips, indexes the backoff ladder
	OpenUntil time.Time // zero / past = closed (usable)
	LastError string
	LastAt    time.Time
}

// Open reports whether the breaker is currently open (profile should be skipped).
func (s State) Open() bool { return time.Now().Before(s.OpenUntil) }

// softTripAfter is the DEFAULT number of consecutive TRANSIENT failures (429 /
// 5xx / network) that trip the breaker. Deterministic failures (no credit, bad
// key) trip on the first regardless. Overridable via Registry.SetPolicy.
const softTripAfter = 3

// defaultProbeLease bounds how long a single-flight half-open/last-resort probe
// stays reserved if the caller exits abnormally without settling Pass/Trip.
const defaultProbeLease = 60 * time.Second

type probeEntry struct {
	token uint64
	until time.Time
}

// Registry holds the circuit-breaker state of every profile, keyed by profile id.
// It is process-wide and outlives any single Pool instance, so rebuilding the pool
// (saving an unrelated profile, toggling a setting) never clears what we've learned
// about which backends are broken.
type Registry struct {
	mu             sync.Mutex
	m              map[int64]*State
	probes         map[int64]probeEntry // active single-flight probe leases (id -> entry)
	nextProbeToken uint64

	// persist / forget mirror state to the DB so a cooling-off window survives a
	// restart. Both may be nil (no DB); both are called off the hot path.
	persist func(id int64, st State)
	forget  func(id int64)

	// softTrip / cooldown are the operator-set overrides (0 = use the built-in
	// default / ladder). They live here rather than being read per failure because
	// Trip runs on the failure path of every request.
	softTrip     int
	cooldown     time.Duration
	probeTimeout time.Duration // 0 = defaultProbeLease (test hook)
}

// SetPolicy overrides the breaker's two knobs. softTrip: how many consecutive
// transient failures trip it (0 = default softTripAfter; negative = transient
// failures never trip it, leaving only the deterministic ones). cooldown: a fixed
// cooling-off window (0 = the 1min/5min/30min ladder). Safe to call at any time.
func (r *Registry) SetPolicy(softTrip int, cooldown time.Duration) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.softTrip, r.cooldown = softTrip, cooldown
}

// tripAfter is the effective consecutive-transient-failure threshold. Callers
// hold r.mu. A negative override yields 0, which Trip reads as "never soft-trip".
func (r *Registry) tripAfter() int {
	if r.softTrip == 0 {
		return softTripAfter
	}
	return max(r.softTrip, 0)
}

// coolFor is the cooling-off window for the trips-th trip (1-based): the fixed
// override when set, else the ladder (last rung repeats). Callers hold r.mu.
func (r *Registry) coolFor(trips int) time.Duration {
	if r.cooldown > 0 {
		return r.cooldown
	}
	if trips-1 < len(backoff) {
		return backoff[trips-1]
	}
	return backoff[len(backoff)-1]
}

// probeLease returns the active probe lease duration. Callers hold r.mu.
func (r *Registry) probeLease() time.Duration {
	if r.probeTimeout > 0 {
		return r.probeTimeout
	}
	return defaultProbeLease
}

// NewRegistry builds an empty registry. persist/forget may be nil.
func NewRegistry(persist func(id int64, st State), forget func(id int64)) *Registry {
	return &Registry{
		m:       map[int64]*State{},
		probes:  map[int64]probeEntry{},
		persist: persist,
		forget:  forget,
	}
}

// Restore seeds state loaded from the DB at startup (bypasses persistence).
func (r *Registry) Restore(id int64, st State) {
	r.mu.Lock()
	defer r.mu.Unlock()
	cp := st
	r.m[id] = &cp
	delete(r.probes, id)
}

// Get returns a copy of one profile's state.
func (r *Registry) Get(id int64) State {
	r.mu.Lock()
	defer r.mu.Unlock()
	if st := r.m[id]; st != nil {
		return *st
	}
	return State{}
}

// IsOpen reports whether a profile is in its cooling-off window.
func (r *Registry) IsOpen(id int64) bool { return r.Get(id).Open() }

// TryAcquireProbe reports whether a caller may send a request to profile id.
//
//   - Closed (never tripped / OpenUntil zero): returns (0, true).
//   - Open (now < OpenUntil): returns (0, false).
//   - Half-open (OpenUntil expired): admits ONLY ONE caller at a time, returning
//     (token, true) with a non-zero lease token that must be passed to
//     ReleaseProbe(id, token) if the call aborts before Pass/Trip; concurrent
//     callers receive (0, false) until Pass, Trip, Reset, ReleaseProbe, or lease
//     expiry clears the probe.
func (r *Registry) TryAcquireProbe(id int64) (uint64, bool) {
	allowed, token := r.allowProbe(id)
	return token, allowed
}

// AllowProbe reports whether a caller may send a request to profile id.
func (r *Registry) AllowProbe(id int64) bool {
	allowed, _ := r.allowProbe(id)
	return allowed
}

func (r *Registry) allowProbe(id int64) (allowed bool, token uint64) {
	r.mu.Lock()
	defer r.mu.Unlock()
	st := r.m[id]
	if st == nil || st.OpenUntil.IsZero() {
		return true, 0
	}
	now := time.Now()
	if now.Before(st.OpenUntil) {
		return false, 0
	}
	if r.probes == nil {
		r.probes = map[int64]probeEntry{}
	}
	if ent, ok := r.probes[id]; ok && now.Before(ent.until) {
		return false, 0
	}
	r.nextProbeToken++
	token = r.nextProbeToken
	r.probes[id] = probeEntry{token: token, until: now.Add(r.probeLease())}
	return true, token
}

// acquireLastResort admits a last-resort call when every candidate in the pool
// was filtered out.
//   - Closed: always allowed (token=0).
//   - Open or half-open with no active probe: admits ONE caller (token!=0).
//   - Open or half-open with an active probe in flight: returns (false, 0)
//     so concurrent callers fail fast instead of hammering the tripped member.
func (r *Registry) acquireLastResort(id int64) (allowed bool, token uint64) {
	r.mu.Lock()
	defer r.mu.Unlock()
	st := r.m[id]
	if st == nil || st.OpenUntil.IsZero() {
		return true, 0
	}
	now := time.Now()
	if r.probes == nil {
		r.probes = map[int64]probeEntry{}
	}
	if ent, ok := r.probes[id]; ok && now.Before(ent.until) {
		return false, 0
	}
	r.nextProbeToken++
	token = r.nextProbeToken
	r.probes[id] = probeEntry{token: token, until: now.Add(r.probeLease())}
	return true, token
}

// ReleaseProbe clears an active probe lease without altering failure counters
// ONLY when the active lease's token matches token, preventing an expired slow
// probe from deleting a newer probe's lease.
func (r *Registry) ReleaseProbe(id int64, token uint64) {
	if token == 0 {
		return
	}
	r.mu.Lock()
	if ent, ok := r.probes[id]; ok && ent.token == token {
		delete(r.probes, id)
	}
	r.mu.Unlock()
}

// Pass records a successful call: clears the failure counters so a profile that
// recovers is fully trusted again (and drops the persisted row).
func (r *Registry) Pass(id int64) {
	r.mu.Lock()
	delete(r.probes, id)
	st := r.m[id]
	if st == nil || (st.Fails == 0 && st.Trips == 0 && st.OpenUntil.IsZero()) {
		r.mu.Unlock()
		return // already clean — nothing to write
	}
	delete(r.m, id)
	forget := r.forget
	r.mu.Unlock()
	if forget != nil {
		forget(id)
	}
}

// Trip records a failed call. hard=true marks a deterministic failure (no credit,
// invalid key, missing model) which opens the breaker immediately; hard=false is a
// transient one (429 / 5xx / network) that needs softTripAfter in a row (or fails
// an active half-open probe). Returns true when this call is what opened the
// breaker, so the caller can log it once.
func (r *Registry) Trip(id int64, errMsg string, hard bool) (tripped bool) {
	r.mu.Lock()
	now := time.Now()
	_, wasProbing := r.probes[id]
	delete(r.probes, id)
	st := r.m[id]
	if st == nil {
		st = &State{}
		r.m[id] = st
	}
	wasHalfOpen := !st.OpenUntil.IsZero() && !now.Before(st.OpenUntil)
	st.Fails++
	st.LastError = errMsg
	st.LastAt = now
	softTrip := r.tripAfter()
	if hard || (softTrip > 0 && (st.Fails >= softTrip || wasProbing || wasHalfOpen)) {
		st.Trips++
		st.OpenUntil = now.Add(r.coolFor(st.Trips))
		st.Fails = 0 // counted into this trip; start fresh for the half-open probe
		tripped = true
	}
	snap := *st
	persist := r.persist
	r.mu.Unlock()
	if persist != nil {
		persist(id, snap)
	}
	return tripped
}

// Reset clears one profile's state — the UI's "立即恢复" action.
func (r *Registry) Reset(id int64) {
	r.mu.Lock()
	delete(r.m, id)
	delete(r.probes, id)
	forget := r.forget
	r.mu.Unlock()
	if forget != nil {
		forget(id)
	}
}

// Snapshot returns a copy of all tracked state, for the status API.
func (r *Registry) Snapshot() map[int64]State {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make(map[int64]State, len(r.m))
	for id, st := range r.m {
		out[id] = *st
	}
	return out
}
