package llmpool

import (
	"context"
	"errors"
	"fmt"
	"hash/fnv"
	"iter"
	"log"
	"regexp"
	"strconv"
	"strings"
	"sync/atomic"
	"unicode/utf8"

	"github.com/RC-CHN/ARTEX/norma/llm"
	"github.com/RC-CHN/ARTEX/norma/transcript"
)

// Member is one LLM profile in the chain, already built into a provider (wrapped
// with the recorder by the caller, so a failed attempt is still recorded under
// its own profile name).
type Member struct {
	ID       int64  // llm_profiles.id
	Name     string // profile name, for logs / UI
	Model    string
	Format   string // "anthropic" | "openai"
	Priority int    // the profile's configured priority (display only)
	Active   bool   // is_default (display only)
	// Rank is the ordering key the caller assigned: higher goes first, and members
	// sharing a Rank take turns leading (load-spreading across duplicate keys).
	// The caller encodes "active profile heads the chain" as a Rank above every
	// user-settable priority, so this type needs no policy of its own.
	Rank int
	// WindowTokens is the profile's context window in tokens. A member whose
	// window can't hold the request is skipped rather than made to fail on it.
	WindowTokens int
	Prov         llm.Provider
}

// RankActive is the Rank the caller gives the chain head (the active profile, or
// an explicitly bound one) so it always outranks any configured priority.
const RankActive = int(^uint(0)>>1) - 1

// ErrExhausted is returned when every member of the chain failed.
var ErrExhausted = errors.New("LLM 轮询：所有配置均不可用")

// Pool is an llm.Provider that fails over across an ordered chain of members.
// It is safe for concurrent use: members are immutable after construction and
// all mutable state lives in the shared Registry.
type Pool struct {
	members []*Member // in chain order (active first, then priority DESC)
	health  *Registry
	rr      atomic.Uint64 // rotates the starting point within an equal-priority group
}

// New builds a Pool over members (already in chain order). Returns nil when the
// chain is empty. A single-member chain is still a valid Pool — it just behaves
// exactly like the bare provider.
func New(members []*Member, health *Registry) *Pool {
	if len(members) == 0 {
		return nil
	}
	if health == nil {
		health = NewRegistry(nil, nil)
	}
	return &Pool{members: members, health: health}
}

// Members returns the chain in order (read-only).
func (p *Pool) Members() []*Member { return p.members }

// Head returns the first member of the chain.
func (p *Pool) Head() *Member { return p.members[0] }

// Stream implements llm.Provider with failover.
//
// The one hard rule: a member may only be abandoned BEFORE it has yielded any
// non-diagnostic event. Once text or a tool_use has reached the caller, re-sending
// the same request to another model would duplicate output and corrupt the conversation
// history — so a mid-stream failure is surfaced as-is and left to the agent
// harness's resume logic. Fortunately the failures this exists for (402 no
// credit, 401 bad key, 429, 5xx) all surface during request establishment,
// before the body is read, so they always land in the safe window.
func (p *Pool) Stream(ctx context.Context, req llm.CompletionRequest) iter.Seq2[llm.StreamEvent, error] {
	return func(yield func(llm.StreamEvent, error) bool) {
		candidates := p.orderedMembers(ctx, req)
		var lastErr error
		var prevFailed *Member
		tried := 0

		runMember := func(m *Member, probeToken uint64) (done bool) {
			settled := false
			if probeToken != 0 {
				defer func() {
					if !settled {
						p.health.ReleaseProbe(m.ID, probeToken)
					}
				}()
			}
			if prevFailed != nil {
				log.Printf("[llmpool] LLM 故障转移：%q(%s) → %q(%s)，原因：%s",
					prevFailed.Name, prevFailed.Model, m.Name, m.Model, trimErr(lastErr))
			}
			tried++
			emitted := false
			var failed error
			for ev, err := range m.Prov.Stream(ctx, req) {
				if err != nil && !emitted && shouldFailover(ctx, err) {
					failed = err
					break // safe window: no non-diagnostic event reached the caller
				}
				// Structural diagnostics are forwarded for observability, but they do
				// not commit model output or make a pre-response failover unsafe.
				if ev.Type != llm.SEStreamDiagnostics {
					emitted = true
				}
				if !yield(ev, err) {
					return true // caller stopped consuming (cancel / early exit)
				}
				if err != nil {
					return true // terminal error already handed to the caller
				}
			}
			if failed == nil {
				p.health.Pass(m.ID) // completed (or failed in a non-failover way)
				settled = true
				return true
			}
			lastErr = failed
			prevFailed = m
			hard := isHardFailure(failed)
			if p.health.Trip(m.ID, trimErr(failed), hard) {
				log.Printf("[llmpool] 配置 %q(%s) 已熔断：%s", m.Name, m.Model, trimErr(failed))
			}
			settled = true
			return false
		}

		for _, m := range candidates {
			allowed, token := p.health.allowProbe(m.ID)
			if !allowed {
				continue
			}
			if runMember(m, token) {
				return
			}
		}
		if tried == 0 {
			fallback := p.members[0]
			if len(candidates) > 0 {
				fallback = candidates[0]
			}
			if allowed, token := p.health.acquireLastResort(fallback.ID); allowed {
				if runMember(fallback, token) {
					return
				}
			}
		}
		if lastErr == nil {
			log.Printf("[llmpool] 轮询链已耗尽(所有配置均在熔断冷却或探测中)")
			yield(llm.StreamEvent{}, fmt.Errorf("%w：所有配置均在熔断冷却或探测中", ErrExhausted))
			return
		}
		log.Printf("[llmpool] 轮询链已耗尽(%d 个配置全部失败)，最后错误：%s", tried, trimErr(lastErr))
		yield(llm.StreamEvent{}, fmt.Errorf("%w：%v", ErrExhausted, lastErr))
	}
}

// Complete implements llm.Provider with failover for non-streaming calls. A
// non-streaming request is atomic — it never delivers partial output — so every
// failover-eligible failure lands in the safe window and the next member can be
// tried without risk of duplicated output. Mirrors Stream's health-tripping and
// chain-exhaustion behavior.
func (p *Pool) Complete(ctx context.Context, req llm.CompletionRequest) (llm.Message, string, llm.Usage, error) {
	candidates := p.orderedMembers(ctx, req)
	var lastErr error
	var prevFailed *Member
	tried := 0

	runMember := func(m *Member, probeToken uint64) (llm.Message, string, llm.Usage, error, bool) {
		settled := false
		if probeToken != 0 {
			defer func() {
				if !settled {
					p.health.ReleaseProbe(m.ID, probeToken)
				}
			}()
		}
		if prevFailed != nil {
			log.Printf("[llmpool] LLM 故障转移：%q(%s) → %q(%s)，原因：%s",
				prevFailed.Name, prevFailed.Model, m.Name, m.Model, trimErr(lastErr))
		}
		tried++
		msg, sr, usage, err := m.Prov.Complete(ctx, req)
		if err == nil {
			p.health.Pass(m.ID)
			settled = true
			return msg, sr, usage, nil, true
		}
		if !shouldFailover(ctx, err) {
			// Non-failover error (e.g. ctx cancel, deterministic 4xx, incomplete
			// response): surface as-is without tripping health. On cancellation or
			// *llm.IncompleteResponseError, leave circuit state untouched (only
			// releasing any probe lease via defer, matching Stream).
			var incomplete *llm.IncompleteResponseError
			if ctx.Err() == nil && !errors.Is(err, context.Canceled) && !errors.Is(err, context.DeadlineExceeded) && !errors.As(err, &incomplete) {
				p.health.Pass(m.ID)
				settled = true
			}
			return msg, sr, usage, err, true
		}
		lastErr = err
		prevFailed = m
		hard := isHardFailure(err)
		if p.health.Trip(m.ID, trimErr(err), hard) {
			log.Printf("[llmpool] 配置 %q(%s) 已熔断：%s", m.Name, m.Model, trimErr(err))
		}
		settled = true
		return llm.Message{}, "", llm.Usage{}, nil, false
	}

	for _, m := range candidates {
		allowed, token := p.health.allowProbe(m.ID)
		if !allowed {
			continue
		}
		if msg, sr, usage, err, done := runMember(m, token); done {
			return msg, sr, usage, err
		}
	}
	if tried == 0 {
		fallback := p.members[0]
		if len(candidates) > 0 {
			fallback = candidates[0]
		}
		if allowed, token := p.health.acquireLastResort(fallback.ID); allowed {
			if msg, sr, usage, err, done := runMember(fallback, token); done {
				return msg, sr, usage, err
			}
		}
	}
	if lastErr == nil {
		log.Printf("[llmpool] 轮询链已耗尽(所有配置均在熔断冷却或探测中)")
		return llm.Message{}, "", llm.Usage{}, fmt.Errorf("%w：所有配置均在熔断冷却或探测中", ErrExhausted)
	}
	log.Printf("[llmpool] 轮询链已耗尽(%d 个配置全部失败)，最后错误：%s", tried, trimErr(lastErr))
	return llm.Message{}, "", llm.Usage{}, fmt.Errorf("%w：%v", ErrExhausted, lastErr)
}

// orderedMembers filters out members whose context window cannot hold req and
// rotates equal-priority groups. When a session key is present (PromptCacheKey
// or transcript session ID), a deterministic FNV-1a hash is used so repeated
// turns of the same session stick to the same backup profile and preserve its
// prompt cache; otherwise falls back to round-robin rotation.
func (p *Pool) orderedMembers(ctx context.Context, req llm.CompletionRequest) []*Member {
	est := estimateTokens(req)
	candidates := make([]*Member, 0, len(p.members))
	for _, m := range p.members {
		if m.WindowTokens > 0 && est > m.WindowTokens {
			continue // would 400 on length — not a useful failover target
		}
		candidates = append(candidates, m)
	}
	var offset uint64
	if key := sessionKey(ctx, req); key != "" {
		offset = fnv64a(key)
	} else {
		offset = p.rr.Add(1) - 1
	}
	return rotateGroups(candidates, offset)
}

func sessionKey(ctx context.Context, req llm.CompletionRequest) string {
	if k := strings.TrimSpace(req.PromptCacheKey); k != "" {
		return k
	}
	if k := strings.TrimSpace(llm.PromptCacheKeyFrom(ctx)); k != "" {
		return k
	}
	return strings.TrimSpace(transcript.SessionIDFrom(ctx))
}

func fnv64a(s string) uint64 {
	h := fnv.New64a()
	_, _ = h.Write([]byte(s))
	return h.Sum64()
}

// rotateGroups rotates each run of equal-ranked members by n, so profiles sharing
// a priority take turns going first (free load-spreading across duplicate keys).
// The chain head has its own Rank and always stays at the front.
func rotateGroups(in []*Member, n uint64) []*Member {
	out := make([]*Member, 0, len(in))
	for i := 0; i < len(in); {
		j := i + 1
		for j < len(in) && in[j].Rank == in[i].Rank {
			j++
		}
		g := in[i:j]
		if len(g) > 1 {
			off := int(n % uint64(len(g)))
			for k := range g {
				out = append(out, g[(k+off)%len(g)])
			}
		} else {
			out = append(out, g...)
		}
		i = j
	}
	return out
}

// statusRe pulls the HTTP status out of the SDK's error text, which is formatted
// as "<prefix>: status <code>: <body>" (norma/llm/retry.go). The SDK exposes no
// typed error, so the string is what we have.
var statusRe = regexp.MustCompile(`status (\d{3})`)

// statusOf returns the HTTP status carried by err, or 0 if it isn't one.
func statusOf(err error) int {
	m := statusRe.FindStringSubmatch(err.Error())
	if m == nil {
		return 0
	}
	code, _ := strconv.Atoi(m[1])
	return code
}

// shouldFailover reports whether err justifies trying the next profile.
//
// Never fails over on context cancellation — that's the user stopping a task or a
// task-level timeout, and burning a backup key on it would both waste credit and
// pollute the run's termination diagnosis. Never on 400 either: a malformed or
// over-long request fails identically everywhere.
func shouldFailover(ctx context.Context, err error) bool {
	if err == nil {
		return false
	}
	if ctx.Err() != nil || errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return false
	}
	var incomplete *llm.IncompleteResponseError
	if errors.As(err, &incomplete) {
		return false // response-level retries are exhausted; retain accounting/evidence
	}
	switch code := statusOf(err); {
	case code == 0:
		return true // no status → transport-level failure (reset / DNS / timeout)
	case code == 400:
		return false // bad or over-long request: identical everywhere
	case code == 401, code == 402, code == 403, code == 404, code == 408, code == 429:
		return true
	case code >= 500:
		return true
	}
	return false
}

// isHardFailure reports whether the failure is deterministic (the profile will
// keep failing until a human fixes it) rather than transient. Hard failures open
// the breaker on the first occurrence.
func isHardFailure(err error) bool {
	switch statusOf(err) {
	case 401, 402, 403, 404:
		return true
	}
	return false
}

// trimErr shortens an error for logs/UI on a UTF-8 boundary — provider bodies can be long.
func trimErr(err error) string {
	s := strings.TrimSpace(strings.ReplaceAll(err.Error(), "\n", " "))
	if len(s) <= 300 {
		return s
	}
	cut := 300
	for cut > 0 && 300-cut < utf8.UTFMax && !utf8.RuneStart(s[cut]) {
		cut--
	}
	return s[:cut] + "…"
}

// estimateTokens roughly sizes a request so members whose context window clearly
// can't hold it are skipped. Deliberately crude (~3.5 chars/token) and biased to
// over-estimate slightly; it only needs to tell "fits" from "nowhere near".
func estimateTokens(req llm.CompletionRequest) int {
	n := 0
	for _, s := range req.System {
		n += len(s)
	}
	for _, m := range req.Messages {
		n += blocksLen(m.Content)
	}
	for _, t := range req.Tools {
		// InputSchema is a decoded map, so its serialized size isn't available
		// cheaply — charge a flat ~120 chars per top-level property instead.
		n += len(t.Name) + len(t.Description) + len(t.InputSchema)*120
	}
	return n * 2 / 7 // ≈ len/3.5
}

func blocksLen(bs []llm.ContentBlock) int {
	n := 0
	for _, b := range bs {
		n += len(b.Text) + len(b.Thinking) + len(b.Input) + len(b.Name)
		if len(b.Content) > 0 {
			n += blocksLen(b.Content)
		}
	}
	return n
}
