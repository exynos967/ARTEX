package noa

import (
	"fmt"
	"sort"
	"strings"
)

// Truncation defaults. These bound how much of a large tool result survives;
// head and tail together usually carry the command and its verdict, which is
// what a later reader actually needs.
const (
	truncateMinOutputTokens = 1000
	truncateKeepPrefixChars = 2000
	truncateKeepSuffixChars = 2000
	// truncateTargetPct is the hysteresis low-water target (75% of limit) when
	// truncation triggers (default 95%). Cutting to 75% in one batch leaves a
	// wide stable band so subsequent turns do not re-trigger and break KV cache.
	truncateTargetPct = 0.75
)

// TruncateResult reports what the valve did.
type TruncateResult struct {
	Messages       []CoreMessage
	TruncatedCount int
	SavedTokens    int
	// TruncatedIDs records the CoreMessage IDs shortened during this pass
	// (sticky replays and newly truncated items) so callers can persist them
	// across turns for cache-preserving hysteresis.
	TruncatedIDs []string
}

// TruncateLargeToolOutputs is the mechanical last resort.
//
// Everything else in noa depends on the model choosing to compress. This does
// not: when the context is about to overflow, the largest tool results are cut
// down in one batch to the hysteresis target (75% of the limit). It is the only
// thing standing between an uncooperative model and a request the provider
// rejects outright.
//
// It rewrites only what is SENT. The stored history keeps the originals, so
// message identity is unchanged. Callers that want cross-turn prefix stability
// should pass previously truncated IDs via TruncateLargeToolOutputsSticky.
func TruncateLargeToolOutputs(msgs []CoreMessage, tokenCount int, cfg Config, count TokenCountFn) TruncateResult {
	return TruncateLargeToolOutputsSticky(msgs, tokenCount, cfg, count, nil)
}

// ApplyStickyTruncations deterministically re-applies truncation to tool results
// whose ID (or ToolCallID) is already in stickyIDs, regardless of tokenCount,
// so previously truncated early tool outputs never flip back to raw text and
// invalidate the prompt cache.
func ApplyStickyTruncations(msgs []CoreMessage, stickyIDs map[string]bool, count TokenCountFn) TruncateResult {
	if count == nil {
		count = DefaultCountTokens
	}
	res := TruncateResult{Messages: msgs}
	if len(stickyIDs) == 0 {
		return res
	}
	var out []CoreMessage
	saved := 0
	for i, m := range msgs {
		if m.ContentType != CTToolResult || m.Text == "" {
			continue
		}
		if strings.Contains(m.Text, TruncationMarker) {
			continue
		}
		if !stickyIDs[m.ID] && (m.ToolCallID == "" || !stickyIDs[m.ToolCallID]) {
			continue
		}
		if len([]rune(m.Text)) <= truncateKeepPrefixChars+truncateKeepSuffixChars {
			continue
		}
		origTok := count(m.Text)
		replaced := truncateBody(m.Text, origTok)
		if out == nil {
			out = append([]CoreMessage(nil), msgs...)
		}
		out[i].Text = replaced
		saved += max(0, origTok-count(replaced))
		res.TruncatedCount++
		res.TruncatedIDs = append(res.TruncatedIDs, m.ID)
	}
	if out != nil {
		res.Messages = out
		res.SavedTokens = saved
	}
	return res
}

// TruncateLargeToolOutputsSticky is the batch/hysteresis-stable form of
// TruncateLargeToolOutputs:
//  1. It always re-applies truncation to any IDs in stickyIDs so earlier turns'
//     truncations stay byte-identical and never flip-flop.
//  2. Only when (tokenCount - stickySaved) still meets or exceeds the high-water
//     threshold (cfg.Truncate.Threshold * limit, default 95%) does it select new
//     tool outputs to truncate in a single batch down to 75% of the limit.
func TruncateLargeToolOutputsSticky(msgs []CoreMessage, tokenCount int, cfg Config, count TokenCountFn, stickyIDs map[string]bool) TruncateResult {
	if count == nil {
		count = DefaultCountTokens
	}
	res := ApplyStickyTruncations(msgs, stickyIDs, count)
	work := res.Messages
	saved := res.SavedTokens

	limit := cfg.ModelContextLimit
	if limit <= 0 || cfg.Truncate.Threshold <= 0 {
		return res
	}
	threshold := int(cfg.Truncate.Threshold * float64(limit))
	effectiveTokens := max(0, tokenCount-saved)
	if effectiveTokens < threshold {
		return res
	}
	// Aim well below the threshold (75% of limit, or 90% of threshold for small
	// custom thresholds) so one batch buys a wide cache-stable headroom band.
	target := int(truncateTargetPct * float64(limit))
	if alt := int(float64(threshold) * 0.9); alt < target {
		target = alt
	}

	protectRecent := max(cfg.PreserveRecentMessages, 0)
	cutoff := len(work) - protectRecent

	type candidate struct {
		idx    int
		tokens int
	}
	var candidates []candidate
	for i, m := range work {
		if i >= cutoff {
			break
		}
		if m.ContentType != CTToolResult || m.Text == "" {
			continue
		}
		if strings.Contains(m.Text, TruncationMarker) {
			continue // already truncated; cutting it again reclaims nothing
		}
		n := count(m.Text)
		if n < truncateMinOutputTokens {
			continue
		}
		candidates = append(candidates, candidate{idx: i, tokens: n})
	}
	if len(candidates) == 0 {
		return res
	}
	// Largest first: the fewest edits that get under the target.
	sort.SliceStable(candidates, func(a, b int) bool {
		return candidates[a].tokens > candidates[b].tokens
	})

	var out []CoreMessage
	if res.TruncatedCount > 0 {
		out = work // already a fresh copy from ApplyStickyTruncations
	}
	newCount := 0
	for _, c := range candidates {
		if tokenCount-saved <= target {
			break
		}
		orig := work[c.idx].Text
		if len([]rune(orig)) <= truncateKeepPrefixChars+truncateKeepSuffixChars {
			continue
		}
		if out == nil {
			out = append([]CoreMessage(nil), work...)
		}
		replaced := truncateBody(orig, c.tokens)
		saved += max(0, c.tokens-count(replaced))
		out[c.idx].Text = replaced
		res.TruncatedCount++
		res.TruncatedIDs = append(res.TruncatedIDs, out[c.idx].ID)
		newCount++
	}
	if newCount == 0 {
		return res
	}
	res.Messages = out
	res.SavedTokens = saved
	return res
}

// truncateBody keeps the head and tail around a marker naming the original size.
func truncateBody(s string, tokens int) string {
	r := []rune(s)
	head := string(r[:truncateKeepPrefixChars])
	tail := string(r[len(r)-truncateKeepSuffixChars:])
	return fmt.Sprintf("%s\n\n...%s — original ~%d tokens]...\n\n%s",
		head, TruncationMarker, tokens, tail)
}

// emergencyTruncateNode is the pipeline stage wrapper.
func emergencyTruncateNode() PipelineNode {
	return nodeFunc{
		name: "emergency-truncate",
		enabled: func(_ NodeIO, ctx PipelineContext) bool {
			limit := ctx.Config.ModelContextLimit
			return limit > 0 && ctx.TokenCount >= int(ctx.Config.Truncate.Threshold*float64(limit))
		},
		run: func(io NodeIO, ctx PipelineContext) NodeIO {
			r := TruncateLargeToolOutputs(io.Messages, ctx.TokenCount, ctx.Config, ctx.CountTokens)
			io.Messages = r.Messages
			io.TruncatedCount = r.TruncatedCount
			return io
		},
	}
}
