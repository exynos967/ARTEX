package noa

import (
	"slices"
	"strings"
	"testing"
)

// TestTruncateBatchTargetReaches75Percent verifies that a single truncation
// sweep cuts down to the 75% hysteresis target (rather than stopping at 85.5%)
// and reports the truncated CoreMessage IDs.
func TestTruncateBatchTargetReaches75Percent(t *testing.T) {
	cfg := DefaultConfig(200000) // threshold = 190000, target = 150000 (75%)
	msgs := []CoreMessage{
		bigToolResult("r1", 100000), // ~25000 tokens -> saves ~24000
		bigToolResult("r2", 100000), // ~25000 tokens -> saves ~24000
		bigToolResult("r3", 100000), // ~25000 tokens -> should stay untouched once <= 150000
	}
	for range 5 {
		msgs = append(msgs, msg("tail", RoleUser, CTText, "recent"))
	}

	// 195000 -> cutting r1 alone leaves ~171000 (> 150000, whereas old 85.5% target
	// 171000 would have stopped after 1). Cutting r1 + r2 reaches ~147000 <= 150000.
	r := TruncateLargeToolOutputs(msgs, 195000, cfg, nil)
	if r.TruncatedCount != 2 {
		t.Fatalf("TruncatedCount=%d, want 2 to reach 75%% target (saved=%d)", r.TruncatedCount, r.SavedTokens)
	}
	if 195000-r.SavedTokens > 150000 {
		t.Fatalf("post-truncate tokens=%d, want <= 150000 (75%% of 200000)", 195000-r.SavedTokens)
	}
	if !slices.Equal(r.TruncatedIDs, []string{"r1", "r2"}) {
		t.Fatalf("TruncatedIDs=%v, want [r1 r2]", r.TruncatedIDs)
	}
	if strings.Contains(r.Messages[2].Text, TruncationMarker) {
		t.Fatal("r3 should stay intact once the 75% target is reached")
	}
}

// TestTruncateStickyPreservesEarlierTruncationsAndSuppressesFlipFlop verifies
// that once IDs are truncated in an epoch, subsequent calls re-apply those exact
// truncations without flipping to newer larger outputs until effective usage
// climbs back to the 95% threshold.
func TestTruncateStickyPreservesEarlierTruncationsAndSuppressesFlipFlop(t *testing.T) {
	cfg := DefaultConfig(200000) // threshold = 190000, target = 150000
	tail := make([]CoreMessage, 5)
	for i := range tail {
		tail[i] = msg("tail"+idFor(i), RoleUser, CTText, "recent")
	}

	// Turn 1: trigger at 195000 -> truncates r1 (200K chars = 50K tokens -> saves ~49K -> 146K <= 150K).
	msgs1 := append([]CoreMessage{
		bigToolResult("r1", 200000),
		bigToolResult("r2", 40000),
	}, tail...)
	res1 := TruncateLargeToolOutputsSticky(msgs1, 195000, cfg, nil, nil)
	if !slices.Equal(res1.TruncatedIDs, []string{"r1"}) {
		t.Fatalf("turn 1 TruncatedIDs=%v, want [r1]", res1.TruncatedIDs)
	}
	sticky := map[string]bool{}
	for _, id := range res1.TruncatedIDs {
		sticky[id] = true
	}

	// Turn 2: a NEW, EVEN LARGER tool result (r3, 240K chars = 60K tokens) exits
	// the protected tail. Raw tokenCount is 205000 (> 190000), but after sticky
	// replay of r1 (~49K saved), effective tokens = ~156000 (< 190000).
	// Result: ONLY r1 is truncated — r3 is NOT truncated and r1 does NOT flip back.
	msgs2 := append([]CoreMessage{
		bigToolResult("r1", 200000),
		bigToolResult("r2", 40000),
		bigToolResult("r3", 240000),
	}, tail...)
	res2 := TruncateLargeToolOutputsSticky(msgs2, 205000, cfg, nil, sticky)
	if !slices.Equal(res2.TruncatedIDs, []string{"r1"}) {
		t.Fatalf("turn 2 TruncatedIDs=%v, want [r1] only (no flip-flop to r3)", res2.TruncatedIDs)
	}
	if res2.Messages[0].Text != res1.Messages[0].Text {
		t.Fatal("r1 truncated body changed between turn 1 and turn 2")
	}
	if strings.Contains(res2.Messages[2].Text, TruncationMarker) {
		t.Fatal("r3 was prematurely truncated below effective 95% threshold")
	}

	// Turn 3: even if usage temporarily dips well below 95% (120000), r1 stays
	// truncated so the earlier prefix never reverts to raw bytes.
	res3 := TruncateLargeToolOutputsSticky(msgs2, 120000, cfg, nil, sticky)
	if !slices.Equal(res3.TruncatedIDs, []string{"r1"}) {
		t.Fatalf("turn 3 low-usage TruncatedIDs=%v, want [r1] kept sticky", res3.TruncatedIDs)
	}
	if res3.Messages[0].Text != res1.Messages[0].Text {
		t.Fatal("r1 reverted or changed at lower token count")
	}

	// Turn 4: effective usage crosses 190000 again (raw 245000 - 49000 sticky = 196000 >= 190000).
	// Now a second batch fires: r1 stays truncated AND r3 is added to get back <= 150000.
	res4 := TruncateLargeToolOutputsSticky(msgs2, 245000, cfg, nil, sticky)
	if !slices.Equal(res4.TruncatedIDs, []string{"r1", "r3"}) {
		t.Fatalf("turn 4 second-epoch TruncatedIDs=%v, want [r1 r3]", res4.TruncatedIDs)
	}
	if res4.Messages[0].Text != res1.Messages[0].Text {
		t.Fatal("r1 changed during second-epoch sweep")
	}
}
