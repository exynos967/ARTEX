import assert from "node:assert/strict";
import test from "node:test";
import {
  CODE_PREVIEW_THRESHOLD_BYTES,
  buildCodePreview,
  collapseLogPreview,
  computeExecWindowTransition,
  computeVirtualWindow,
  mapWithConcurrency,
  pruneSessionStoreLRU,
  touchAccessOrder,
  trimBoundedItems,
} from "./view-guards.ts";

function session(id, overrides = {}) {
  return {
    items: [{ seq: id }, { seq: id + 1 }],
    loaded: true,
    loading: false,
    loadingMore: false,
    hasMore: true,
    earliestSeq: id,
    unread: id,
    lastTs: `2026-11-24T00:00:${String(id % 60).padStart(2, "0")}Z`,
    ...overrides,
  };
}

test("pruneSessionStoreLRU evicts oldest inactive loaded sessions from a Record while preserving metadata", () => {
  const store = {};
  let order = [];
  for (let i = 1; i <= 10; i++) {
    const key = `intent:${i}`;
    store[key] = session(i);
    order = touchAccessOrder(order, key);
  }
  // Cold unloaded session with a tiny accounting tail must not count toward loaded limit.
  store["intent:cold"] = session(99, { loaded: false, items: [{ seq: 99 }], unread: 5 });

  // Active key is the oldest one (intent:1) — it must NEVER be evicted.
  const pruned = pruneSessionStoreLRU(store, "intent:1", order, 8);
  assert.notEqual(pruned, store);

  // Loaded count should drop from 10 to 8 by evicting intent:2 and intent:3.
  const loadedKeys = Object.entries(pruned)
    .filter(([, s]) => s.loaded)
    .map(([k]) => k);
  assert.equal(loadedKeys.length, 8);
  assert.equal(pruned["intent:1"].loaded, true);
  assert.equal(pruned["intent:1"].items.length, 2);

  for (const evictedKey of ["intent:2", "intent:3"]) {
    assert.equal(pruned[evictedKey].loaded, false);
    assert.deepEqual(pruned[evictedKey].items, []);
    assert.equal(pruned[evictedKey].hasMore, false);
    assert.equal(pruned[evictedKey].earliestSeq, 0);
    // Lightweight sidebar metadata preserved.
    assert.equal(pruned[evictedKey].unread, store[evictedKey].unread);
    assert.equal(pruned[evictedKey].lastTs, store[evictedKey].lastTs);
  }

  for (let i = 4; i <= 10; i++) {
    assert.equal(pruned[`intent:${i}`].loaded, true);
    assert.equal(pruned[`intent:${i}`].items.length, 2);
  }
  // Cold session untouched.
  assert.equal(pruned["intent:cold"].items.length, 1);
  assert.equal(pruned["intent:cold"].unread, 5);
});

test("pruneSessionStoreLRU works with Map stores, preserves in-flight loads, and bails out under cap", () => {
  const underCap = new Map([
    ["main:0", session(1)],
    ["plan", session(2)],
  ]);
  assert.equal(pruneSessionStoreLRU(underCap, "main:0", ["main:0", "plan"], 8), underCap);

  const mapStore = new Map([
    ["s1", session(1, { loading: true })],
    ["s2", session(2)],
    ["s3", session(3)],
    ["s4", session(4)],
  ]);
  const pruned = pruneSessionStoreLRU(mapStore, "s4", ["s1", "s2", "s3", "s4"], 2);
  assert.ok(pruned instanceof Map);
  // s1 is loading (protected), s4 is active (protected), so s2 and s3 get evicted.
  assert.equal(pruned.get("s1").loaded, true);
  assert.equal(pruned.get("s4").loaded, true);
  assert.equal(pruned.get("s2").loaded, false);
  assert.deepEqual(pruned.get("s2").items, []);
  assert.equal(pruned.get("s3").loaded, false);
  assert.deepEqual(pruned.get("s3").items, []);
});

test("trimBoundedItems enforces normal cap when pinned and hard scrolledCap when scrolled up", () => {
  const items = Array.from({ length: 4500 }, (_, i) => i + 1);

  const pinned = trimBoundedItems(items, true, 2000, 4000);
  assert.equal(pinned.length, 2000);
  assert.equal(pinned[0], 2501);
  assert.equal(pinned.at(-1), 4500);

  const scrolled = trimBoundedItems(items, false, 2000, 4000);
  assert.equal(scrolled.length, 4000);
  assert.equal(scrolled[0], 501);
  assert.equal(scrolled.at(-1), 4500);

  const small = Array.from({ length: 1500 }, (_, i) => i);
  assert.equal(trimBoundedItems(small, true, 2000, 4000), small);
  assert.equal(trimBoundedItems(small, false, 2000, 4000), small);
});

test("buildCodePreview leaves payloads <= 64 KiB intact and truncates larger payloads cleanly", () => {
  assert.equal(CODE_PREVIEW_THRESHOLD_BYTES, 65536);

  const exact = "a".repeat(CODE_PREVIEW_THRESHOLD_BYTES);
  const exactRes = buildCodePreview(exact);
  assert.equal(exactRes.isLarge, false);
  assert.equal(exactRes.preview, exact);
  assert.equal(exactRes.totalChars, 65536);
  assert.equal(exactRes.truncatedChars, 0);

  const large = "x".repeat(CODE_PREVIEW_THRESHOLD_BYTES) + "TAIL_DATA";
  const largeRes = buildCodePreview(large);
  assert.equal(largeRes.isLarge, true);
  assert.equal(largeRes.preview.length, 65536);
  assert.equal(largeRes.totalChars, 65536 + 9);
  assert.equal(largeRes.truncatedChars, 9);
});

test("mapWithConcurrency caps in-flight tasks, preserves result order, and propagates failures", async () => {
  assert.deepEqual(await mapWithConcurrency([], 4, async () => 1), []);

  let active = 0;
  let peak = 0;
  const inputs = Array.from({ length: 12 }, (_, i) => i + 1);
  const outputs = await mapWithConcurrency(inputs, 4, async (n, idx) => {
    active++;
    peak = Math.max(peak, active);
    // Reverse delay so fast later items finish before earlier ones, testing order preservation.
    await new Promise((resolve) => setTimeout(resolve, (13 - n) * 2));
    active--;
    return `${idx}:${n * 10}`;
  });

  assert.equal(peak, 4);
  assert.deepEqual(
    outputs,
    inputs.map((n, idx) => `${idx}:${n * 10}`),
  );

  // Failure stops scheduling remaining items and rejects cleanly.
  let started = 0;
  await assert.rejects(
    () =>
      mapWithConcurrency(Array.from({ length: 10 }, (_, i) => i), 2, async (n) => {
        started++;
        if (n === 1) throw new Error("boom-1");
        await new Promise((resolve) => setTimeout(resolve, 10));
        return n;
      }),
    /boom-1/,
  );
  assert.ok(started <= 4, `expected aborted pool to stop early, started=${started}`);
});

test("computeVirtualWindow computes bounded slices, spacers, and clamps past-bottom scrollTop", () => {
  assert.deepEqual(computeVirtualWindow(0, 0, 600, 24, 15), {
    startIndex: 0,
    endIndex: 0,
    topSpacerPx: 0,
    bottomSpacerPx: 0,
  });

  // Top of a 3000-row list (viewport 600 / 24 = 25 visible + 15 overscan = 40 rendered).
  const top = computeVirtualWindow(3000, 0, 600, 24, 15);
  assert.deepEqual(top, {
    startIndex: 0,
    endIndex: 40,
    topSpacerPx: 0,
    bottomSpacerPx: (3000 - 40) * 24,
  });

  // Middle scroll position.
  const mid = computeVirtualWindow(3000, 1000 * 24, 600, 24, 15);
  assert.deepEqual(mid, {
    startIndex: 985,
    endIndex: 1040,
    topSpacerPx: 985 * 24,
    bottomSpacerPx: (3000 - 1040) * 24,
  });

  // Wrapped lines taller than estimate can yield scrollTop > total * itemHeight:
  // window must clamp to the tail instead of returning an empty slice.
  const pastBottom = computeVirtualWindow(3000, 120000, 600, 24, 15);
  assert.equal(pastBottom.endIndex, 3000);
  assert.equal(pastBottom.startIndex, 3000 - 25 - 15);
  assert.equal(pastBottom.bottomSpacerPx, 0);
  assert.equal(pastBottom.topSpacerPx, pastBottom.startIndex * 24);
});

test("collapseLogPreview keeps single-line text intact and collapses CRLF/LF/CR breaks", () => {
  assert.equal(collapseLogPreview("plain log message"), "plain log message");
  assert.equal(
    collapseLogPreview("Error: fail\n  at foo (a.ts:1)\r\n  at bar\rnext"),
    "Error: fail ↵   at foo (a.ts:1) ↵   at bar ↵ next",
  );
});

test("computeExecWindowTransition resets on sessionKey switch and bumps on prepended history", () => {
  // Initial load on session A.
  const s1 = computeExecWindowTransition(null, {
    sessionKey: "1:main:0",
    taskId: "1",
    minRealSeq: 500,
    maxRealSeq: 700,
    groupCount: 180,
  });
  assert.equal(s1.action, "reset");

  // Tail SSE append keeps current visibleCount intact.
  const s2 = computeExecWindowTransition(s1.nextSnapshot, {
    sessionKey: "1:main:0",
    taskId: "1",
    minRealSeq: 500,
    maxRealSeq: 705,
    groupCount: 183,
  });
  assert.equal(s2.action, "keep");
  assert.equal(s2.delta, 0);

  // Scroll-up loadEarlier prepends older steps on same sessionKey -> bumps by added groups.
  const s3 = computeExecWindowTransition(s2.nextSnapshot, {
    sessionKey: "1:main:0",
    taskId: "1",
    minRealSeq: 300,
    maxRealSeq: 705,
    groupCount: 303,
  });
  assert.equal(s3.action, "bump");
  assert.equal(s3.delta, 120);

  // Front-trimming during live overflow raises minRealSeq -> never bumps.
  const s4 = computeExecWindowTransition(s3.nextSnapshot, {
    sessionKey: "1:main:0",
    taskId: "1",
    minRealSeq: 350,
    maxRealSeq: 750,
    groupCount: 303,
  });
  assert.equal(s4.action, "keep");

  // Switching sessionKey resets deterministically EVEN when seq ranges overlap!
  const s5 = computeExecWindowTransition(s4.nextSnapshot, {
    sessionKey: "1:intent:9",
    taskId: "1",
    minRealSeq: 400,
    maxRealSeq: 600,
    groupCount: 150,
  });
  assert.equal(s5.action, "reset");

  // Initial empty-to-loaded transition (e.g. worker session with only synthetic intent seq -1 -> real steps)
  // keeps initial window without bumping.
  const workerEmpty = computeExecWindowTransition(s5.nextSnapshot, {
    sessionKey: "1:intent:10",
    taskId: "1",
    minRealSeq: 0,
    maxRealSeq: 0,
    groupCount: 1,
  });
  assert.equal(workerEmpty.action, "reset");
  const workerLoaded = computeExecWindowTransition(workerEmpty.nextSnapshot, {
    sessionKey: "1:intent:10",
    taskId: "1",
    minRealSeq: 800,
    maxRealSeq: 950,
    groupCount: 90,
  });
  assert.equal(workerLoaded.action, "keep");
  const workerPrepended = computeExecWindowTransition(workerLoaded.nextSnapshot, {
    sessionKey: "1:intent:10",
    taskId: "1",
    minRealSeq: 600,
    maxRealSeq: 950,
    groupCount: 210,
  });
  assert.equal(workerPrepended.action, "bump");
  assert.equal(workerPrepended.delta, 120);

  // Legacy fallback without sessionKey still resets on disjoint seq ranges.
  const legacy1 = computeExecWindowTransition(null, {
    taskId: "1",
    minRealSeq: 100,
    maxRealSeq: 200,
    groupCount: 50,
  });
  const legacy2 = computeExecWindowTransition(legacy1.nextSnapshot, {
    taskId: "1",
    minRealSeq: 300,
    maxRealSeq: 400,
    groupCount: 50,
  });
  assert.equal(legacy2.action, "reset");
});
