import assert from "node:assert/strict";
import test from "node:test";
import {
  MAIN_CONSULTATION_SEG,
  applyMainActivityToStatus,
  isMainComposerBusy,
  isMainSegmentLive,
  normalizeMainChatStatus,
} from "./main-sessions.ts";

test("new human session is neither live nor busy while older session and consultation are running", () => {
  const status = normalizeMainChatStatus({
    running: true,
    running_segs: [0],
    consultation_running: true,
  });
  const sending = new Set();

  assert.equal(isMainSegmentLive(0, status, sending), true);
  assert.equal(isMainComposerBusy(0, status, sending, false), true);

  assert.equal(isMainSegmentLive(MAIN_CONSULTATION_SEG, status, sending), true);
  assert.equal(isMainComposerBusy(MAIN_CONSULTATION_SEG, status, sending, false), false);

  // Newly opened session #2 (seg 1) must be immediately idle & writable.
  assert.equal(isMainSegmentLive(1, status, sending), false);
  assert.equal(isMainComposerBusy(1, status, sending, false), false);
});

test("consultation running alone never blocks or marks human sessions live", () => {
  const status = normalizeMainChatStatus({
    running: true,
    running_segs: [],
    consultation_running: true,
  });
  const sending = new Set();

  assert.equal(isMainSegmentLive(0, status, sending), false);
  assert.equal(isMainComposerBusy(0, status, sending, false), false);
  assert.equal(isMainSegmentLive(1, status, sending), false);
  assert.equal(isMainComposerBusy(1, status, sending, false), false);
  assert.equal(isMainSegmentLive(MAIN_CONSULTATION_SEG, status, sending), true);
});

test("sending on one segment only marks that segment live and busy", () => {
  const status = normalizeMainChatStatus({
    running: false,
    running_segs: [],
    consultation_running: false,
  });
  const sending = new Set([1]);

  assert.equal(isMainSegmentLive(1, status, sending), true);
  assert.equal(isMainComposerBusy(1, status, sending, false), true);
  assert.equal(isMainSegmentLive(0, status, sending), false);
  assert.equal(isMainComposerBusy(0, status, sending, false), false);
});

test("terminal SSE activity clears only the settled lane and preserves other active lanes", () => {
  const initial = normalizeMainChatStatus({
    running: true,
    running_segs: [0, 1],
    consultation_running: true,
  });

  const afterSeg0Result = applyMainActivityToStatus(initial, {
    seq: 10,
    worker: "mainagent",
    kind: "result",
    summary: "done",
    ts: "2026-11-24T12:00:00Z",
    main_seg: 0,
  });
  assert.deepEqual([...afterSeg0Result.runningSegs], [1]);
  assert.equal(afterSeg0Result.consultationRunning, true);

  const afterConsultResult = applyMainActivityToStatus(afterSeg0Result, {
    seq: 11,
    worker: "mainagent",
    kind: "result",
    summary: "consult done",
    ts: "2026-11-24T12:00:01Z",
    main_seg: MAIN_CONSULTATION_SEG,
  });
  assert.deepEqual([...afterConsultResult.runningSegs], [1]);
  assert.equal(afterConsultResult.consultationRunning, false);
});

test("consultation round SSE marks consultation running without affecting human sessions", () => {
  const idle = normalizeMainChatStatus({
    running: false,
    running_segs: [],
    consultation_running: false,
  });
  const next = applyMainActivityToStatus(idle, {
    seq: 20,
    worker: "mainagent",
    kind: "round",
    summary: "自动处理 Worker #3 的请示 #1",
    ts: "2026-11-24T12:00:02Z",
    main_seg: MAIN_CONSULTATION_SEG,
  });
  assert.equal(next.consultationRunning, true);
  assert.deepEqual([...next.runningSegs], []);
});

test("unknown initial status falls back to conservative recentLive only before first authoritative poll", () => {
  const unknown = normalizeMainChatStatus(null);
  const sending = new Set();
  assert.equal(unknown.known, false);
  assert.equal(isMainSegmentLive(0, unknown, sending), false);
  assert.equal(isMainComposerBusy(0, unknown, sending, true), true);
  assert.equal(isMainComposerBusy(0, unknown, sending, false), false);
});

test("legacy backend status without running_segs falls back cleanly", () => {
  const legacy = normalizeMainChatStatus({ running: true }, 0);
  assert.equal(legacy.known, true);
  assert.deepEqual([...legacy.runningSegs], [0]);
  assert.equal(legacy.consultationRunning, false);
});
