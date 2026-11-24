import type { Activity } from "./types";

// Dedicated main_seg lane for asynchronous worker consultations (matches db.MainSegConsultation).
export const MAIN_CONSULTATION_SEG = -1;

export type MainChatStatus = {
  running: boolean;
  running_segs?: number[];
  consultation_running?: boolean;
};

export type MainRunningSnapshot = {
  known: boolean;
  runningSegs: Set<number>;
  consultationRunning: boolean;
};

export function emptyMainRunningSnapshot(): MainRunningSnapshot {
  return {
    known: false,
    runningSegs: new Set<number>(),
    consultationRunning: false,
  };
}

// Normalize GET /api/tasks/{id}/chat/status into an authoritative per-lane snapshot.
// Supports both the per-segment schema ({running_segs, consultation_running}) and
// legacy servers that only return {running}.
export function normalizeMainChatStatus(status: MainChatStatus | null, fallbackSeg = 0): MainRunningSnapshot {
  if (!status) return emptyMainRunningSnapshot();
  const hasStructured = Array.isArray(status.running_segs) || typeof status.consultation_running === "boolean";
  if (hasStructured) {
    const runningSegs = new Set<number>();
    for (const seg of status.running_segs ?? []) {
      if (Number.isInteger(seg) && seg >= 0) runningSegs.add(seg);
    }
    return {
      known: true,
      runningSegs,
      consultationRunning: Boolean(status.consultation_running),
    };
  }
  return {
    known: true,
    runningSegs: status.running ? new Set<number>([fallbackSeg]) : new Set<number>(),
    consultationRunning: false,
  };
}

export function withMainSegmentRunning(
  snapshot: MainRunningSnapshot,
  seg: number,
  running: boolean,
): MainRunningSnapshot {
  if (seg === MAIN_CONSULTATION_SEG) {
    if (snapshot.known && snapshot.consultationRunning === running) return snapshot;
    return {
      known: true,
      runningSegs: new Set(snapshot.runningSegs),
      consultationRunning: running,
    };
  }
  const has = snapshot.runningSegs.has(seg);
  if (snapshot.known && has === running) return snapshot;
  const next = new Set(snapshot.runningSegs);
  if (running) next.add(seg);
  else next.delete(seg);
  return {
    known: true,
    runningSegs: next,
    consultationRunning: snapshot.consultationRunning,
  };
}

export function isMainSegmentLive(
  seg: number,
  snapshot: MainRunningSnapshot,
  sendingSegs: ReadonlySet<number>,
): boolean {
  if (seg === MAIN_CONSULTATION_SEG) return snapshot.consultationRunning;
  return sendingSegs.has(seg) || snapshot.runningSegs.has(seg);
}

export function isMainComposerBusy(
  seg: number,
  snapshot: MainRunningSnapshot,
  sendingSegs: ReadonlySet<number>,
  fallbackRecentLive: boolean,
): boolean {
  if (seg === MAIN_CONSULTATION_SEG) return false;
  if (sendingSegs.has(seg)) return true;
  if (snapshot.known) return snapshot.runningSegs.has(seg);
  return fallbackRecentLive;
}

// Optimistically reflect terminal or consultation-start SSE frames on the specific
// main-agent lane without disturbing any other concurrent segment or consultation.
export function applyMainActivityToStatus(
  snapshot: MainRunningSnapshot,
  activity: Pick<Activity, "worker" | "kind" | "is_error" | "main_seg">,
): MainRunningSnapshot {
  if (activity.worker !== "mainagent") return snapshot;
  const seg = activity.main_seg ?? 0;
  if (activity.kind === "result" || (activity.kind === "text" && activity.is_error)) {
    return withMainSegmentRunning(snapshot, seg, false);
  }
  if (
    seg === MAIN_CONSULTATION_SEG &&
    (activity.kind === "round" || activity.kind === "thinking" || activity.kind === "tool_use")
  ) {
    return withMainSegmentRunning(snapshot, MAIN_CONSULTATION_SEG, true);
  }
  return snapshot;
}
