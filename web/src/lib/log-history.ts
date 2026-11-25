import type { LogLine } from "./types";

const LIVE_LIMIT = 3000;
export const HISTORY_LIMIT = 5000;

export function appendLiveLine(rows: LogLine[], line: LogLine): LogLine[] {
  if (rows.some((row) => row.seq === line.seq)) return rows;
  const capacity = Math.min(HISTORY_LIMIT, Math.max(LIVE_LIMIT, rows.length));
  const next = rows.slice(Math.max(0, rows.length + 1 - capacity));
  next.push(line);
  return next;
}

export function historyPageSize(rowCount: number): number {
  return Math.min(200, Math.max(0, HISTORY_LIMIT - rowCount));
}

export async function loadHistoryPage(
  inFlight: { current: boolean },
  rowCount: number,
  before: number,
  load: (url: string) => Promise<void>,
): Promise<void> {
  const limit = historyPageSize(rowCount);
  if (inFlight.current || limit === 0) return;
  inFlight.current = true;
  try {
    const cursor = before > 0 ? `before=${before}&` : "";
    await load(`/api/logs/history?${cursor}limit=${limit}`);
  } finally {
    inFlight.current = false;
  }
}

export function prependHistory(rows: LogLine[], items: LogLine[]): LogLine[] {
  // Historical rows get synthetic sequence numbers below every displayed row.
  const minSeq = rows.reduce((min, row) => Math.min(min, row.seq ?? 0), 0);
  const older = items.map((row, i) => ({ ...row, seq: minSeq - items.length + i }));
  const seen = new Set<number>();
  const deduped = [...older, ...rows].filter((row) => {
    if (!row.db_id) return true;
    if (seen.has(row.db_id)) return false;
    seen.add(row.db_id);
    return true;
  });
  return deduped.slice(-HISTORY_LIMIT);
}
