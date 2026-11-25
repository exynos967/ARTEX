// Pure, dependency-free frontend performance guards shared across transcript,
// session store, code viewer, live log, and list-loading views.

export const DEFAULT_MAX_LOADED_SESSIONS = 8;
export const DEFAULT_NORMAL_ITEM_CAP = 2000;
export const DEFAULT_SCROLLED_ITEM_CAP = 4000;
export const CODE_PREVIEW_THRESHOLD_BYTES = 64 * 1024;

export interface EvictableSessionEntry {
  items: readonly unknown[];
  loaded?: boolean;
  loading?: boolean;
  loadingMore?: boolean;
  hasMore?: boolean;
  earliestSeq?: number;
}

export interface CodePreview {
  isLarge: boolean;
  preview: string;
  totalChars: number;
  truncatedChars: number;
}

export interface VirtualWindow {
  startIndex: number;
  endIndex: number;
  topSpacerPx: number;
  bottomSpacerPx: number;
}

export interface ExecWindowSnapshot {
  sessionKey?: string;
  taskId?: string;
  minRealSeq: number;
  maxRealSeq: number;
  groupCount: number;
}

export interface ExecWindowTransition {
  action: "reset" | "keep" | "bump";
  delta: number;
  nextSnapshot: ExecWindowSnapshot;
}

// Moves `key` to the most-recently-used tail of an access-order list.
export function touchAccessOrder(accessOrder: readonly string[], key: string): string[] {
  if (!key) return [...accessOrder];
  if (accessOrder[accessOrder.length - 1] === key) return [...accessOrder];
  const next = accessOrder.filter((existing) => existing !== key);
  next.push(key);
  return next;
}

function isLoadedEntry(entry: EvictableSessionEntry): boolean {
  if (entry.loaded !== undefined) return entry.loaded;
  return entry.items.length > 0;
}

function evictEntry<T extends EvictableSessionEntry>(entry: T): T {
  const next: EvictableSessionEntry = {
    ...entry,
    items: [],
  };
  if (entry.loaded !== undefined) next.loaded = false;
  if (entry.loadingMore !== undefined) next.loadingMore = false;
  if (entry.hasMore !== undefined) next.hasMore = false;
  if (entry.earliestSeq !== undefined) next.earliestSeq = 0;
  return next as T;
}

function pickEvictionKeys<T extends EvictableSessionEntry>(
  entries: Iterable<[string, T]>,
  activeKey: string,
  accessOrder: readonly string[],
  maxLoaded: number,
): Set<string> {
  const cap = Math.max(1, Math.floor(Number.isFinite(maxLoaded) ? maxLoaded : DEFAULT_MAX_LOADED_SESSIONS));
  const loadedKeys: string[] = [];
  const candidates: string[] = [];

  for (const [key, entry] of entries) {
    if (!isLoadedEntry(entry)) continue;
    loadedKeys.push(key);
    if (key !== activeKey && !entry.loading) {
      candidates.push(key);
    }
  }

  const excess = loadedKeys.length - cap;
  if (excess <= 0 || candidates.length === 0) return new Set();

  // Higher index = more recently accessed; keys absent from accessOrder rank oldest (-1).
  const recency = new Map<string, number>();
  for (let i = 0; i < accessOrder.length; i++) {
    recency.set(accessOrder[i], i);
  }

  const ordered = candidates
    .map((key, index) => ({ key, rank: recency.get(key) ?? -1, index }))
    .sort((a, b) => (a.rank !== b.rank ? a.rank - b.rank : a.index - b.index));

  const toEvict = new Set<string>();
  const count = Math.min(excess, ordered.length);
  for (let i = 0; i < count; i++) {
    toEvict.add(ordered[i].key);
  }
  return toEvict;
}

// Evicts the heavy `items` arrays of least-recently-used inactive sessions when
// more than `maxLoaded` sessions are cached, preserving lightweight metadata
// (such as `unread` / `lastTs`) so revisiting an evicted session re-fetches cleanly.
export function pruneSessionStoreLRU<T extends EvictableSessionEntry>(
  store: Map<string, T>,
  activeKey: string,
  accessOrder: readonly string[],
  maxLoaded?: number,
): Map<string, T>;
export function pruneSessionStoreLRU<T extends EvictableSessionEntry>(
  store: Record<string, T>,
  activeKey: string,
  accessOrder: readonly string[],
  maxLoaded?: number,
): Record<string, T>;
export function pruneSessionStoreLRU<T extends EvictableSessionEntry>(
  store: Map<string, T> | Record<string, T>,
  activeKey: string,
  accessOrder: readonly string[],
  maxLoaded = DEFAULT_MAX_LOADED_SESSIONS,
): Map<string, T> | Record<string, T> {
  if (store instanceof Map) {
    const toEvict = pickEvictionKeys(store.entries(), activeKey, accessOrder, maxLoaded);
    if (toEvict.size === 0) return store;
    const next = new Map<string, T>();
    for (const [key, entry] of store.entries()) {
      next.set(key, toEvict.has(key) ? evictEntry(entry) : entry);
    }
    return next;
  }

  const pairs = Object.entries(store);
  const toEvict = pickEvictionKeys(pairs, activeKey, accessOrder, maxLoaded);
  if (toEvict.size === 0) return store;
  const next: Record<string, T> = {};
  for (const [key, entry] of pairs) {
    next[key] = toEvict.has(key) ? evictEntry(entry) : entry;
  }
  return next;
}

// Bounds an ascending activity/message list. Keeps at most `normalCap` newest
// items when pinned to bottom, and ALWAYS enforces a hard `scrolledCap` even
// when scrolled up so long-running sessions cannot grow memory unboundedly.
export function trimBoundedItems<T>(
  items: T[],
  pinnedToBottom: boolean,
  normalCap = DEFAULT_NORMAL_ITEM_CAP,
  scrolledCap = DEFAULT_SCROLLED_ITEM_CAP,
): T[] {
  const safeNormal = Math.max(1, Math.floor(Number.isFinite(normalCap) ? normalCap : DEFAULT_NORMAL_ITEM_CAP));
  const safeScrolled = Math.max(
    safeNormal,
    Math.floor(Number.isFinite(scrolledCap) ? scrolledCap : DEFAULT_SCROLLED_ITEM_CAP),
  );
  const cap = pinnedToBottom ? safeNormal : safeScrolled;
  if (items.length <= cap) return items;
  return items.slice(items.length - cap);
}

// Evaluates whether a payload exceeds the plain-text preview threshold and
// returns a bounded preview slice without mutating the source text.
export function buildCodePreview(text: string, maxChars = CODE_PREVIEW_THRESHOLD_BYTES): CodePreview {
  const limit = Math.max(0, Math.floor(Number.isFinite(maxChars) ? maxChars : CODE_PREVIEW_THRESHOLD_BYTES));
  const totalChars = text.length;
  if (totalChars <= limit) {
    return {
      isLarge: false,
      preview: text,
      totalChars,
      truncatedChars: 0,
    };
  }
  return {
    isLarge: true,
    preview: text.slice(0, limit),
    totalChars,
    truncatedChars: totalChars - limit,
  };
}

// Bounded async concurrency pool preserving input order. Rejects with the first
// worker error and stops scheduling remaining items on failure.
export async function mapWithConcurrency<T, R>(
  items: readonly T[],
  limit: number,
  fn: (item: T, idx: number) => Promise<R>,
): Promise<R[]> {
  const count = items.length;
  if (count === 0) return [];
  const concurrency = Math.min(count, Math.max(1, Math.floor(Number.isFinite(limit) ? limit : 1)));
  const results = new Array<R>(count);
  let nextIndex = 0;
  let aborted = false;

  async function worker(): Promise<void> {
    while (!aborted) {
      const index = nextIndex++;
      if (index >= count) return;
      try {
        results[index] = await fn(items[index], index);
      } catch (error) {
        aborted = true;
        throw error;
      }
    }
  }

  const workers = Array.from({ length: concurrency }, () => worker());
  await Promise.all(workers);
  return results;
}

// Computes a dependency-free virtual slice [startIndex, endIndex) and top/bottom
// spacer heights for fixed- or estimated-height scrollable lists. Clamps the
// first visible index so wrapped rows taller than `estimatedItemHeight` never
// produce an empty window at the bottom edge.
export function computeVirtualWindow(
  total: number,
  scrollTop: number,
  viewportHeight: number,
  estimatedItemHeight: number,
  overscan = 15,
): VirtualWindow {
  const safeTotal = Math.max(0, Math.floor(Number.isFinite(total) ? total : 0));
  if (safeTotal === 0) {
    return { startIndex: 0, endIndex: 0, topSpacerPx: 0, bottomSpacerPx: 0 };
  }
  const itemHeight = Math.max(1, Number.isFinite(estimatedItemHeight) ? estimatedItemHeight : 1);
  const safeScrollTop = Math.max(0, Number.isFinite(scrollTop) ? scrollTop : 0);
  const safeViewport = Math.max(0, Number.isFinite(viewportHeight) ? viewportHeight : 0);
  const safeOverscan = Math.max(0, Math.floor(Number.isFinite(overscan) ? overscan : 15));

  const visibleCount = Math.max(1, Math.ceil(safeViewport / itemHeight));
  const maxFirstVisible = Math.max(0, safeTotal - visibleCount);
  const firstVisible = Math.min(maxFirstVisible, Math.floor(safeScrollTop / itemHeight));

  const startIndex = Math.max(0, firstVisible - safeOverscan);
  const endIndex = Math.min(safeTotal, firstVisible + visibleCount + safeOverscan);

  return {
    startIndex,
    endIndex,
    topSpacerPx: startIndex * itemHeight,
    bottomSpacerPx: Math.max(0, (safeTotal - endIndex) * itemHeight),
  };
}

// Collapses embedded line breaks so virtualized single-line log rows stay at a
// deterministic 24px height while making multi-line breaks visually obvious.
export function collapseLogPreview(text: string): string {
  if (!text.includes("\n") && !text.includes("\r")) return text;
  return text.replace(/\r\n|\r|\n/g, " ↵ ");
}

// Decides how ExecView's tail window (`visibleCount`) should react to an updated
// transcript:
// - Switching `sessionKey` deterministically resets to the initial window.
// - Prepending older history on the same session (`minRealSeq` shrinks) bumps the
//   window by the number of newly prepended groups so fetched history is revealed
//   immediately instead of disappearing behind the fold.
// - Tail appends or front-trims preserve the current window size.
export function computeExecWindowTransition(
  prev: ExecWindowSnapshot | null,
  current: ExecWindowSnapshot,
): ExecWindowTransition {
  if (current.groupCount <= 0) {
    return { action: "reset", delta: 0, nextSnapshot: current };
  }
  if (!prev) {
    return { action: "reset", delta: 0, nextSnapshot: current };
  }

  const hasExplicitKey = current.sessionKey !== undefined || prev.sessionKey !== undefined;
  if (hasExplicitKey) {
    if (prev.sessionKey !== current.sessionKey) {
      return { action: "reset", delta: 0, nextSnapshot: current };
    }
  } else {
    const disjoint =
      prev.taskId !== current.taskId ||
      (prev.maxRealSeq > 0 &&
        current.maxRealSeq > 0 &&
        (current.maxRealSeq < prev.minRealSeq || current.minRealSeq > prev.maxRealSeq));
    if (disjoint) {
      return { action: "reset", delta: 0, nextSnapshot: current };
    }
  }

  if (prev.minRealSeq > 0 && current.minRealSeq > 0 && current.minRealSeq < prev.minRealSeq) {
    const delta = Math.max(0, current.groupCount - prev.groupCount);
    if (delta > 0) {
      return { action: "bump", delta, nextSnapshot: current };
    }
  }

  return { action: "keep", delta: 0, nextSnapshot: current };
}
