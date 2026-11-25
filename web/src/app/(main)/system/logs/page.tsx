"use client";

import * as React from "react";
import { CheckIcon, CopyIcon, XIcon } from "lucide-react";
import { Input } from "@/components/ui/input";
import { Button } from "@/components/ui/button";
import { api, sseUrl } from "@/lib/api";
import { appendLiveLine, HISTORY_LIMIT, historyPageSize, loadHistoryPage, prependHistory } from "@/lib/log-history";
import { MOCK } from "@/lib/mock/enabled";
import type { LogLine } from "@/lib/types";
import { cn, copyText } from "@/lib/utils";
import { collapseLogPreview, computeVirtualWindow } from "@/lib/view-guards";

const FLUSH_INTERVAL_MS = 150;
const VIRTUALIZE_THRESHOLD = 200;
const VIRTUAL_ROW_HEIGHT = 24;
const LOG_OVERSCAN = 15;
const LIVE_CAPACITY_FLOOR = 3000;

// Mock demo：无后端 SSE，塞几行示例日志。
const MOCK_LOGS: LogLine[] = [
  { seq: 1, ts: "2026-07-26T03:55:00Z", level: "info", tag: "engine", text: "ARTEX v0.1.0 backend listening on :8787 (workers=3)" },
  { seq: 2, ts: "2026-07-26T03:55:01Z", level: "info", tag: "config", text: "LLM configured from DB: anthropic / claude-opus-4-8" },
  { seq: 3, ts: "2026-07-26T03:56:10Z", level: "info", tag: "planner", text: "task t-acme-web: 第 3 轮规划，生成意图 i-4" },
  { seq: 4, ts: "2026-07-26T03:57:00Z", level: "warn", tag: "guard", text: "block bash: 目标越界 out.evil.example 不在 scope 内" },
  { seq: 5, ts: "2026-07-26T03:57:30Z", level: "info", tag: "work#1", text: "report_finding: Default Credentials (high) 已落库" },
  { seq: 6, ts: "2026-07-26T03:58:20Z", level: "error", tag: "work#3", text: "intercept: mysqldump 命中破坏性规则，等待人工审批" },
];

const levelTone: Record<LogLine["level"], string> = {
  info: "text-foreground/80",
  warn: "text-amber-600 dark:text-amber-400",
  error: "text-red-600 dark:text-red-400",
};
const levelDot: Record<LogLine["level"], string> = {
  info: "bg-muted-foreground/40",
  warn: "bg-amber-500",
  error: "bg-red-500",
};

function fmtTime(ts: string) {
  const d = new Date(ts);
  if (isNaN(d.getTime())) return "";
  const p = (n: number) => String(n).padStart(2, "0");
  return `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())} ${p(d.getHours())}:${p(d.getMinutes())}:${p(d.getSeconds())}`;
}

function logBody(line: LogLine): string {
  return line.tag && line.text.startsWith("[" + line.tag + "]")
    ? line.text.slice(line.tag.length + 2).trimStart()
    : line.text;
}

function mergeLiveLog(prev: LogLine[], line: LogLine): LogLine[] {
  if (line.db_id && prev.some((row) => row.db_id === line.db_id)) return prev;
  return appendLiveLine(prev, line);
}

function mergeLiveBatch(prev: LogLine[], batch: LogLine[]): LogLine[] {
  if (batch.length === 0) return prev;
  if (batch.length === 1) return mergeLiveLog(prev, batch[0]);
  const seenSeq = new Set<number>();
  const seenDbId = new Set<number>();
  for (const row of prev) {
    seenSeq.add(row.seq);
    if (row.db_id) seenDbId.add(row.db_id);
  }
  const toAdd: LogLine[] = [];
  for (const line of batch) {
    if (seenSeq.has(line.seq)) continue;
    if (line.db_id && seenDbId.has(line.db_id)) continue;
    seenSeq.add(line.seq);
    if (line.db_id) seenDbId.add(line.db_id);
    toAdd.push(line);
  }
  if (toAdd.length === 0) return prev;
  const capacity = Math.min(HISTORY_LIMIT, Math.max(LIVE_CAPACITY_FLOOR, prev.length));
  if (prev.length + toAdd.length <= capacity) return [...prev, ...toAdd];
  return [...prev.slice(Math.max(0, prev.length + toAdd.length - capacity)), ...toAdd];
}

export default function LogsPage() {
  const [lines, setLines] = React.useState<LogLine[]>([]);
  const [q, setQ] = React.useState("");
  const [level, setLevel] = React.useState<"all" | LogLine["level"]>("all");
  const [paused, setPaused] = React.useState(false);
  const [loadingHistory, setLoadingHistory] = React.useState(false);
  const [hasMore, setHasMore] = React.useState(false);
  const [isPinned, setIsPinned] = React.useState(true);
  const [inspectedLine, setInspectedLine] = React.useState<LogLine | null>(null);
  const [copiedInspected, setCopiedInspected] = React.useState(false);
  const historyInFlight = React.useRef(false);
  const exhaustedRef = React.useRef(false);
  const historyFull = historyPageSize(lines.length) === 0;
  const containerRef = React.useRef<HTMLDivElement>(null);
  const bottom = React.useRef<HTMLDivElement>(null);
  const stick = React.useRef(true);
  const pausedRef = React.useRef(false);
  const pendingQueueRef = React.useRef<LogLine[]>([]);
  const scrollRafRef = React.useRef<number | null>(null);
  const copyTimerRef = React.useRef<ReturnType<typeof setTimeout> | null>(null);
  const [scrollTop, setScrollTop] = React.useState(0);
  const [viewportHeight, setViewportHeight] = React.useState(600);

  React.useEffect(() => {
    pausedRef.current = paused;
  }, [paused]);

  // Measure log viewport height so windowed slicing adapts to resizes.
  React.useEffect(() => {
    const el = containerRef.current;
    if (!el) return;
    const measure = () => {
      if (el.clientHeight > 0) setViewportHeight(el.clientHeight);
    };
    measure();
    if (typeof ResizeObserver === "undefined") return;
    const observer = new ResizeObserver(measure);
    observer.observe(el);
    return () => observer.disconnect();
  }, []);

  React.useEffect(
    () => () => {
      if (scrollRafRef.current !== null) cancelAnimationFrame(scrollRafRef.current);
      if (copyTimerRef.current !== null) clearTimeout(copyTimerRef.current);
    },
    [],
  );

  // Minimum db_id seen — used as the cursor for loading older history.
  const minDbId = React.useMemo(() => {
    let min = 0;
    for (const l of lines) {
      if (l.db_id && (min === 0 || l.db_id < min)) min = l.db_id;
    }
    return min;
  }, [lines]);

  // Live tail via SSE. On initial connect, replays whatever is in the ring
  // (includes DB-restored history from the last 100 rows written before restart).
  // EventSource automatically sends Last-Event-ID on reconnect; client-side
  // sequence/db_id watermarks also guard against proxy-stripped reconnect replays
  // and post-restart seq resets. Incoming bursts are queued in a ref and flushed
  // every 150ms to prevent per-line React re-render storms.
  React.useEffect(() => {
    if (MOCK) {
      setLines(MOCK_LOGS);
      return;
    }
    let lastRawSeq = 0;
    let maxDisplaySeq = 0;
    let maxDbId = 0;
    let lastTsMs = 0;
    let flushTimer: ReturnType<typeof setTimeout> | null = null;
    const queue = pendingQueueRef.current;
    queue.length = 0;

    const flush = () => {
      flushTimer = null;
      if (queue.length === 0) return;
      if (pausedRef.current) {
        queue.length = 0;
        return;
      }
      const batch = queue.splice(0, queue.length);
      setLines((prev) => mergeLiveBatch(prev, batch));
    };

    const es = new EventSource(sseUrl("/api/logs/stream?since=0"));
    es.onmessage = (e) => {
      try {
        const l = JSON.parse(e.data) as LogLine;
        const parsedTs = Date.parse(l.ts);
        const tsMs = Number.isFinite(parsedTs) ? parsedTs : 0;
        const dbId = l.db_id ?? 0;
        const isReplay =
          l.seq > 0 && l.seq <= lastRawSeq && (dbId === 0 || dbId <= maxDbId) && tsMs <= lastTsMs;
        if (isReplay) return;
        if (l.seq > 0) lastRawSeq = l.seq;
        const nextLine = l.seq <= maxDisplaySeq ? { ...l, seq: maxDisplaySeq + 1 } : l;
        maxDisplaySeq = nextLine.seq;
        if (dbId > maxDbId) maxDbId = dbId;
        if (tsMs > lastTsMs) lastTsMs = tsMs;
        if (pausedRef.current) return;
        queue.push(nextLine);
        if (flushTimer === null) {
          flushTimer = setTimeout(flush, FLUSH_INTERVAL_MS);
        }
      } catch {
        /* ignore malformed frame */
      }
    };
    return () => {
      if (flushTimer !== null) clearTimeout(flushTimer);
      queue.length = 0;
      es.close();
    };
  }, []);

  // Mark "has more" once we have any db_id in view, unless the server already
  // reported that no older rows exist.
  React.useEffect(() => {
    if (minDbId > 1 && !exhaustedRef.current) setHasMore(true);
  }, [minDbId]);

  function loadOlderHistory() {
    const limit = historyPageSize(lines.length);
    const before = minDbId;
    return loadHistoryPage(historyInFlight, lines.length, before, async () => {
      setLoadingHistory(true);
      try {
        const data = await api.logsHistory(before, limit);
        if (data.items.length > 0) setLines((prev) => prependHistory(prev, data.items));
        if (!data.has_more) exhaustedRef.current = true;
        setHasMore(data.has_more);
      } catch {
        // Keep current rows and allow retrying on transient failures.
      } finally {
        setLoadingHistory(false);
      }
    });
  }

  async function copyInspected() {
    if (!inspectedLine) return;
    const ok = await copyText(logBody(inspectedLine));
    if (!ok) return;
    setCopiedInspected(true);
    if (copyTimerRef.current !== null) clearTimeout(copyTimerRef.current);
    copyTimerRef.current = setTimeout(() => setCopiedInspected(false), 1500);
  }

  const filtered = React.useMemo(() => {
    const needle = q.trim().toLowerCase();
    return lines.filter(
      (l) =>
        (level === "all" || l.level === level) &&
        (!needle || l.text.toLowerCase().includes(needle) || l.tag.toLowerCase().includes(needle)),
    );
  }, [lines, q, level]);

  const shouldVirtualize = filtered.length > VIRTUALIZE_THRESHOLD;
  const effectiveScrollTop =
    shouldVirtualize && isPinned && !paused ? filtered.length * VIRTUAL_ROW_HEIGHT : scrollTop;
  const virtualWindow = React.useMemo(
    () =>
      shouldVirtualize
        ? computeVirtualWindow(
            filtered.length,
            effectiveScrollTop,
            viewportHeight,
            VIRTUAL_ROW_HEIGHT,
            LOG_OVERSCAN,
          )
        : { startIndex: 0, endIndex: filtered.length, topSpacerPx: 0, bottomSpacerPx: 0 },
    [shouldVirtualize, filtered.length, effectiveScrollTop, viewportHeight],
  );
  const visibleLines = React.useMemo(
    () => (shouldVirtualize ? filtered.slice(virtualWindow.startIndex, virtualWindow.endIndex) : filtered),
    [shouldVirtualize, filtered, virtualWindow.startIndex, virtualWindow.endIndex],
  );

  React.useLayoutEffect(() => {
    if (!stick.current || paused) return;
    const el = containerRef.current;
    if (el) {
      el.scrollTop = el.scrollHeight;
    } else {
      bottom.current?.scrollIntoView();
    }
  }, [filtered, paused]);

  const counts = React.useMemo(() => {
    let warn = 0,
      error = 0;
    for (const l of lines) {
      if (l.level === "warn") warn++;
      else if (l.level === "error") error++;
    }
    return { warn, error, total: lines.length };
  }, [lines]);

  return (
    <div className="flex flex-1 flex-col gap-3">
      <div>
        <h1 className="text-xl font-semibold tracking-tight">系统日志</h1>
        <p className="text-muted-foreground text-sm">后端实时日志流(planner / worker / 数据库 / 流量 …)</p>
      </div>
      <div className="flex flex-1 flex-col gap-3">
        <div className="flex flex-wrap items-center gap-2">
          <Input
            placeholder="过滤(文本 / tag)…"
            value={q}
            onChange={(e) => setQ(e.target.value)}
            className="h-8 max-w-xs"
          />
          <div className="flex gap-1">
            {(["all", "info", "warn", "error"] as const).map((lv) => (
              <Button
                key={lv}
                size="sm"
                variant={level === lv ? "default" : "outline"}
                className="h-8"
                onClick={() => setLevel(lv)}
              >
                {lv === "all" ? "全部" : lv}
              </Button>
            ))}
          </div>
          <Button
            size="sm"
            variant={paused ? "default" : "outline"}
            className="h-8"
            onClick={() => setPaused((p) => !p)}
          >
            {paused ? "已暂停" : "暂停"}
          </Button>
          <Button
            size="sm"
            variant="outline"
            className="h-8"
            onClick={() => {
              pendingQueueRef.current.length = 0;
              exhaustedRef.current = false;
              stick.current = true;
              setIsPinned(true);
              setHasMore(false);
              setInspectedLine(null);
              setCopiedInspected(false);
              setLines([]);
              setScrollTop(0);
            }}
          >
            清空
          </Button>
          <span className="ml-auto text-xs text-muted-foreground">
            {counts.total} 行 ·{" "}
            <span className="text-amber-600 dark:text-amber-400">{counts.warn} 警告</span> ·{" "}
            <span className="text-red-600 dark:text-red-400">{counts.error} 错误</span>
          </span>
        </div>

        <div className="flex h-[calc(100vh-14rem)] flex-col gap-2">
          <div
            ref={containerRef}
            onScroll={(e) => {
              const el = e.currentTarget;
              const pinned = el.scrollHeight - el.scrollTop - el.clientHeight < 40;
              stick.current = pinned;
              setIsPinned(pinned);
              if (scrollRafRef.current === null) {
                scrollRafRef.current = requestAnimationFrame(() => {
                  scrollRafRef.current = null;
                  const current = containerRef.current;
                  if (!current) return;
                  setScrollTop(current.scrollTop);
                  if (current.clientHeight > 0) setViewportHeight(current.clientHeight);
                });
              }
            }}
            className="min-h-0 flex-1 overflow-auto rounded-lg border bg-card p-2 font-mono text-xs leading-relaxed"
          >
            {hasMore && (
              <div className="flex justify-center py-2">
                <Button
                  size="sm"
                  variant="outline"
                  className="h-7 text-xs"
                  disabled={loadingHistory || historyFull}
                  onClick={() => void loadOlderHistory()}
                >
                  {historyFull ? `已达 ${HISTORY_LIMIT} 行显示上限` : loadingHistory ? "加载中…" : "加载更早日志"}
                </Button>
              </div>
            )}
            {filtered.length === 0 ? (
              <p className="py-10 text-center text-muted-foreground">暂无日志。</p>
            ) : (
              <>
                {virtualWindow.topSpacerPx > 0 && (
                  <div aria-hidden="true" style={{ height: virtualWindow.topSpacerPx }} />
                )}
                {visibleLines.map((l) => {
                  const body = logBody(l);
                  if (shouldVirtualize) {
                    const selected = inspectedLine?.seq === l.seq;
                    return (
                      <button
                        key={l.seq}
                        type="button"
                        onClick={() => {
                          setCopiedInspected(false);
                          setInspectedLine((cur) => (cur?.seq === l.seq ? null : l));
                        }}
                        className={cn(
                          "flex h-6 w-full items-center gap-2 overflow-hidden whitespace-nowrap px-1 text-left leading-6 hover:bg-muted/40",
                          selected && "bg-accent/60",
                        )}
                      >
                        <span className={cn("size-1.5 shrink-0 rounded-full", levelDot[l.level])} />
                        <span className="shrink-0 tabular-nums text-muted-foreground">{fmtTime(l.ts)}</span>
                        {l.tag && (
                          <span className="shrink-0 rounded bg-muted px-1 text-[10px] leading-4 text-foreground/70">
                            {l.tag}
                          </span>
                        )}
                        <span className={cn("min-w-0 flex-1 truncate whitespace-nowrap", levelTone[l.level])}>
                          {collapseLogPreview(body)}
                        </span>
                      </button>
                    );
                  }
                  return (
                    <div key={l.seq} className="flex items-start gap-2 px-1 py-0.5 hover:bg-muted/40">
                      <span className={cn("mt-1.5 size-1.5 shrink-0 rounded-full", levelDot[l.level])} />
                      <span className="shrink-0 tabular-nums text-muted-foreground">{fmtTime(l.ts)}</span>
                      {l.tag && (
                        <span className="shrink-0 rounded bg-muted px-1 text-[10px] text-foreground/70">{l.tag}</span>
                      )}
                      <span className={cn("min-w-0 whitespace-pre-wrap break-words", levelTone[l.level])}>{body}</span>
                    </div>
                  );
                })}
                {virtualWindow.bottomSpacerPx > 0 && (
                  <div aria-hidden="true" style={{ height: virtualWindow.bottomSpacerPx }} />
                )}
              </>
            )}
            <div ref={bottom} />
          </div>

          {inspectedLine && (
            <div className="shrink-0 rounded-lg border bg-card p-3 font-mono text-xs">
              <div className="mb-2 flex flex-wrap items-center gap-2 border-b pb-2">
                <span className={cn("size-1.5 shrink-0 rounded-full", levelDot[inspectedLine.level])} />
                <span className="tabular-nums text-muted-foreground">{fmtTime(inspectedLine.ts)}</span>
                {inspectedLine.tag && (
                  <span className="rounded bg-muted px-1 text-[10px] text-foreground/70">{inspectedLine.tag}</span>
                )}
                <span className="text-[10px] text-muted-foreground">完整日志详情</span>
                <div className="ml-auto flex items-center gap-1">
                  <Button
                    type="button"
                    size="sm"
                    variant="outline"
                    className="h-6 px-2 text-xs"
                    onClick={() => void copyInspected()}
                  >
                    {copiedInspected ? <CheckIcon className="size-3 text-emerald-600" /> : <CopyIcon className="size-3" />}
                    {copiedInspected ? "已复制" : "复制"}
                  </Button>
                  <Button
                    type="button"
                    size="icon"
                    variant="ghost"
                    className="size-6"
                    aria-label="关闭日志详情"
                    onClick={() => setInspectedLine(null)}
                  >
                    <XIcon className="size-3.5" />
                  </Button>
                </div>
              </div>
              <pre
                className={cn(
                  "max-h-48 overflow-auto whitespace-pre-wrap break-words leading-relaxed",
                  levelTone[inspectedLine.level],
                )}
              >
                {logBody(inspectedLine)}
              </pre>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
