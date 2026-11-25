// Browser-independent request caching and refresh scheduling. Keeping this core
// free of React/DOM dependencies lets CI exercise races with a deterministic clock.

type Entry = {
  path: string;
  revision: number;
  expires: number;
  value?: unknown;
  present: boolean;
  disposed: boolean;
  pending?: Promise<unknown>;
};

const MAX_STALE_RETRIES = 1;

export function matchesPath(path: string, prefixes?: readonly string[]): boolean {
  if (!prefixes?.length) return true;
  const qIndex = path.indexOf("?");
  const pathname = qIndex >= 0 ? path.slice(0, qIndex) : path;
  return prefixes.some((prefix) => {
    if (pathname === prefix || pathname.startsWith(`${prefix}/`)) return true;
    // Nested side-questions resources live under /tasks/:id/chat/side-questions,
    // /tasks/:id/intents/:id/side-questions, or /conversations/:id/side-questions.
    if (prefix === "/side-questions") {
      return pathname.endsWith("/side-questions") || pathname.includes("/side-questions/");
    }
    return false;
  });
}

// Derives targeted cache/refresh invalidation prefixes from a mutating API path
// so narrow actions (such as chat turns or stop signals) do not wipe unrelated
// resources like agents, skills, MCP servers, traffic, or companies.
// Returns an empty array for read-only POST probes, and undefined only when a
// full session-level refresh is genuinely required (e.g. login/init).
export function mutationInvalidationKeys(path: string): readonly string[] | undefined {
  const qIndex = path.indexOf("?");
  const pathname = qIndex >= 0 ? path.slice(0, qIndex) : path;
  const query = qIndex >= 0 ? new URLSearchParams(path.slice(qIndex + 1)) : undefined;

  if (!pathname.startsWith("/")) return undefined;

  // Read-only probe/preview/test POST endpoints never mutate server state.
  if (
    pathname === "/llm/test" ||
    pathname === "/llm/models" ||
    pathname === "/settings/web-search/test" ||
    pathname === "/settings/python/detect" ||
    pathname === "/tools/custom/test" ||
    /^\/agents\/[^/]+\/prompt\/preview$/.test(pathname)
  ) {
    return [];
  }

  // Side-questions (scoped under task chat, worker intent, conversation, or top-level cancel).
  if (pathname === "/side-questions" || pathname.startsWith("/side-questions/")) {
    return ["/side-questions"];
  }
  const sideIdx = pathname.indexOf("/side-questions");
  if (sideIdx > 0) {
    return [pathname.slice(0, sideIdx), "/side-questions"];
  }

  // Main-agent chat submission.
  if (pathname === "/chat" || pathname.startsWith("/chat/")) {
    const taskId = query?.get("task");
    return taskId
      ? ["/chat", `/tasks/${encodeURIComponent(taskId)}/chat`, "/exploration/activity", "/exploration/main-sessions"]
      : ["/chat", "/exploration/activity", "/exploration/main-sessions"];
  }

  // Task sub-resources with narrow scopes first.
  const taskMatch = pathname.match(/^\/tasks\/([^/]+)(\/.*)?$/);
  if (taskMatch && !["category", "control", "archive"].includes(taskMatch[1])) {
    const taskId = taskMatch[1];
    const sub = taskMatch[2] ?? "";
    const taskPrefix = `/tasks/${taskId}`;
    if (sub === "/chat" || sub.startsWith("/chat/")) return [`${taskPrefix}/chat`];
    if (sub === "/main-requests" || sub.startsWith("/main-requests/")) {
      return [`${taskPrefix}/main-requests`, `${taskPrefix}/chat`];
    }
    if (sub === "/assets" || sub.startsWith("/assets/")) {
      return [taskPrefix, "/assets", "/stats", "/exploration"];
    }
    if (sub === "/intercept-rules" || sub.startsWith("/intercept-rules/")) {
      return [`${taskPrefix}/intercept-rules`, taskPrefix, "/intercept"];
    }
    if (sub === "/llm" || sub.startsWith("/llm/")) {
      return [taskPrefix, "/tasks", "/llm", "/stats", "/exploration"];
    }
    if (sub === "/worker-budgets" || sub === "/token-budget") {
      return [taskPrefix, "/stats"];
    }
    return ["/tasks", "/task-categories", "/stats", "/exploration", "/task-archives"];
  }

  if (pathname === "/tasks" || pathname.startsWith("/tasks/")) {
    return ["/tasks", "/task-categories", "/stats", "/exploration", "/task-archives"];
  }
  if (pathname === "/task-categories" || pathname.startsWith("/task-categories/")) {
    return ["/task-categories", "/tasks"];
  }
  if (pathname === "/task-templates" || pathname.startsWith("/task-templates/")) {
    return ["/task-templates"];
  }
  if (pathname === "/task-archives" || pathname.startsWith("/task-archives/")) {
    return ["/task-archives", "/tasks", "/task-categories", "/stats", "/exploration"];
  }
  if (pathname === "/task-record-exports" || pathname.startsWith("/task-record-exports/")) {
    return ["/task-record-exports"];
  }
  if (pathname === "/active") {
    return ["/tasks", "/stats"];
  }
  if (pathname === "/exploration/main-session" || pathname.startsWith("/exploration/main-session/")) {
    return ["/exploration/main-sessions", "/exploration/activity"];
  }
  if (pathname === "/exploration/findings" || pathname.startsWith("/exploration/findings/")) {
    return ["/exploration", "/tasks", "/stats", "/conversations"];
  }
  if (pathname === "/exploration" || pathname.startsWith("/exploration/")) {
    return ["/exploration", "/tasks", "/stats"];
  }
  if (pathname === "/assets" || pathname.startsWith("/assets/")) {
    return ["/assets", "/companies", "/stats", "/tasks"];
  }
  if (pathname === "/companies" || pathname.startsWith("/companies/")) {
    return ["/companies", "/assets", "/stats"];
  }
  if (pathname === "/intercept" || pathname.startsWith("/intercept/")) {
    return ["/intercept", "/stats"];
  }
  if (pathname === "/asset-intercept" || pathname.startsWith("/asset-intercept/")) {
    return ["/asset-intercept", "/intercept"];
  }
  if (pathname === "/llm/records" || pathname.startsWith("/llm/records/")) {
    return ["/llm/records", "/tokens"];
  }
  if (pathname === "/llm" || pathname.startsWith("/llm/")) {
    return ["/llm", "/stats", "/tasks", "/agents"];
  }
  if (pathname === "/settings" || pathname.startsWith("/settings/")) {
    return ["/settings", "/stats", "/llm", "/notify", "/traffic"];
  }
  if (
    pathname === "/agents" ||
    pathname.startsWith("/agents/") ||
    pathname === "/triggers" ||
    pathname.startsWith("/triggers/")
  ) {
    return ["/agents", "/triggers", "/visibility", "/tools"];
  }
  if (pathname === "/skills" || pathname.startsWith("/skills/")) {
    return ["/skills", "/visibility", "/agents"];
  }
  if (pathname === "/mcp" || pathname.startsWith("/mcp/")) {
    return ["/mcp", "/visibility", "/agents"];
  }
  if (pathname === "/tools" || pathname.startsWith("/tools/")) {
    return ["/tools", "/agents"];
  }
  if (pathname === "/visibility" || pathname.startsWith("/visibility/")) {
    return ["/visibility", "/agents", "/mcp", "/skills"];
  }
  if (pathname === "/notify" || pathname.startsWith("/notify/")) {
    return ["/notify"];
  }
  const convMatch = pathname.match(/^\/conversations\/(\d+)(\/.*)?$/);
  if (convMatch) {
    return [`/conversations/${convMatch[1]}`, "/conversations"];
  }
  if (pathname === "/conversations" || pathname.startsWith("/conversations/")) {
    return ["/conversations"];
  }
  if (pathname === "/traffic" || pathname.startsWith("/traffic/")) {
    return ["/traffic"];
  }
  if (pathname === "/workspace" || pathname.startsWith("/workspace/")) {
    return ["/workspace"];
  }
  if (pathname === "/sync/scopesentry/sync") {
    return ["/sync", "/assets", "/companies", "/stats"];
  }
  if (pathname === "/sync/scopesentry/datasource") {
    return ["/sync", "/mcp"];
  }
  if (pathname === "/sync" || pathname.startsWith("/sync/")) {
    return ["/sync"];
  }
  if (pathname === "/runners" || pathname.startsWith("/runners/")) {
    return ["/runners"];
  }
  if (
    pathname === "/resources" ||
    pathname.startsWith("/resources/") ||
    pathname === "/resource-drafts" ||
    pathname.startsWith("/resource-drafts/")
  ) {
    return ["/resources", "/resource-drafts", "/tasks"];
  }
  if (pathname === "/auth/change-password") {
    return ["/auth"];
  }
  if (pathname === "/auth" || pathname.startsWith("/auth/")) {
    return undefined;
  }
  if (pathname === "/gc") {
    return ["/tasks", "/stats", "/exploration"];
  }
  if (pathname === "/update" || pathname.startsWith("/update/")) {
    return ["/update"];
  }

  const firstSegment = pathname.match(/^\/[^/]+/)?.[0];
  return firstSegment ? [firstSegment] : undefined;
}

export class RequestCache {
  private entries = new Map<string, Entry>();
  private now: () => number;
  private ttlMs: number;
  private maxEntries: number;
  constructor(now = Date.now, ttlMs = 5_000, maxEntries = 256) {
    this.now = now;
    this.ttlMs = ttlMs;
    this.maxEntries = maxEntries;
  }

  get size(): number {
    return this.entries.size;
  }

  read<T>(key: string, path: string, loader: () => Promise<T>): Promise<T> {
    let entry = this.entries.get(key);
    if (!entry) {
      entry = { path, revision: 0, expires: 0, present: false, disposed: false };
      this.entries.set(key, entry);
      for (const [oldKey, old] of this.entries) {
        if (this.entries.size <= this.maxEntries) break;
        if (oldKey !== key && !old.pending) this.entries.delete(oldKey);
      }
    }
    // Refresh insertion order for bounded LRU eviction.
    this.entries.delete(key);
    this.entries.set(key, entry);
    if (entry.pending) return entry.pending as Promise<T>;
    if (entry.present && entry.expires > this.now()) return Promise.resolve(entry.value as T);
    // Drop expired payload before awaiting the replacement fetch so large
    // responses are not retained during reloads.
    entry.value = undefined;
    entry.present = false;
    const current = entry;
    const pending = (async () => {
      // An invalidation while a read is running schedules at most MAX_STALE_RETRIES
      // follow-up read so slow endpoints under continuous SSE events never enter an
      // unbounded refetch storm.
      for (let attempt = 0; ; attempt++) {
        const revision = current.revision;
        try {
          const value = await loader();
          if (current.disposed) throw new Error("请求会话已失效");
          if (current.revision !== revision) {
            if (attempt < MAX_STALE_RETRIES) continue;
            // Still invalidated after the bounded follow-up: return the latest
            // value without extending TTL so waiting callers settle cleanly.
            current.value = undefined;
            current.present = false;
            current.expires = 0;
            return value;
          }
          current.value = value;
          current.present = true;
          current.expires = this.now() + this.ttlMs;
          return value;
        } catch (error) {
          if (!current.disposed && current.revision !== revision && attempt < MAX_STALE_RETRIES) continue;
          // Rejected promises and errors never receive a freshness window.
          current.value = undefined;
          current.present = false;
          current.expires = 0;
          throw error;
        }
      }
    })();
    current.pending = pending;
    void pending
      .finally(() => {
        if (current.pending === pending) {
          current.pending = undefined;
          if (!current.present && this.entries.get(key) === current) this.entries.delete(key);
        }
      })
      .catch(() => {
        // The original promise retains the rejection for the caller.
      });
    return pending;
  }

  invalidate(prefixes?: readonly string[]): void {
    for (const [key, entry] of this.entries) {
      if (!matchesPath(entry.path, prefixes)) continue;
      entry.revision++;
      entry.expires = 0;
      entry.value = undefined;
      entry.present = false;
      if (!entry.pending) this.entries.delete(key);
    }
  }

  clear(): void {
    for (const entry of this.entries.values()) {
      entry.disposed = true;
      entry.value = undefined;
      entry.present = false;
      entry.expires = 0;
    }
    this.entries.clear();
  }
}

export interface RefreshOptions {
  keys?: readonly string[];
  intervalMs?: number;
  immediate?: boolean;
}

type Clock = {
  now(): number;
  setTimeout(callback: () => void, delay: number): ReturnType<typeof setTimeout>;
  clearTimeout(timer: ReturnType<typeof setTimeout>): void;
};
type Job = {
  load: () => unknown | Promise<unknown>;
  keys?: readonly string[];
  interval: number;
  due: number;
  running: boolean;
  queued: boolean;
};

export class RefreshCoordinator {
  private jobs = new Set<Job>();
  private timer?: ReturnType<typeof setTimeout>;
  private visible = true;
  private clock: Clock;
  constructor(
    clock: Clock = {
      now: Date.now,
      // Calling a browser timer as clock.setTimeout changes its receiver and
      // throws "Illegal invocation". Keep native calls in the global scope.
      setTimeout: (callback, delay) => setTimeout(callback, delay),
      clearTimeout: (timer) => clearTimeout(timer),
    },
  ) {
    this.clock = clock;
  }

  subscribe(load: Job["load"], options: RefreshOptions = {}): () => void {
    const interval = Math.max(1_000, options.intervalMs ?? 30_000);
    const job: Job = {
      load,
      keys: options.keys,
      interval,
      running: false,
      queued: false,
      due: this.clock.now() + (options.immediate === false ? interval : 0),
    };
    this.jobs.add(job);
    this.schedule();
    return () => {
      this.jobs.delete(job);
      this.schedule();
    };
  }

  invalidate(prefixes?: readonly string[]): void {
    for (const job of this.jobs) {
      if (
        prefixes?.length &&
        job.keys?.length &&
        !job.keys.some((key) => matchesPath(key, prefixes) || prefixes.some((prefix) => matchesPath(prefix, [key])))
      )
        continue;
      if (job.running) job.queued = true;
      else job.due = Math.min(job.due, this.clock.now() + 100);
    }
    this.schedule();
  }

  setVisible(visible: boolean, refreshNow = true): void {
    if (this.visible === visible) return;
    this.visible = visible;
    if (visible && refreshNow) {
      for (const job of this.jobs) {
        if (job.running) job.queued = true;
        else job.due = this.clock.now();
      }
    }
    this.schedule();
  }

  private schedule(): void {
    if (this.timer !== undefined) this.clock.clearTimeout(this.timer);
    this.timer = undefined;
    if (!this.visible) return;
    let due = Infinity;
    for (const job of this.jobs) if (!job.running) due = Math.min(due, job.due);
    if (!Number.isFinite(due)) return;
    this.timer = this.clock.setTimeout(
      () => {
        this.timer = undefined;
        for (const job of this.jobs) {
          if (job.running || job.due > this.clock.now()) continue;
          job.running = true;
          void Promise.resolve()
            .then(job.load)
            .catch(() => {
              // The consumer owns its error UI. Keep the subscription alive so a
              // transient network error cannot permanently stop future refreshes.
            })
            .finally(() => {
              if (!this.jobs.has(job)) return;
              job.running = false;
              job.due = this.clock.now() + (job.queued ? 100 : job.interval);
              job.queued = false;
              this.schedule();
            });
        }
        this.schedule();
      },
      Math.max(0, due - this.clock.now()),
    );
  }
}

export type RefreshTriggerKind = "focus" | "resume" | "online";

export interface RefreshCooldownOptions {
  now?: () => number;
  focusMs?: number;
  resumeMs?: number;
}

// Guards browser-driven global refreshes (window focus, visibility resume,
// network online) so rapid alt-tabbing or visibility+focus pairs do not fire
// back-to-back query storms across every mounted subscriber.
export class RefreshCooldownGate {
  private now: () => number;
  private focusMs: number;
  private resumeMs: number;
  private lastRefreshAt = -Infinity;
  private lastOnlineAt = -Infinity;

  constructor(options: RefreshCooldownOptions = {}) {
    this.now = options.now ?? Date.now;
    this.focusMs = options.focusMs ?? 10_000;
    this.resumeMs = options.resumeMs ?? 5_000;
  }

  allow(kind: RefreshTriggerKind): boolean {
    const current = this.now();
    if (kind === "online") {
      if (current - this.lastOnlineAt < this.resumeMs) return false;
      this.lastOnlineAt = current;
      this.lastRefreshAt = current;
      return true;
    }
    const cooldown = kind === "focus" ? this.focusMs : this.resumeMs;
    if (current - this.lastRefreshAt < cooldown) return false;
    this.lastRefreshAt = current;
    return true;
  }

  reset(): void {
    this.lastRefreshAt = -Infinity;
    this.lastOnlineAt = -Infinity;
  }
}
