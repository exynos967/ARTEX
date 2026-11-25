import assert from "node:assert/strict";
import test from "node:test";
import {
  matchesPath,
  mutationInvalidationKeys,
  RefreshCooldownGate,
  RefreshCoordinator,
  RequestCache,
} from "./api-cache.ts";

function deferred() {
  let resolve, reject;
  const promise = new Promise((yes, no) => {
    resolve = yes;
    reject = no;
  });
  return { promise, resolve, reject };
}
async function flush() {
  for (let i = 0; i < 12; i++) await Promise.resolve();
}

class FakeClock {
  time = 0;
  next = 0;
  timers = new Map();
  now = () => this.time;
  setTimeout = (callback, delay) => {
    const id = ++this.next;
    this.timers.set(id, { at: this.time + delay, callback });
    return id;
  };
  clearTimeout = (id) => {
    this.timers.delete(id);
  };
  async advance(duration) {
    const target = this.time + duration;
    for (let guard = 0; guard < 10_000; guard++) {
      await flush();
      const next = [...this.timers].sort((a, b) => a[1].at - b[1].at)[0];
      if (!next || next[1].at > target) {
        this.time = target;
        await flush();
        return;
      }
      this.time = next[1].at;
      this.timers.delete(next[0]);
      next[1].callback();
    }
    throw new Error("Scheduler did not settle");
  }
}

test("identical GETs share one pending request and reuse only fresh results", async () => {
  const clock = new FakeClock();
  const cache = new RequestCache(clock.now);
  const result = deferred();
  let calls = 0;
  const load = () => {
    calls++;
    return result.promise;
  };
  const first = cache.read("user:/tasks?page=1", "/tasks?page=1", load);
  const second = cache.read("user:/tasks?page=1", "/tasks?page=1", load);
  assert.equal(first, second);
  result.resolve({ version: 1 });
  assert.deepEqual(await first, { version: 1 });
  await cache.read("user:/tasks?page=1", "/tasks?page=1", load);
  assert.equal(calls, 1);
  await clock.advance(5_001);
  await cache.read("user:/tasks?page=1", "/tasks?page=1", load);
  assert.equal(calls, 2);
});

test("query parameters and auth identities do not share cached data", async () => {
  const cache = new RequestCache();
  const reads = [
    ["alice:/tasks?page=1", "/tasks?page=1", "first"],
    ["alice:/tasks?page=2", "/tasks?page=2", "second"],
    ["bob:/tasks?page=1", "/tasks?page=1", "other user"],
  ];
  for (const [key, path, value] of reads) assert.equal(await cache.read(key, path, async () => value), value);
  for (const [key, path, value] of reads) assert.equal(await cache.read(key, path, async () => "wrong"), value);
});

test("mutation during a GET waits for one fresh follow-up without overlap or stale writes", async () => {
  const cache = new RequestCache();
  const old = deferred(),
    fresh = deferred();
  let calls = 0;
  const load = () => (++calls === 1 ? old.promise : fresh.promise);
  const first = cache.read("task", "/tasks/one", load);
  cache.invalidate(["/tasks"]);
  cache.invalidate(["/tasks"]);
  const afterMutation = cache.read("task", "/tasks/one", load);
  assert.equal(calls, 1, "invalidation must not overlap the existing request");
  old.resolve("obsolete");
  await flush();
  assert.equal(calls, 2);
  fresh.resolve("current");
  assert.deepEqual(await Promise.all([first, afterMutation]), ["current", "current"]);
  assert.equal(await cache.read("task", "/tasks/one", async () => "wrong"), "current");
});

test("errors are not cached, and invalidation does not match unrelated prefixes", async () => {
  const cache = new RequestCache();
  let calls = 0;
  const load = async () => {
    if (++calls === 1) throw new Error("offline");
    return "online";
  };
  await assert.rejects(cache.read("task", "/tasks", load), /offline/);
  assert.equal(await cache.read("task", "/tasks", load), "online");
  cache.invalidate(["/task"]);
  assert.equal(await cache.read("task", "/tasks", load), "online");
  assert.equal(calls, 2);
  cache.invalidate(["/tasks"]);
  await cache.read("task", "/tasks", load);
  assert.equal(calls, 3);
});

test("an invalidated failed request retries current data instead of surfacing an obsolete error", async () => {
  const cache = new RequestCache();
  const old = deferred();
  let calls = 0;
  const read = cache.read("task", "/tasks/one", () => (++calls === 1 ? old.promise : Promise.resolve("new")));
  cache.invalidate(["/tasks"]);
  old.reject(new Error("obsolete error"));
  assert.equal(await read, "new");
  assert.equal(calls, 2);
});

test("logout clears successful values and rejects old in-flight responses", async () => {
  const cache = new RequestCache();
  const old = deferred();
  const request = cache.read("alice", "/tasks", () => old.promise);
  const rejected = assert.rejects(request, /会话已失效/);
  cache.clear();
  assert.equal(await cache.read("bob", "/tasks", async () => "bob data"), "bob data");
  old.resolve("alice data");
  await rejected;
  assert.equal(await cache.read("alice", "/tasks", async () => "new login"), "new login");
});

test("cache evicts least recently used completed entries", async () => {
  const cache = new RequestCache(Date.now, 5_000, 2);
  await cache.read("one", "/one", async () => 1);
  await cache.read("two", "/two", async () => 2);
  await cache.read("one", "/one", async () => 9);
  await cache.read("three", "/three", async () => 3);
  assert.equal(await cache.read("one", "/one", async () => 9), 1);
  assert.equal(await cache.read("two", "/two", async () => 22), 22);
});

test("two mounted consumers make one request per fallback cycle", async () => {
  const clock = new FakeClock();
  const cache = new RequestCache(clock.now);
  const coordinator = new RefreshCoordinator(clock);
  let network = 0,
    commits = 0;
  const load = async () => {
    await cache.read("tasks", "/tasks", async () => ++network);
    commits++;
  };
  const stop1 = coordinator.subscribe(load, { keys: ["/tasks"] });
  const stop2 = coordinator.subscribe(load, { keys: ["/tasks"] });
  await clock.advance(0);
  assert.equal(network, 1);
  assert.equal(commits, 2);
  await clock.advance(29_999);
  assert.equal(network, 1);
  await clock.advance(1);
  assert.equal(network, 2);
  stop1();
  stop2();
  assert.equal(clock.timers.size, 0);
});

test("slow refreshes never overlap and event bursts schedule only one follow-up", async () => {
  const clock = new FakeClock();
  const coordinator = new RefreshCoordinator(clock);
  const first = deferred();
  let calls = 0;
  const stop = coordinator.subscribe(() => (++calls === 1 ? first.promise : Promise.resolve()), { keys: ["/tasks"] });
  await clock.advance(0);
  for (let i = 0; i < 50; i++) coordinator.invalidate(["/tasks/one"]);
  await clock.advance(90_000);
  assert.equal(calls, 1);
  first.resolve();
  await flush();
  await clock.advance(100);
  assert.equal(calls, 2);
  stop();
});

test("hidden views pause initial/fallback/event loads and refresh once on return", async () => {
  const clock = new FakeClock();
  const coordinator = new RefreshCoordinator(clock);
  let calls = 0;
  coordinator.setVisible(false);
  const stop = coordinator.subscribe(async () => {
    calls++;
  });
  coordinator.invalidate();
  await clock.advance(120_000);
  assert.equal(calls, 0);
  coordinator.setVisible(true);
  await clock.advance(0);
  assert.equal(calls, 1);
  coordinator.setVisible(false);
  await clock.advance(120_000);
  assert.equal(calls, 1);
  coordinator.setVisible(true);
  await clock.advance(0);
  assert.equal(calls, 2);
  stop();
});

test("failed refreshes retry, unrelated events stay quiet, and unsubscribe cancels queued work", async () => {
  const clock = new FakeClock();
  const coordinator = new RefreshCoordinator(clock);
  let calls = 0;
  const stop = coordinator.subscribe(
    async () => {
      calls++;
      if (calls === 1) throw new Error("offline");
    },
    { keys: ["/tasks"] },
  );
  await clock.advance(0);
  coordinator.invalidate(["/assets"]);
  await clock.advance(1_000);
  assert.equal(calls, 1);
  await clock.advance(29_000);
  assert.equal(calls, 2);
  coordinator.invalidate(["/tasks"]);
  stop();
  await clock.advance(60_000);
  assert.equal(calls, 2);
});

test("unmounting during a request cannot resurrect its timer or queued invalidation", async () => {
  const clock = new FakeClock();
  const coordinator = new RefreshCoordinator(clock);
  const pending = deferred();
  let calls = 0;
  const stop = coordinator.subscribe(() => {
    calls++;
    return pending.promise;
  });
  await clock.advance(0);
  coordinator.invalidate();
  stop();
  pending.resolve();
  await clock.advance(120_000);
  assert.equal(calls, 1);
  assert.equal(clock.timers.size, 0);
});

test("default timer adapter preserves the native browser timer receiver", () => {
  const originalSet = globalThis.setTimeout;
  const originalClear = globalThis.clearTimeout;
  let scheduled = 0;
  let cleared = 0;
  try {
    globalThis.setTimeout = function (callback, delay) {
      assert(this == null || this === globalThis, "native browser setTimeout rejects an arbitrary receiver");
      scheduled++;
      return originalSet(callback, delay);
    };
    globalThis.clearTimeout = function (timer) {
      assert(this == null || this === globalThis, "native browser clearTimeout rejects an arbitrary receiver");
      cleared++;
      return originalClear(timer);
    };
    const coordinator = new RefreshCoordinator();
    const stop = coordinator.subscribe(async () => undefined);
    stop();
    assert.equal(scheduled, 1);
    assert.equal(cleared, 1);
  } finally {
    globalThis.setTimeout = originalSet;
    globalThis.clearTimeout = originalClear;
  }
});

test("continuous invalidations during slow GETs make at most 2 requests and do not cache stale response", async () => {
  const clock = new FakeClock();
  const cache = new RequestCache(clock.now);
  const first = deferred();
  const second = deferred();
  let calls = 0;
  const load = () => {
    calls++;
    if (calls === 1) return first.promise;
    if (calls === 2) return second.promise;
    return Promise.resolve(`v${calls}`);
  };

  const pending = cache.read("graph", "/exploration/graph?task=1", load);
  // Invalidate repeatedly during the initial slow GET.
  cache.invalidate(["/exploration"]);
  cache.invalidate(["/exploration"]);
  first.resolve("v1");
  await flush();
  assert.equal(calls, 2, "must trigger at most one follow-up fetch");

  // Invalidate again while the follow-up GET is still in flight.
  cache.invalidate(["/exploration"]);
  cache.invalidate(["/exploration"]);
  second.resolve("v2");
  assert.equal(await pending, "v2", "must settle with the latest fetched value instead of looping");
  assert.equal(calls, 2, "must stop after 1 follow-up even under continuous invalidations");
  assert.equal(cache.size, 0, "stale-at-arrival response must not remain cached");

  // Because expires=0 (uncached), the next read performs a fresh fetch immediately.
  assert.equal(await cache.read("graph", "/exploration/graph?task=1", load), "v3");
  assert.equal(calls, 3);
});

test("continuous invalidations during failing GETs bound retries and surface follow-up error", async () => {
  const cache = new RequestCache();
  const first = deferred();
  const second = deferred();
  let calls = 0;
  const load = () => {
    calls++;
    return calls === 1 ? first.promise : second.promise;
  };

  const pending = cache.read("task", "/tasks/1", load);
  cache.invalidate(["/tasks"]);
  first.reject(new Error("first failure"));
  await flush();
  assert.equal(calls, 2);

  cache.invalidate(["/tasks"]);
  second.reject(new Error("second failure"));
  await assert.rejects(pending, /second failure/);
  assert.equal(calls, 2);
  assert.equal(cache.size, 0);
});

test("invalidate immediately evicts non-pending entries while preserving in-flight follow-up deduplication", async () => {
  const cache = new RequestCache();
  await cache.read("graph", "/exploration/graph?task=1", async () => ({ huge: "graph" }));
  await cache.read("agents", "/agents", async () => [{ key: "worker" }]);
  assert.equal(cache.size, 2);

  // Non-pending matching entry is evicted immediately; unrelated entry stays cached.
  cache.invalidate(["/exploration"]);
  assert.equal(cache.size, 1);
  assert.deepEqual(
    await cache.read("agents", "/agents", async () => {
      throw new Error("unrelated entry must stay cached");
    }),
    [{ key: "worker" }],
  );

  // Pending entry stays tracked during invalidation so concurrent callers share the follow-up.
  const first = deferred();
  const second = deferred();
  let calls = 0;
  const load = () => (++calls === 1 ? first.promise : second.promise);
  const a = cache.read("intercept", "/intercept/task/1?status=pending", load);
  assert.equal(cache.size, 2);
  cache.invalidate(["/intercept"]);
  assert.equal(cache.size, 2, "in-flight entry must stay in map until pending settles");
  const b = cache.read("intercept", "/intercept/task/1?status=pending", load);
  assert.equal(a, b, "concurrent reader after invalidation must join the same pending promise");
  first.resolve(["stale"]);
  await flush();
  assert.equal(calls, 2);
  second.resolve(["fresh"]);
  assert.deepEqual(await Promise.all([a, b]), [["fresh"], ["fresh"]]);
  assert.equal(cache.size, 2);
});

test("setVisible(true, false) resumes timers without forcing an immediate storm for fresh jobs", async () => {
  const clock = new FakeClock();
  const coordinator = new RefreshCoordinator(clock);
  let calls = 0;
  const stop = coordinator.subscribe(
    async () => {
      calls++;
    },
    { intervalMs: 30_000 },
  );
  await clock.advance(0);
  assert.equal(calls, 1);

  coordinator.setVisible(false);
  await clock.advance(2_000);
  coordinator.setVisible(true, false);
  await clock.advance(0);
  assert.equal(calls, 1, "recently executed job must not immediately storm on cooldown-suppressed resume");

  await clock.advance(28_000);
  assert.equal(calls, 2, "job still runs on its normal fallback schedule");
  stop();
});

test("RefreshCooldownGate throttles rapid focus switches and deduplicates visibility+focus pairs", () => {
  const clock = new FakeClock();
  const gate = new RefreshCooldownGate({ now: clock.now, focusMs: 10_000, resumeMs: 5_000 });

  // Visibility return succeeds and suppresses the immediate paired window.focus event.
  clock.time = 10_000;
  assert.equal(gate.allow("resume"), true);
  clock.time = 10_005;
  assert.equal(gate.allow("focus"), false);

  // Rapid tab hide/show within 5s is suppressed; at +5s resume is allowed again.
  clock.time = 14_999;
  assert.equal(gate.allow("resume"), false);
  clock.time = 15_000;
  assert.equal(gate.allow("resume"), true);

  // Rapid alt-tabbing is blocked for 10s after last refresh.
  clock.time = 24_999;
  assert.equal(gate.allow("focus"), false);
  clock.time = 25_000;
  assert.equal(gate.allow("focus"), true);
  clock.time = 28_000;
  assert.equal(gate.allow("focus"), false);

  // Network online recovery works even shortly after focus, with its own 5s flap cooldown.
  clock.time = 29_000;
  assert.equal(gate.allow("online"), true);
  clock.time = 32_000;
  assert.equal(gate.allow("online"), false);
  clock.time = 34_000;
  assert.equal(gate.allow("online"), true);

  gate.reset();
  assert.equal(gate.allow("focus"), true);
});

test("mutationInvalidationKeys scopes mutations cleanly without wiping unrelated caches", () => {
  const unrelated = ["/agents", "/skills", "/mcp", "/traffic", "/tokens/usage", "/companies"];

  // Narrow chat mutations must not wipe inventory/traffic/company caches.
  const chatKeys = mutationInvalidationKeys("/chat?task=42");
  assert(Array.isArray(chatKeys) && chatKeys.length > 0);
  assert.equal(matchesPath("/tasks/42/chat/status", chatKeys), true);
  for (const path of unrelated) assert.equal(matchesPath(path, chatKeys), false, `POST /chat must not wipe ${path}`);

  const stopKeys = mutationInvalidationKeys("/tasks/42/chat/stop");
  assert.deepEqual(stopKeys, ["/tasks/42/chat"]);
  assert.equal(matchesPath("/tasks/42/chat/status", stopKeys), true);
  assert.equal(matchesPath("/tasks/42", stopKeys), false);
  for (const path of unrelated) assert.equal(matchesPath(path, stopKeys), false);

  // Task/intent/goal/finding mutations keep tasks + stats + exploration reactive together.
  for (const mutation of [
    "/tasks/42/intents/7/control",
    "/tasks/42/goals",
    "/exploration/findings/9",
    "/tasks/42/control",
  ]) {
    const keys = mutationInvalidationKeys(mutation);
    assert(Array.isArray(keys));
    assert.equal(matchesPath("/tasks/42", keys), true);
    assert.equal(matchesPath("/stats?task=42", keys), true);
    assert.equal(matchesPath("/exploration/intents?task=42", keys), true);
    for (const path of unrelated) assert.equal(matchesPath(path, keys), false, `${mutation} must not wipe ${path}`);
  }

  // Intercept decisions invalidate pending & task-scoped intercept queries + stats.
  const decideKeys = mutationInvalidationKeys("/intercept/pending/5/decide");
  assert.deepEqual(decideKeys, ["/intercept", "/stats"]);
  assert.equal(matchesPath("/intercept/task/42?status=pending&page=1&size=100", decideKeys), true);
  assert.equal(matchesPath("/intercept/pending", decideKeys), true);
  assert.equal(matchesPath("/agents", decideKeys), false);

  // Conversation turns stay scoped to conversations.
  const convKeys = mutationInvalidationKeys("/conversations/12/messages");
  assert.deepEqual(convKeys, ["/conversations/12", "/conversations"]);
  assert.equal(matchesPath("/tasks", convKeys), false);

  // Read-only probe/preview POSTs return empty array (no invalidation).
  for (const probe of [
    "/llm/test",
    "/llm/models",
    "/settings/web-search/test",
    "/settings/python/detect",
    "/tools/custom/test",
    "/agents/worker/prompt/preview",
  ]) {
    assert.deepEqual(mutationInvalidationKeys(probe), []);
  }

  // Auth login/init keep full-refresh semantics; unknown endpoints fall back to first segment.
  assert.equal(mutationInvalidationKeys("/auth/login"), undefined);
  assert.deepEqual(mutationInvalidationKeys("/custom-widgets/99"), ["/custom-widgets"]);
});

test("side-questions cancel invalidates nested side-questions caches without wiping parent resources", async () => {
  const cancelKeys = mutationInvalidationKeys("/side-questions/42/cancel");
  assert.deepEqual(cancelKeys, ["/side-questions"]);

  // Matches direct and nested side-questions paths (with or without query strings).
  assert.equal(matchesPath("/side-questions", cancelKeys), true);
  assert.equal(matchesPath("/side-questions/42", cancelKeys), true);
  assert.equal(matchesPath("/tasks/7/chat/side-questions?before=0", cancelKeys), true);
  assert.equal(matchesPath("/tasks/7/intents/4/side-questions?before=0", cancelKeys), true);
  assert.equal(matchesPath("/conversations/3/side-questions?before=0", cancelKeys), true);

  // Never wipes unrelated parent task/conversation entries or prefix collisions.
  assert.equal(matchesPath("/tasks/7", cancelKeys), false);
  assert.equal(matchesPath("/tasks/7/chat/status", cancelKeys), false);
  assert.equal(matchesPath("/conversations/3", cancelKeys), false);
  assert.equal(matchesPath("/tasks/7/side-questions-other", cancelKeys), false);

  // End-to-end RequestCache eviction check.
  const cache = new RequestCache();
  await cache.read("task-sq", "/tasks/7/chat/side-questions?before=0", async () => ["sq-1"]);
  await cache.read("conv-sq", "/conversations/3/side-questions?before=0", async () => ["sq-2"]);
  await cache.read("task", "/tasks/7", async () => ({ id: 7 }));
  await cache.read("conv", "/conversations/3", async () => ({ id: 3 }));
  assert.equal(cache.size, 4);

  cache.invalidate(cancelKeys);
  assert.equal(cache.size, 2);
  assert.deepEqual(
    await cache.read("task", "/tasks/7", async () => {
      throw new Error("unrelated /tasks/7 entry must remain cached");
    }),
    { id: 7 },
  );
  assert.deepEqual(
    await cache.read("conv", "/conversations/3", async () => {
      throw new Error("unrelated /conversations/3 entry must remain cached");
    }),
    { id: 3 },
  );
});

test("task and task-archive mutations invalidate task-categories counts", () => {
  for (const mutation of [
    "/tasks",
    "/tasks/42",
    "/tasks/42/archive",
    "/tasks/42/category",
    "/tasks/category/batch",
    "/tasks/archive/batch",
    "/task-archives/9/restore",
    "/task-archives/restore/batch",
    "/task-archives/9",
    "/task-archives/delete/batch",
  ]) {
    const keys = mutationInvalidationKeys(mutation);
    assert(Array.isArray(keys), `expected array keys for ${mutation}`);
    assert.equal(matchesPath("/task-categories", keys), true, `${mutation} must invalidate /task-categories`);
    assert.equal(matchesPath("/tasks", keys), true, `${mutation} must invalidate /tasks`);
  }
});
