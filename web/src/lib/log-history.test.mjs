import assert from "node:assert/strict";
import test from "node:test";
import { appendLiveLine, historyPageSize, loadHistoryPage, prependHistory } from "./log-history.ts";

const row = (id) => ({ seq: id, db_id: id, ts: "", level: "info", tag: "", text: "" });
const rows = (start, length) => Array.from({ length }, (_, i) => row(start + i));

test("the default live window rolls at 3000 and ignores a replayed frame", () => {
  const initial = rows(1, 3000);
  assert.equal(appendLiveLine(initial, row(3000)), initial);
  const next = appendLiveLine(initial, row(3001));
  assert.equal(next.length, 3000);
  assert.equal(next[0].db_id, 2);
  assert.equal(next.at(-1).db_id, 3001);
  assert.equal(appendLiveLine([], row(1)).length, 1);
});

test("live frames retain the manually expanded window and a full window skips history requests", async () => {
  let current = rows(2001, 3000);
  const lock = { current: false };
  let requests = 0;
  for (let page = 1; page <= 10; page++) {
    const before = current[0].db_id;
    await loadHistoryPage(lock, current.length, before, async (url) => {
      requests++;
      assert.equal(url, "/api/logs/history?before=" + before + "&limit=200");
      current = prependHistory(current, rows(before - 200, 200));
    });
    const size = 3000 + 200 * page;
    assert.equal(current.length, size);
    const fresh = appendLiveLine(current, row(5000 + page));
    assert.equal(fresh.length, size);
    assert.equal(fresh[0].db_id, current[1].db_id);
    current = fresh;
  }
  assert.equal(historyPageSize(current.length), 0);
  await loadHistoryPage(lock, current.length, current[0].db_id, async () => { requests++; });
  assert.equal(requests, 10);
});

test("the last page requests just the remaining space and a missing cursor is omitted", async () => {
  const urls = [];
  const load = async (url) => { urls.push(url); };
  const lock = { current: false };
  await loadHistoryPage(lock, 4999, 123, load);
  await loadHistoryPage(lock, 0, 0, load);
  assert.deepEqual(urls, ["/api/logs/history?before=123&limit=1", "/api/logs/history?limit=200"]);
});

test("concurrent clicks share the in-flight guard and failure releases it for retry", async () => {
  const lock = { current: false };
  const calls = [];
  const { promise, reject } = Promise.withResolvers();
  const first = loadHistoryPage(lock, 100, 6001, async (url) => {
    calls.push(url);
    await promise;
  });
  const load = async (url) => { calls.push(url); };
  await loadHistoryPage(lock, 100, 6001, load);
  assert.equal(calls.length, 1);
  reject(new Error("offline test"));
  await assert.rejects(first, /offline test/);
  await loadHistoryPage(lock, 100, 6001, load);
  assert.deepEqual(calls, Array(2).fill("/api/logs/history?before=6001&limit=200"));
});
