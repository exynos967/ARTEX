import assert from "node:assert/strict";
import test from "node:test";
import { dashboardTokenBreakdown, tokenPercentage } from "./dashboard-tokens.ts";

test("daily stack counts input once; bar share and input hit rate have different denominators", () => {
  const b = dashboardTokenBreakdown({ input: 100, cacheRead: 80, output: 100 });
  assert.deepEqual([b.uncachedInput, b.cacheRead, b.output], [20, 80, 100]);
  assert.equal(b.uncachedInput + b.cacheRead + b.output, 200);
  assert.equal(b.total, 200);
  assert.equal(tokenPercentage(b.cacheRead, b.total), 40);
  assert.equal(b.hitPercent, 80);
});

test("missing input leaves hit rate undefined, while positive input with no reads gives zero", () => {
  assert.equal(dashboardTokenBreakdown({ input: 0, cacheRead: 0, output: 9 }).hitPercent, null);
  assert.equal(tokenPercentage(0, 0), null);
  assert.equal(dashboardTokenBreakdown({ input: 100, cacheRead: 0, output: 9 }).hitPercent, 0);
});

test("all-cached input has no uncached segment and a rounded rate uses full input", () => {
  assert.equal(dashboardTokenBreakdown({ input: 20, cacheRead: 20, output: 5 }).uncachedInput, 0);
  assert.equal(dashboardTokenBreakdown({ input: 3893, cacheRead: 3840, output: 23 }).hitPercent, 99);
});

test("cacheRead exceeding reported input clamps uncachedInput to zero", () => {
  const b = dashboardTokenBreakdown({ input: 50, cacheRead: 80, output: 15 });
  assert.equal(b.uncachedInput, 0);
  assert.equal(b.cacheRead, 80);
  assert.equal(b.output, 15);
  assert.equal(b.total, 65);
});
