type TokenUsage = { input: number; output: number; cacheRead: number };

export function tokenPercentage(tokens: number, denominator: number): number | null {
  return denominator > 0 ? (tokens / denominator) * 100 : null;
}

export function dashboardTokenBreakdown({ input, output, cacheRead }: TokenUsage) {
  // Normalized input already includes cache reads, so only stack the remainder alongside them.
  const hitRate = tokenPercentage(cacheRead, input);
  return {
    uncachedInput: Math.max(0, input - cacheRead),
    cacheRead,
    output,
    total: input + output,
    hitPercent: hitRate === null ? null : Math.round(hitRate),
  };
}
