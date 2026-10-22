import { v } from 'convex/values';
import { internalMutation, mutation } from './_generated/server';
import { requireToken } from './lib/auth';
import { endpoint, engine } from './validators';

/**
 * Screening-result cache keyed by sha256(endpoint, engine, instructions, input). A hit means the same input is not
 * screened again, so replays and retries spend no credits. A mutation, not a query, because a hit bumps `hits`.
 */
export const lookup = mutation({
  args: { token: v.string(), key: v.string(), now: v.optional(v.number()) },
  handler: async (ctx, { token, key, now }) => {
    requireToken(token);
    const row = await ctx.db
      .query('cache')
      .withIndex('by_key', (q) => q.eq('key', key))
      .unique();
    if (!row || row.expiresAt <= (now ?? Date.now())) return null;
    await ctx.db.patch(row._id, { hits: row.hits + 1 });
    return row.result;
  },
});

/** Store a result. `result` must be offsets-only JSON: no quotes, no values, no screened text. */
export const put = mutation({
  args: { token: v.string(), key: v.string(), endpoint, engine, result: v.string(), ttlSeconds: v.number() },
  handler: async (ctx, { token, key, endpoint: ep, engine: eng, result, ttlSeconds }) => {
    requireToken(token);
    if (!/^[0-9a-f]{64}$/.test(key)) throw new Error('cache key must be a sha256 hex digest');
    const parsed: unknown = JSON.parse(result);
    if (JSON.stringify(parsed).match(/"(quote|value|line|text|anonymizedText|withheld)"\s*:/)) {
      throw new Error('cache result carries screened text; store offsets only');
    }
    const createdAt = Date.now();
    const row = { key, endpoint: ep, engine: eng, result, createdAt, expiresAt: createdAt + ttlSeconds * 1000, hits: 0 };
    const existing = await ctx.db
      .query('cache')
      .withIndex('by_key', (q) => q.eq('key', key))
      .unique();
    if (existing) await ctx.db.replace(existing._id, row);
    else await ctx.db.insert('cache', row);
  },
});

/** Drop expired rows (for a cron once a deployment exists). */
export const purgeExpired = internalMutation({
  args: { now: v.optional(v.number()) },
  handler: async (ctx, { now }) => {
    const expired = await ctx.db
      .query('cache')
      .withIndex('by_expiresAt', (q) => q.lt('expiresAt', now ?? Date.now()))
      .take(500);
    for (const row of expired) await ctx.db.delete(row._id);
    return expired.length;
  },
});
