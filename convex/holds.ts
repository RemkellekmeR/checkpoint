import { v } from 'convex/values';
import { mutation, query } from './_generated/server';
import { requireToken } from './lib/auth';
import { assertRedacted } from './lib/redaction';

/** Open a hold. The withheld content stays in the MCP server; only the reason and redacted evidence are stored. */
export const open = mutation({
  args: {
    token: v.string(),
    holdId: v.string(),
    tool: v.string(),
    sessionId: v.optional(v.string()),
    reason: v.string(),
    evidence: v.array(v.string()),
    callId: v.optional(v.string()),
    createdAt: v.number(),
  },
  handler: async (ctx, { token, ...hold }) => {
    requireToken(token);
    assertRedacted('reason', hold.reason);
    hold.evidence.forEach((e, i) => assertRedacted(`evidence[${i}]`, e));
    const existing = await ctx.db
      .query('holds')
      .withIndex('by_holdId', (q) => q.eq('holdId', hold.holdId))
      .unique();
    if (existing) return existing._id;
    return await ctx.db.insert('holds', { ...hold, status: 'pending' });
  },
});

/** Reviewer decision. A decided hold cannot be decided again; there is no agent-facing path to this mutation. */
export const resolve = mutation({
  args: {
    token: v.string(),
    holdId: v.string(),
    decision: v.union(v.literal('approved'), v.literal('denied')),
    reviewer: v.string(),
    note: v.optional(v.string()),
    resolvedAt: v.optional(v.number()),
  },
  handler: async (ctx, { token, holdId, decision, reviewer, note, resolvedAt }) => {
    requireToken(token);
    if (!reviewer.trim()) throw new Error('reviewer is required');
    assertRedacted('reviewer', reviewer);
    if (note !== undefined) assertRedacted('note', note);
    const hold = await ctx.db
      .query('holds')
      .withIndex('by_holdId', (q) => q.eq('holdId', holdId))
      .unique();
    if (!hold) throw new Error(`No hold with id ${holdId}`);
    if (hold.status !== 'pending') throw new Error(`Hold ${holdId} is already ${hold.status}`);
    await ctx.db.patch(hold._id, {
      status: decision,
      reviewer,
      resolvedAt: resolvedAt ?? Date.now(),
      ...(note !== undefined ? { decisionNote: note } : {}),
    });
    return holdId;
  },
});

/** Pending holds, oldest first (the review queue). */
export const pending = query({
  args: { token: v.string(), limit: v.optional(v.number()) },
  handler: async (ctx, { token, limit }) => {
    requireToken(token);
    return await ctx.db
      .query('holds')
      .withIndex('by_status_createdAt', (q) => q.eq('status', 'pending'))
      .order('asc')
      .take(Math.min(Math.max(limit ?? 100, 1), 500));
  },
});

export const get = query({
  args: { token: v.string(), holdId: v.string() },
  handler: async (ctx, { token, holdId }) => {
    requireToken(token);
    return await ctx.db
      .query('holds')
      .withIndex('by_holdId', (q) => q.eq('holdId', holdId))
      .unique();
  },
});
