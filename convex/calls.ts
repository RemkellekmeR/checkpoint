import { v } from 'convex/values';
import { mutation, query } from './_generated/server';
import { requireToken } from './lib/auth';
import { assertRedacted } from './lib/redaction';
import { callFields, endpoint } from './validators';

/**
 * Record one Guard/Protect/Inspect screening and what Checkpoint did about it. Idempotent on `callId`, so a retried
 * write from the MCP server does not duplicate a row. Every free-text field must pass the redaction tripwire.
 */
export const record = mutation({
  args: { token: v.string(), call: v.object(callFields) },
  handler: async (ctx, { token, call }) => {
    requireToken(token);
    assertRedacted('summary', call.summary);
    assertRedacted('reason', call.reason);
    if (call.error !== undefined) assertRedacted('error', call.error);
    if (call.category !== undefined) assertRedacted('category', call.category);
    const existing = await ctx.db
      .query('calls')
      .withIndex('by_callId', (q) => q.eq('callId', call.callId))
      .unique();
    if (existing) return existing._id;
    return await ctx.db.insert('calls', call);
  },
});

/** Live feed: newest calls first, optionally for one endpoint. Reactive, so a dashboard subscription updates itself. */
export const feed = query({
  args: { token: v.string(), endpoint: v.optional(endpoint), limit: v.optional(v.number()) },
  handler: async (ctx, { token, endpoint: ep, limit }) => {
    requireToken(token);
    const n = Math.min(Math.max(limit ?? 50, 1), 200);
    if (ep) {
      return await ctx.db
        .query('calls')
        .withIndex('by_endpoint_startedAt', (q) => q.eq('endpoint', ep))
        .order('desc')
        .take(n);
    }
    return await ctx.db.query('calls').withIndex('by_startedAt').order('desc').take(n);
  },
});
