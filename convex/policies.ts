import { v } from 'convex/values';
import { mutation, query } from './_generated/server';
import { requireToken } from './lib/auth';
import { assertRedacted } from './lib/redaction';
import { policyBody } from './validators';

const ACTIVE = 'active';

/** The active policy, or null before the first update (the MCP server then keeps its built-in defaults). */
export const get = query({
  args: { token: v.string() },
  handler: async (ctx, { token }) => {
    requireToken(token);
    return await ctx.db
      .query('policies')
      .withIndex('by_name', (q) => q.eq('name', ACTIVE))
      .unique();
  },
});

/**
 * Replace the active policy and bump its version. `expectedVersion` guards against two reviewers overwriting each
 * other (0 creates the first row). Thresholds are validated so a typo cannot silently disable screening.
 */
export const update = mutation({
  args: { token: v.string(), expectedVersion: v.number(), updatedBy: v.string(), ...policyBody },
  handler: async (ctx, { token, expectedVersion, updatedBy, ...body }) => {
    requireToken(token);
    assertRedacted('updatedBy', updatedBy);
    const { holdLow, holdHigh } = body.guard;
    if (!(0 <= holdLow && holdLow <= holdHigh && holdHigh <= 1)) throw new Error('guard hold band must satisfy 0 <= low <= high <= 1');
    if (!(body.inspect.suspiciousHold > 0 && body.inspect.suspiciousHold <= 1)) throw new Error('inspect.suspiciousHold must be in (0, 1]');
    if (!(body.cacheTtlSeconds >= 0 && body.cacheTtlSeconds <= 86_400)) throw new Error('cacheTtlSeconds must be 0..86400');

    const current = await ctx.db
      .query('policies')
      .withIndex('by_name', (q) => q.eq('name', ACTIVE))
      .unique();
    const currentVersion = current?.version ?? 0;
    if (currentVersion !== expectedVersion) {
      throw new Error(`policy version is ${currentVersion}, expected ${expectedVersion}; reload and retry`);
    }
    const row = { name: ACTIVE, version: currentVersion + 1, ...body, updatedAt: Date.now(), updatedBy };
    if (current) await ctx.db.replace(current._id, row);
    else await ctx.db.insert('policies', row);
    return row.version;
  },
});
