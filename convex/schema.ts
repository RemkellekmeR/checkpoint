import { defineSchema, defineTable } from 'convex/server';
import { v } from 'convex/values';
import { callFields, endpoint, engine, holdFields, policyBody } from './validators';

/**
 * Checkpoint's audit and control tables.
 *
 * Nothing here stores the raw text that was screened or the personal data Protect found. `calls` and `holds`
 * carry labels, numbers, counts, code point offsets and a sha256 of the input; withheld content stays in the
 * MCP server's memory. Every free-text field passes `assertRedacted` (convex/lib/redaction.ts) before insert.
 */
export default defineSchema({
  /** One row per Guard/Protect/Inspect screening (live call or cache hit), with what Checkpoint did about it. */
  calls: defineTable(callFields)
    .index('by_callId', ['callId'])
    .index('by_startedAt', ['startedAt'])
    .index('by_endpoint_startedAt', ['endpoint', 'startedAt'])
    .index('by_session', ['sessionId', 'startedAt']),

  /** Human approval queue. The withheld content is never stored here, only why it was held and redacted evidence. */
  holds: defineTable(holdFields)
    .index('by_holdId', ['holdId'])
    .index('by_status_createdAt', ['status', 'createdAt']),

  /** Current screening policy. One row per `name` (`active`); every update bumps `version`. */
  policies: defineTable({
    name: v.string(),
    version: v.number(),
    ...policyBody,
    updatedAt: v.number(),
    updatedBy: v.string(),
  }).index('by_name', ['name']),

  /**
   * Short-TTL cache of screening results keyed by sha256(endpoint, engine, instructions, input). A replayed input
   * costs zero credits. `result` holds verdict labels, numbers and code point offsets only; quotes and values are
   * rebuilt from the caller's own input on a hit, so the cache never holds the screened text.
   */
  cache: defineTable({
    key: v.string(),
    endpoint,
    engine,
    result: v.string(), // JSON, offsets-only
    createdAt: v.number(),
    expiresAt: v.number(),
    hits: v.number(),
  })
    .index('by_key', ['key'])
    .index('by_expiresAt', ['expiresAt']),
});
