import { v } from 'convex/values';

export const endpoint = v.union(v.literal('guard'), v.literal('protect'), v.literal('inspect'));
export const engine = v.union(v.literal('clocked'), v.literal('offline-stub'));
export const holdStatus = v.union(v.literal('pending'), v.literal('approved'), v.literal('denied'));
export const direction = v.union(v.literal('inbound'), v.literal('outbound'), v.literal('script'));

/**
 * What Checkpoint did because of a screening call. allow/cut/hold/deny are the policy outcomes; redact means
 * Protect replaced personal data with placeholders; unscreened (read tools, Guard error, fail open), withheld
 * (Protect error on a read, fail closed) and refused (write/execute tools, fail closed) are the failure outcomes.
 */
export const action = v.union(
  v.literal('allow'),
  v.literal('cut'),
  v.literal('hold'),
  v.literal('deny'),
  v.literal('redact'),
  v.literal('unscreened'),
  v.literal('withheld'),
  v.literal('refused'),
);

export const guardPolicy = v.object({
  cutSeverities: v.array(v.string()),
  holdLow: v.number(),
  holdHigh: v.number(),
});

export const inspectPolicy = v.object({
  suspiciousHold: v.number(),
  holdSeverities: v.array(v.string()),
});

export const toolPolicy = v.object({
  tool: v.string(),
  endpoints: v.array(endpoint),
  onScreeningError: v.union(v.literal('fail_open_banner'), v.literal('fail_closed')),
});

/** Fields of one `calls` row. Shared by the schema and the `calls.record` mutation. */
export const callFields = {
  callId: v.string(),
  endpoint, // guard (/injection) | protect (/pii) | inspect (/script)
  engine, // clocked | offline-stub
  tool: v.string(), // MCP tool that triggered the screening
  sessionId: v.optional(v.string()), // MCP-Session-Id
  direction,
  /** Engine label (`injection`, `benign`, `malicious`, `pii_found`, `clean`) or `error`. */
  verdict: v.string(),
  /** What Checkpoint did because of this call. */
  action,
  reason: v.string(),
  probability: v.optional(v.number()), // Guard injection or Inspect malicious probability
  severity: v.optional(v.string()),
  category: v.optional(v.string()),
  evidenceCount: v.number(),
  /** Code point spans of the evidence (no quotes: quotes are the screened text). */
  evidenceSpans: v.array(v.object({ start: v.number(), end: v.number() })),
  piiCounts: v.optional(v.record(v.string(), v.number())),
  inputChars: v.number(),
  inputSha256: v.string(),
  cached: v.boolean(), // true: served from the cache, no Clocked credits spent
  holdId: v.optional(v.string()),
  error: v.optional(v.string()),
  /** One-line redacted summary for the live feed. */
  summary: v.string(),
  startedAt: v.number(), // epoch ms
  finishedAt: v.number(),
  latencyMs: v.number(),
  modelMs: v.optional(v.number()), // X-Clocked-Model-Ms when the engine reports it
};

/** Fields of one `holds` row. The withheld content itself is never stored. */
export const holdFields = {
  holdId: v.string(),
  tool: v.string(),
  sessionId: v.optional(v.string()),
  status: holdStatus,
  reason: v.string(),
  /** Redacted evidence: labels, line numbers, counts. */
  evidence: v.array(v.string()),
  callId: v.optional(v.string()),
  createdAt: v.number(),
  resolvedAt: v.optional(v.number()),
  reviewer: v.optional(v.string()),
  decisionNote: v.optional(v.string()),
};

/** The editable part of a policy row (what `policies.update` accepts). */
export const policyBody = {
  guard: guardPolicy,
  inspect: inspectPolicy,
  tools: v.array(toolPolicy),
  cacheTtlSeconds: v.number(),
};
