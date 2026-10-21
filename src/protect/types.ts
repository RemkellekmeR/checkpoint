/**
 * Protect = PII detection and anonymization. Two implementations sit behind this interface:
 *   - ClockedProtect: the real Clocked /pii endpoint via clocked-sdk (used when CLOCKED_API_KEY is set).
 *   - OfflineStubProtect: a few regexes for local tests only. It is NOT Clocked and NOT real PII screening.
 *
 * The agent only ever sees `anonymizedText`. `findings` still hold the original values (as Clocked's own
 * `entities` do), so they stay server-side and are never put into a tool result.
 */

export type ProtectEngine = 'clocked' | 'offline-stub';

export interface ProtectRequest {
  /** The text to screen and anonymize. */
  text: string;
  /** Deployment context sent as `instructions`. */
  instructions?: string;
}

export interface ProtectFinding {
  /** Entity kind, for example `email` or `employee_id`. */
  type: string;
  /** The original value. Sensitive: never returned to the agent. */
  value: string;
  /** Zero-based Unicode code point offset into ProtectRequest.text, inclusive. */
  start: number;
  /** Zero-based Unicode code point offset, exclusive. */
  end: number;
  confidence: number;
}

export interface ProtectResult {
  engine: ProtectEngine;
  /** The transformed copy. This, and only this, is what the agent or a recipient gets. */
  anonymizedText: string;
  /**
   * Who produced anonymizedText: `engine` when the engine returned it (Clocked's `anonymized_text`),
   * `checkpoint` when Checkpoint rebuilt it from the finding offsets because the field was absent.
   */
  anonymizedBy: 'engine' | 'checkpoint';
  findings: ProtectFinding[];
  /** Findings per entity kind. Safe to show: no values. */
  counts: Record<string, number>;
  /** Model time in ms (X-Clocked-Model-Ms) when the engine reports it. */
  modelMs?: number | null;
  /** Idempotency-Key the request was sent with (Clocked only). */
  idempotencyKey?: string;
}

export interface Protect {
  readonly engine: ProtectEngine;
  anonymize(request: ProtectRequest, options?: { idempotencyKey?: string; signal?: AbortSignal }): Promise<ProtectResult>;
}
