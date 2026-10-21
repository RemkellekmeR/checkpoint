/**
 * Inspect = behavioral assessment of a script before anything would run it. Two implementations:
 *   - ClockedInspect: the real Clocked /script endpoint via clocked-sdk (used when CLOCKED_API_KEY is set).
 *   - OfflineStubInspect: a few line patterns for local tests only. It is NOT Clocked and NOT real script analysis.
 * Neither runs the script. Checkpoint never executes a script either; an allowed script gets a simulated run.
 */

export type InspectEngine = 'clocked' | 'offline-stub';

export interface InspectRequest {
  script: string;
  /** Approved environment and change scope (host, window, permitted actions, prohibitions). */
  instructions?: string;
}

export interface InspectEvidence {
  /** The quoted script line. */
  line: string;
  /** Zero-based Unicode code point offset into InspectRequest.script, inclusive (character offsets, not line numbers). */
  start: number;
  /** Zero-based Unicode code point offset, exclusive. */
  end: number;
  confidence: number;
}

export interface InspectVerdict {
  engine: InspectEngine;
  /** Clocked's verdict label. Observed in the docs: `malicious`. Assumed: `suspicious`, `benign`. */
  verdict: string;
  /** Risk signals, 0 to 1. */
  malicious: number;
  suspicious: number;
  /** Malicious cutoff the verdict was made with. */
  threshold: number;
  category: string;
  severity?: string;
  evidence: InspectEvidence[];
  modelMs?: number | null;
  idempotencyKey?: string;
}

export interface Inspect {
  readonly engine: InspectEngine;
  assess(request: InspectRequest, options?: { idempotencyKey?: string; signal?: AbortSignal }): Promise<InspectVerdict>;
}
