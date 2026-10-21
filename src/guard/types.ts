/**
 * Guard = prompt-injection screening. Two implementations sit behind this interface:
 *   - ClockedGuard: the real Clocked /injection endpoint via clocked-sdk (used when CLOCKED_API_KEY is set).
 *   - OfflineStubGuard: a keyword heuristic for local tests only. It is NOT Clocked and NOT real screening.
 */

export type GuardEngine = 'clocked' | 'offline-stub';

export interface GuardRequest {
  /** The text to screen. */
  text: string;
  /** `content` for retrieved/tool data, `user` for the user's own message (Clocked's two sources). */
  source: 'user' | 'content';
  /** Deployment context: what the agent may do, what is untrusted, what needs approval. */
  instructions?: string;
}

export interface GuardEvidence {
  quote: string;
  /** Zero-based Unicode code point offset into GuardRequest.text, inclusive. */
  start: number;
  /** Zero-based Unicode code point offset, exclusive. */
  end: number;
  confidence: number;
}

export interface GuardVerdict {
  engine: GuardEngine;
  /** Clocked's verdict label, for example `injection` or `benign`. */
  verdict: string;
  /** Probability of injection, 0 to 1. */
  injection: number;
  /** Cutoff the verdict was made with. */
  threshold: number;
  category: string;
  /** none | low | medium | high | critical, when returned. */
  severity?: string;
  evidence: GuardEvidence[];
  /** Model time in ms (X-Clocked-Model-Ms) when the engine reports it. */
  modelMs?: number | null;
  /** Idempotency-Key the request was sent with (Clocked only). */
  idempotencyKey?: string;
}

export interface Guard {
  readonly engine: GuardEngine;
  screen(request: GuardRequest, options?: { idempotencyKey?: string; signal?: AbortSignal }): Promise<GuardVerdict>;
}
