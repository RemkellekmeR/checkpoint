import { Clocked, type InjectionResponse } from 'clocked-sdk';
import type { Guard, GuardRequest, GuardVerdict } from './types.ts';

export interface ClockedGuardOptions {
  apiKey: string;
  baseUrl?: string;
  /** Verdict cutoff sent to Clocked (API default 0.5). */
  threshold?: number;
  /** Milliseconds per attempt (SDK default 120000). */
  timeout?: number;
  /** Attempts per call including the first (SDK default 5). */
  maxAttempts?: number;
  /** Injected client, for tests. */
  client?: Pick<Clocked, 'injection'>;
}

/**
 * Real Guard: POST /clocked/injection through clocked-sdk 0.6.0.
 * SDK signature: clocked.injection(request: InjectionTextRequest, options?: RequestOptions)
 *   -> Promise<ClockedResponse<InjectionResponse>>
 * InjectionTextRequest: { text, source?: 'user'|'content', categories?, instructions?, threshold?, evidence? }
 * InjectionResponse: { model, injection, verdict, threshold, source, instructions_used, category, categories,
 *   severity?, severity_expected?, severities?, evidence?: {quote,start,end,confidence}[], timing? }
 * The SDK sends an Idempotency-Key on every call and retries 429/5xx/connection errors under the same key.
 */
export class ClockedGuard implements Guard {
  readonly engine = 'clocked' as const;
  readonly #client: Pick<Clocked, 'injection'>;
  readonly #threshold: number | undefined;

  constructor(options: ClockedGuardOptions) {
    this.#client =
      options.client ??
      new Clocked({
        apiKey: options.apiKey,
        ...(options.baseUrl ? { baseUrl: options.baseUrl } : {}),
        ...(options.timeout ? { timeout: options.timeout } : {}),
        ...(options.maxAttempts ? { maxAttempts: options.maxAttempts } : {}),
      });
    this.#threshold = options.threshold;
  }

  async screen(
    request: GuardRequest,
    options: { idempotencyKey?: string; signal?: AbortSignal } = {},
  ): Promise<GuardVerdict> {
    const res = await this.#client.injection(
      {
        text: request.text,
        source: request.source,
        ...(request.instructions ? { instructions: request.instructions } : {}),
        ...(this.#threshold !== undefined ? { threshold: this.#threshold } : {}),
        evidence: true,
      },
      options,
    );
    return fromInjectionResponse(res.data, { modelMs: res.modelMs, idempotencyKey: res.idempotencyKey });
  }
}

export function fromInjectionResponse(
  data: InjectionResponse,
  meta: { modelMs?: number | null; idempotencyKey?: string } = {},
): GuardVerdict {
  return {
    engine: 'clocked',
    verdict: data.verdict,
    injection: data.injection,
    threshold: data.threshold,
    category: data.category,
    ...(data.severity !== undefined ? { severity: data.severity } : {}),
    evidence: (data.evidence ?? []).map((e) => ({
      quote: e.quote,
      start: e.start,
      end: e.end,
      confidence: e.confidence,
    })),
    ...(meta.modelMs !== undefined ? { modelMs: meta.modelMs } : {}),
    ...(meta.idempotencyKey !== undefined ? { idempotencyKey: meta.idempotencyKey } : {}),
  };
}
