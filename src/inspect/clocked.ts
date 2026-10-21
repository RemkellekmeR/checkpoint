import { Clocked, type ScriptResponse } from 'clocked-sdk';
import type { Inspect, InspectRequest, InspectVerdict } from './types.ts';

export interface ClockedInspectOptions {
  apiKey: string;
  baseUrl?: string;
  /** Malicious verdict cutoff sent to Clocked (API default 0.5). */
  threshold?: number;
  timeout?: number;
  maxAttempts?: number;
  /** Injected client, for tests. */
  client?: Pick<Clocked, 'script'>;
}

/**
 * Real Inspect: POST /clocked/script through clocked-sdk 0.6.0. The endpoint classifies the script as data and
 * does not run it.
 * SDK signature: clocked.script(request: ScriptTextRequest, options?: RequestOptions) -> Promise<ClockedResponse<ScriptResponse>>
 * ScriptTextRequest: { script, categories?, instructions?, threshold?, evidence?, rotations? }
 * ScriptResponse: { model, malicious, suspicious, verdict, threshold, instructions_used, category, categories,
 *   severity?, severity_expected?, severities?, evidence?: {line,start,end,confidence}[], timing? }
 */
export class ClockedInspect implements Inspect {
  readonly engine = 'clocked' as const;
  readonly #client: Pick<Clocked, 'script'>;
  readonly #threshold: number | undefined;

  constructor(options: ClockedInspectOptions) {
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

  async assess(
    request: InspectRequest,
    options: { idempotencyKey?: string; signal?: AbortSignal } = {},
  ): Promise<InspectVerdict> {
    const res = await this.#client.script(
      {
        script: request.script,
        ...(request.instructions ? { instructions: request.instructions } : {}),
        ...(this.#threshold !== undefined ? { threshold: this.#threshold } : {}),
        evidence: true,
      },
      options,
    );
    return fromScriptResponse(res.data, { modelMs: res.modelMs, idempotencyKey: res.idempotencyKey });
  }
}

export function fromScriptResponse(
  data: ScriptResponse,
  meta: { modelMs?: number | null; idempotencyKey?: string } = {},
): InspectVerdict {
  return {
    engine: 'clocked',
    verdict: data.verdict,
    malicious: data.malicious,
    suspicious: data.suspicious,
    threshold: data.threshold,
    category: data.category,
    ...(data.severity !== undefined ? { severity: data.severity } : {}),
    evidence: (data.evidence ?? []).map((e) => ({ line: e.line, start: e.start, end: e.end, confidence: e.confidence })),
    ...(meta.modelMs !== undefined ? { modelMs: meta.modelMs } : {}),
    ...(meta.idempotencyKey !== undefined ? { idempotencyKey: meta.idempotencyKey } : {}),
  };
}
