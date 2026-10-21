import { Clocked, type PiiEntityDefinition, type PiiResponse } from 'clocked-sdk';
import { countByType, replaceFindings } from './anonymize.ts';
import type { Protect, ProtectRequest, ProtectResult } from './types.ts';

/**
 * Entity kinds Checkpoint asks Protect for: Clocked's nine default catalog kinds (null = catalog definition)
 * plus a described custom kind for employee ids, as in Clocked's own HR-case example.
 */
export const SERVICE_DESK_ENTITIES: Record<string, PiiEntityDefinition> = {
  person: null,
  email: null,
  phone: null,
  address: null,
  date_of_birth: null,
  ssn: null,
  credit_card: null,
  bank_account: null,
  ip_address: null,
  employee_id: 'Employee identifiers such as EMP-90214',
};

export interface ClockedProtectOptions {
  apiKey: string;
  baseUrl?: string;
  /** Finding cutoff sent to Clocked (API default 0.5). */
  threshold?: number;
  timeout?: number;
  maxAttempts?: number;
  entities?: Record<string, PiiEntityDefinition>;
  /** Injected client, for tests. */
  client?: Pick<Clocked, 'pii'>;
}

/**
 * Real Protect: POST /clocked/pii through clocked-sdk 0.6.0.
 * SDK signature: clocked.pii(request: PiiTextRequest, options?: RequestOptions) -> Promise<ClockedResponse<PiiResponse>>
 * PiiTextRequest: { text, entities?, allow?, deny?, anonymize?: operator | Record<kind, operator>, threshold?,
 *   mask_keep?, max_items?, instructions? }
 * PiiResponse: { model, entities: {type,value,start,end,confidence,source}[], counts, threshold, instructions_used,
 *   anonymized_text?: string (when anonymize is set), timing? }
 * Offsets refer to the original input, not the transformed output.
 */
export class ClockedProtect implements Protect {
  readonly engine = 'clocked' as const;
  readonly #client: Pick<Clocked, 'pii'>;
  readonly #threshold: number | undefined;
  readonly #entities: Record<string, PiiEntityDefinition>;

  constructor(options: ClockedProtectOptions) {
    this.#client =
      options.client ??
      new Clocked({
        apiKey: options.apiKey,
        ...(options.baseUrl ? { baseUrl: options.baseUrl } : {}),
        ...(options.timeout ? { timeout: options.timeout } : {}),
        ...(options.maxAttempts ? { maxAttempts: options.maxAttempts } : {}),
      });
    this.#threshold = options.threshold;
    this.#entities = options.entities ?? SERVICE_DESK_ENTITIES;
  }

  async anonymize(
    request: ProtectRequest,
    options: { idempotencyKey?: string; signal?: AbortSignal } = {},
  ): Promise<ProtectResult> {
    const res = await this.#client.pii(
      {
        text: request.text,
        entities: this.#entities,
        anonymize: 'replace',
        ...(request.instructions ? { instructions: request.instructions } : {}),
        ...(this.#threshold !== undefined ? { threshold: this.#threshold } : {}),
      },
      options,
    );
    return fromPiiResponse(request.text, res.data, { modelMs: res.modelMs, idempotencyKey: res.idempotencyKey });
  }
}

/**
 * Maps a /pii response. Uses Clocked's `anonymized_text` when present. If it is absent (the docs mark it optional),
 * Checkpoint rebuilds the replace-style copy from the finding offsets itself rather than passing the original on.
 */
export function fromPiiResponse(
  originalText: string,
  data: PiiResponse,
  meta: { modelMs?: number | null; idempotencyKey?: string } = {},
): ProtectResult {
  const findings = (data.entities ?? []).map((e) => ({
    type: e.type,
    value: e.value,
    start: e.start,
    end: e.end,
    confidence: e.confidence,
  }));
  const engineText = typeof data.anonymized_text === 'string' ? data.anonymized_text : undefined;
  return {
    engine: 'clocked',
    anonymizedText: engineText ?? replaceFindings(originalText, findings).text,
    anonymizedBy: engineText !== undefined ? 'engine' : 'checkpoint',
    findings,
    counts: data.counts ?? countByType(findings),
    ...(meta.modelMs !== undefined ? { modelMs: meta.modelMs } : {}),
    ...(meta.idempotencyKey !== undefined ? { idempotencyKey: meta.idempotencyKey } : {}),
  };
}
