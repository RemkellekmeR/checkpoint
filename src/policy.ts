import type { GuardVerdict } from './guard/types.ts';

/** What Checkpoint does with a tool result after Guard has screened it. */
export type GuardAction =
  | 'allow' // pass the content through unchanged
  | 'cut' // remove the evidence spans, wrap the remainder in a quarantine notice
  | 'hold' // withhold the content until a human reviews it
  | 'unscreened'; // Guard failed; read tools fail open with a visible banner

export interface GuardPolicy {
  /** Severities whose evidence spans are cut surgically. */
  cutSeverities: readonly string[];
  /** Injection probabilities in [low, high] are uncertain and held for review. */
  holdBand: { low: number; high: number };
}

export const DEFAULT_GUARD_POLICY: GuardPolicy = {
  cutSeverities: ['high', 'critical'],
  // Starting band from the project brief; to be tuned on the labeled fixture set.
  holdBand: { low: 0.35, high: 0.65 },
};

export interface GuardDecision {
  action: GuardAction;
  reason: string;
}

export function decideGuard(v: GuardVerdict, policy: GuardPolicy = DEFAULT_GUARD_POLICY): GuardDecision {
  const p = v.injection;
  if (p >= policy.holdBand.low && p <= policy.holdBand.high) {
    return { action: 'hold', reason: `uncertain: injection probability ${p} is inside the review band` };
  }
  if (v.verdict === 'injection') {
    const sev = v.severity ?? 'unknown';
    if (policy.cutSeverities.includes(sev)) {
      if (v.evidence.length > 0) {
        return { action: 'cut', reason: `${v.category}, severity ${sev}: evidence spans removed` };
      }
      // A high-severity verdict without evidence cannot be cut surgically; a missing passage is not proof of safety.
      return { action: 'hold', reason: `${v.category}, severity ${sev}, but no evidence spans to cut` };
    }
    return { action: 'hold', reason: `${v.category}, severity ${sev}: below the cut threshold, held for review` };
  }
  return { action: 'allow', reason: `verdict ${v.verdict}, injection probability ${p}` };
}
