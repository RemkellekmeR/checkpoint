import type { InspectVerdict } from './types.ts';

/** What Checkpoint does with a proposed remediation script after Inspect has assessed it. */
export type InspectAction =
  | 'allow' // simulated run only; the script is never executed
  | 'hold' // queued for human approval
  | 'deny'; // refused, with Inspect's evidence lines

export interface InspectPolicy {
  /** A `suspicious` signal at or above this holds the script even when the verdict label is benign. */
  suspiciousHold: number;
  /** Severities that hold a script even when its verdict is benign. */
  holdSeverities: readonly string[];
}

export const DEFAULT_INSPECT_POLICY: InspectPolicy = {
  // Starting values; to be tuned once real /script responses for benign scripts are recorded.
  suspiciousHold: 0.5,
  holdSeverities: ['high', 'critical'],
};

export interface InspectDecision {
  action: InspectAction;
  reason: string;
}

/**
 * Deny on `malicious` (label or probability at the applied threshold); hold on `suspicious` (label, signal, or a
 * high severity); allow only an explicit `benign` verdict. An unrecognized verdict label is held, never allowed.
 */
export function decideInspect(v: InspectVerdict, policy: InspectPolicy = DEFAULT_INSPECT_POLICY): InspectDecision {
  const sev = v.severity ?? 'unknown';
  if (v.verdict === 'malicious' || v.malicious >= v.threshold) {
    return { action: 'deny', reason: `${v.category}, severity ${sev}, malicious ${v.malicious}` };
  }
  if (v.verdict === 'suspicious' || v.suspicious >= policy.suspiciousHold) {
    return { action: 'hold', reason: `${v.category}, severity ${sev}, suspicious ${v.suspicious}: needs approval` };
  }
  if (policy.holdSeverities.includes(sev)) {
    return { action: 'hold', reason: `verdict ${v.verdict} but severity ${sev}: needs approval` };
  }
  if (v.verdict !== 'benign') {
    return { action: 'hold', reason: `unrecognized Inspect verdict "${v.verdict}": held rather than allowed` };
  }
  return { action: 'allow', reason: `verdict benign, malicious ${v.malicious}, suspicious ${v.suspicious}` };
}
