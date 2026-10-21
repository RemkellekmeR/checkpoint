import { randomUUID } from 'node:crypto';
import * as z from 'zod';
import type { ApprovedChange } from '../changes.ts';
import type { HoldQueue } from '../holds.ts';
import { decideInspect, DEFAULT_INSPECT_POLICY, type InspectAction, type InspectPolicy } from '../inspect/policy.ts';
import type { Inspect, InspectVerdict } from '../inspect/types.ts';
import { describeError, stubBanner } from '../labels.ts';
import type { SimulatedRunLog } from '../simulator.ts';
import { codePointSlice } from '../unicode.ts';

export const runRemediationScriptInput = z.object({
  change_id: z.string().regex(/^CHG-[A-Z0-9-]{1,32}$/).describe('Approved change ticket the script belongs to, for example CHG-DEMO-204'),
  script: z.string().min(1).max(20_000).describe('PowerShell or shell script text to assess'),
});

export interface RunScriptDeps {
  inspect: Inspect;
  holds: HoldQueue;
  runs: SimulatedRunLog;
  changes: readonly ApprovedChange[];
  inspectPolicy?: InspectPolicy;
}

export interface RunScriptOutcome {
  action: InspectAction | 'refused' | 'unknown_change';
  text: string;
  structured: Record<string, unknown>;
  isError: boolean;
}

/** 1-based line number of a code point offset (Clocked evidence offsets are characters, not line numbers). */
export function lineNumberAt(script: string, codePointOffset: number): number {
  return codePointSlice(script, 0, codePointOffset).split('\n').length;
}

function evidenceOf(script: string, v: InspectVerdict) {
  return v.evidence.map((e) => ({
    line_number: lineNumberAt(script, e.start),
    line: e.line,
    start: e.start,
    end: e.end,
    confidence: e.confidence,
    // A quote that does not match the script at its offsets is reported, not trusted silently.
    offsets_match: codePointSlice(script, e.start, e.end) === e.line,
  }));
}

/**
 * Execute-class tool: fails CLOSED. The script is NEVER executed. Inspect assesses it against the change ticket's
 * server-side scope; allow = simulated run recorded in memory, hold = approval queue, deny = refusal with evidence.
 */
export async function runRemediationScript(deps: RunScriptDeps, changeId: string, script: string): Promise<RunScriptOutcome> {
  const change = deps.changes.find((c) => c.id === changeId);
  if (!change) {
    return {
      action: 'unknown_change',
      text: `No approved change ${changeId}; the script was not assessed and nothing ran. Known changes: ${deps.changes.map((c) => c.id).join(', ')}`,
      structured: { action: 'unknown_change', change_id: changeId },
      isError: true,
    };
  }

  let verdict: InspectVerdict;
  try {
    verdict = await deps.inspect.assess({ script, instructions: change.scope }, { idempotencyKey: randomUUID() });
  } catch (err) {
    const why = describeError(err);
    return {
      action: 'refused',
      text: `Script for ${change.id} refused: Inspect failed (${why}). Execute tools fail closed when screening is unavailable; nothing ran.`,
      structured: { action: 'refused', change_id: change.id, engine: deps.inspect.engine, error: why },
      isError: true,
    };
  }

  const decision = decideInspect(verdict, deps.inspectPolicy ?? DEFAULT_INSPECT_POLICY);
  const banner = stubBanner({ inspect: verdict.engine });
  const evidence = evidenceOf(script, verdict);
  const structured: Record<string, unknown> = {
    action: decision.action,
    reason: decision.reason,
    engine: verdict.engine,
    change_id: change.id,
    host: change.host,
    verdict: verdict.verdict,
    malicious: verdict.malicious,
    suspicious: verdict.suspicious,
    category: verdict.category,
    severity: verdict.severity ?? null,
    evidence,
  };

  switch (decision.action) {
    case 'allow': {
      const run = deps.runs.record(change.id, change.host, script);
      Object.assign(structured, { simulated_run_id: run.id, executed: false, commands: run.commands.length });
      return {
        action: 'allow',
        text:
          `${banner}SIMULATED RUN ${run.id}: Inspect allowed this script for ${change.id} (${decision.reason}). ` +
          `Checkpoint never executes scripts; it recorded that ${run.commands.length} command line(s) would run on ${change.host}. Nothing was executed.`,
        structured,
        isError: false,
      };
    }
    case 'hold': {
      const hold = deps.holds.open('run_remediation_script', decision.reason, script);
      structured.hold_id = hold.id;
      const lines = evidence.map((e) => `  line ${e.line_number}: ${e.line}`).join('\n');
      return {
        action: 'hold',
        text:
          `${banner}Script for ${change.id} is pending approval (hold id ${hold.id}): ${decision.reason}. It did not run.` +
          (lines ? `\nFlagged lines:\n${lines}` : '') +
          `\nUse check_hold to see its status.`,
        structured,
        isError: false,
      };
    }
    case 'deny':
    default: {
      const lines = evidence.map((e) => `  line ${e.line_number}: ${e.line}`).join('\n') || '  (no evidence lines returned)';
      return {
        action: 'deny',
        text:
          `${banner}Script for ${change.id} DENIED: ${verdict.category} (severity ${verdict.severity ?? 'unknown'}, malicious ${verdict.malicious}). ` +
          `It did not run and was not queued. Evidence:\n${lines}`,
        structured,
        isError: true,
      };
    }
  }
}
