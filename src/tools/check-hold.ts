import * as z from 'zod';
import type { HoldQueue } from '../holds.ts';

export const checkHoldInput = z.object({
  hold_id: z.string().regex(/^hold-[0-9a-f]{8}$/).describe('Hold id returned by another tool, for example hold-1a2b3c4d'),
});

export interface CheckHoldOutcome {
  text: string;
  structured: Record<string, unknown>;
  isError: boolean;
}

/**
 * Read-only status lookup. Returns status and metadata, never the withheld content, and offers no way to change
 * a hold: approval and denial happen outside the agent's reach (HoldQueue.resolve, reviewer side only).
 */
export function checkHold(holds: HoldQueue, holdId: string): CheckHoldOutcome {
  const hold = holds.get(holdId);
  if (!hold) {
    return { text: `No hold with id ${holdId}.`, structured: { hold_id: holdId, status: 'not_found' }, isError: true };
  }
  const structured: Record<string, unknown> = {
    hold_id: hold.id,
    status: hold.status,
    tool: hold.tool,
    reason: hold.reason,
    created_at: hold.createdAt,
    decided_at: hold.decidedAt ?? null,
  };
  const next =
    hold.status === 'pending'
      ? 'A human reviewer has not decided yet. Do not retry the original action; check again later.'
      : hold.status === 'approved'
        ? 'A human reviewer approved it.'
        : 'A human reviewer denied it. Do not attempt the same action again.';
  return { text: `Hold ${hold.id} (${hold.tool}) is ${hold.status}: ${hold.reason}. ${next}`, structured, isError: false };
}
