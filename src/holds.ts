import { randomUUID } from 'node:crypto';

/** In-memory hold queue for this skeleton. Planned: a Convex `holds` table with approve/deny from a dashboard. */
export type HoldStatus = 'pending' | 'approved' | 'denied';

export interface Hold {
  id: string;
  createdAt: string;
  tool: string;
  reason: string;
  /** The withheld content (message, reply or script). Never returned to the agent, not even by check_hold. */
  withheld: string;
  status: HoldStatus;
  decidedAt?: string;
  decidedBy?: string;
}

export class HoldQueue {
  readonly #holds = new Map<string, Hold>();

  open(tool: string, reason: string, withheld: string): Hold {
    const hold: Hold = {
      id: `hold-${randomUUID().slice(0, 8)}`,
      createdAt: new Date().toISOString(),
      tool,
      reason,
      withheld,
      status: 'pending',
    };
    this.#holds.set(hold.id, hold);
    return hold;
  }

  get(id: string): Hold | undefined {
    return this.#holds.get(id);
  }

  list(): Hold[] {
    return [...this.#holds.values()];
  }

  /**
   * Reviewer-side decision. This is deliberately NOT exposed as an MCP tool: the agent can look a hold up with
   * check_hold but can never approve or deny one. A decided hold cannot be decided again.
   */
  resolve(id: string, decision: 'approved' | 'denied', reviewer: string): Hold {
    const hold = this.#holds.get(id);
    if (!hold) throw new Error(`No hold with id ${id}`);
    if (hold.status !== 'pending') throw new Error(`Hold ${id} is already ${hold.status}`);
    hold.status = decision;
    hold.decidedAt = new Date().toISOString();
    hold.decidedBy = reviewer;
    return hold;
  }
}
