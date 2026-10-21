import { randomUUID } from 'node:crypto';

/** In-memory hold queue for this skeleton. Planned: a Convex `holds` table with approve/deny from a dashboard. */
export interface Hold {
  id: string;
  createdAt: string;
  tool: string;
  reason: string;
  /** The withheld content. Never returned to the agent while the hold is open. */
  withheld: string;
  status: 'open' | 'approved' | 'denied';
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
      status: 'open',
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
}
