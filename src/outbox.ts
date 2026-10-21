import { randomUUID } from 'node:crypto';

/**
 * SIMULATED OUTBOX. Nothing is ever sent: send_reply only appends here, in memory. There is no SMTP, HTTP or
 * any other transport behind this class, by design.
 */
export interface OutboxEntry {
  id: string;
  createdAt: string;
  /** Inbox message being answered. */
  inReplyTo: string;
  /** The requester's address, kept server-side only; tool results never echo it. */
  to: string;
  subject: string;
  /** The body after Protect: what would have gone out. The agent's original draft is not kept. */
  body: string;
  simulated: true;
}

export class Outbox {
  readonly #entries: OutboxEntry[] = [];

  record(entry: Omit<OutboxEntry, 'id' | 'createdAt' | 'simulated'>): OutboxEntry {
    const e: OutboxEntry = { id: `out-${randomUUID().slice(0, 8)}`, createdAt: new Date().toISOString(), ...entry, simulated: true };
    this.#entries.push(e);
    return e;
  }

  list(): readonly OutboxEntry[] {
    return [...this.#entries];
  }
}
