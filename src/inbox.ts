import { readFileSync } from 'node:fs';

export interface InboxMessage {
  id: string;
  from: string;
  subject: string;
  received: string;
  body: string;
}

const FIXTURE = new URL('../fixtures/inbox.json', import.meta.url);

export function loadInbox(path: URL | string = FIXTURE): InboxMessage[] {
  const raw = JSON.parse(readFileSync(path, 'utf8')) as { messages: InboxMessage[] };
  return raw.messages;
}

/** The exact text the agent would read; Guard screens this string and its offsets refer to it. */
export function renderMessage(m: InboxMessage): string {
  return `From: ${m.from}\nSubject: ${m.subject}\nReceived: ${m.received}\n\n${m.body}`;
}
