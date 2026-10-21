import { readFileSync } from 'node:fs';

/** An approved change ticket: the only source of the scope Inspect assesses a script against. */
export interface ApprovedChange {
  id: string;
  title: string;
  host: string;
  /** Approved environment and actions, sent to Inspect as `instructions`. Never taken from the agent. */
  scope: string;
}

const FIXTURE = new URL('../fixtures/changes.json', import.meta.url);

export function loadChanges(path: URL | string = FIXTURE): ApprovedChange[] {
  return (JSON.parse(readFileSync(path, 'utf8')) as { changes: ApprovedChange[] }).changes;
}
