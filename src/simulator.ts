import { randomUUID } from 'node:crypto';

/**
 * SIMULATED EXECUTOR. Checkpoint never executes a script: there is no child_process, shell, eval or remote session
 * anywhere in src/ (a unit test enforces the imports). An allowed script is only recorded here, in memory, with what
 * would have run.
 */
export interface SimulatedRun {
  id: string;
  createdAt: string;
  changeId: string;
  host: string;
  script: string;
  /** Non-empty, non-comment lines: the commands that would have run. */
  commands: string[];
  executed: false;
}

export function commandLines(script: string): string[] {
  return script
    .split(/\r?\n/)
    .map((l) => l.trim())
    .filter((l) => l.length > 0 && !l.startsWith('#'));
}

export class SimulatedRunLog {
  readonly #runs: SimulatedRun[] = [];

  record(changeId: string, host: string, script: string): SimulatedRun {
    const run: SimulatedRun = {
      id: `sim-${randomUUID().slice(0, 8)}`,
      createdAt: new Date().toISOString(),
      changeId,
      host,
      script,
      commands: commandLines(script),
      executed: false,
    };
    this.#runs.push(run);
    return run;
  }

  list(): readonly SimulatedRun[] {
    return [...this.#runs];
  }
}
