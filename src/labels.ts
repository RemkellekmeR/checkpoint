/** Visible labels for tool output touched by an offline stub. A stub is never presented as screening. */
export function stubBanner(engines: Record<string, string>): string {
  const stubbed = Object.entries(engines)
    .filter(([, engine]) => engine === 'offline-stub')
    .map(([name]) => name);
  if (stubbed.length === 0) return '';
  return (
    `[UNSCREENED: Checkpoint is running the OFFLINE STUB ${stubbed.join(' and ')} for local testing. ` +
    `This content was NOT screened by Clocked.]\n`
  );
}

export function describeError(err: unknown): string {
  return err instanceof Error ? `${err.name}: ${err.message}` : String(err);
}
