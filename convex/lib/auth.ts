/**
 * Shared-secret check for every Checkpoint function. Convex public functions are reachable by anyone who knows the
 * deployment URL, so each one takes the token the MCP server holds (`CHECKPOINT_CONVEX_TOKEN`, set on both sides) and
 * fails closed when the deployment has no token configured. Planned: replace with real reviewer auth for the dashboard.
 */
declare const process: { env: Record<string, string | undefined> };

export function requireToken(token: string): void {
  const expected = process.env.CHECKPOINT_CONVEX_TOKEN;
  if (!expected) throw new Error('CHECKPOINT_CONVEX_TOKEN is not set on this deployment; refusing all calls');
  if (token.length !== expected.length) throw new Error('bad token');
  let diff = 0;
  for (let i = 0; i < token.length; i++) diff |= token.charCodeAt(i) ^ expected.charCodeAt(i);
  if (diff !== 0) throw new Error('bad token');
}
