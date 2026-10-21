import { ClockedInspect } from './clocked.ts';
import { OfflineStubInspect } from './offline-stub.ts';
import type { Inspect } from './types.ts';

export * from './types.ts';
export { ClockedInspect, fromScriptResponse } from './clocked.ts';
export { OfflineStubInspect } from './offline-stub.ts';
export { DEFAULT_INSPECT_POLICY, decideInspect, type InspectAction, type InspectPolicy } from './policy.ts';

/**
 * Picks the Inspect implementation from the environment, the same way as createGuardFromEnv:
 * - CLOCKED_API_KEY set: the real Clocked client.
 * - Otherwise the offline stub, only when CHECKPOINT_INSPECT=offline-stub is set explicitly.
 * - Neither: startup fails instead of silently running unscreened.
 */
export function createInspectFromEnv(env: NodeJS.ProcessEnv = process.env): Inspect {
  const apiKey = env.CLOCKED_API_KEY?.trim();
  if (apiKey) {
    return new ClockedInspect({
      apiKey,
      ...(env.CLOCKED_BASE_URL?.trim() ? { baseUrl: env.CLOCKED_BASE_URL.trim() } : {}),
    });
  }
  if (env.CHECKPOINT_INSPECT === 'offline-stub') return new OfflineStubInspect();
  throw new Error(
    'No Inspect configured: set CLOCKED_API_KEY for real Clocked screening, or CHECKPOINT_INSPECT=offline-stub for local tests only.',
  );
}
