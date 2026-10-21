import { ClockedProtect } from './clocked.ts';
import { OfflineStubProtect } from './offline-stub.ts';
import type { Protect } from './types.ts';

export * from './types.ts';
export { ClockedProtect, SERVICE_DESK_ENTITIES, fromPiiResponse } from './clocked.ts';
export { OfflineStubProtect } from './offline-stub.ts';
export { placeholder, replaceFindings } from './anonymize.ts';

/**
 * Picks the Protect implementation from the environment, the same way as createGuardFromEnv:
 * - CLOCKED_API_KEY set: the real Clocked client.
 * - Otherwise the offline stub, only when CHECKPOINT_PROTECT=offline-stub is set explicitly.
 * - Neither: startup fails instead of silently running unscreened.
 */
export function createProtectFromEnv(env: NodeJS.ProcessEnv = process.env): Protect {
  const apiKey = env.CLOCKED_API_KEY?.trim();
  if (apiKey) {
    return new ClockedProtect({
      apiKey,
      ...(env.CLOCKED_BASE_URL?.trim() ? { baseUrl: env.CLOCKED_BASE_URL.trim() } : {}),
    });
  }
  if (env.CHECKPOINT_PROTECT === 'offline-stub') return new OfflineStubProtect();
  throw new Error(
    'No Protect configured: set CLOCKED_API_KEY for real Clocked screening, or CHECKPOINT_PROTECT=offline-stub for local tests only.',
  );
}
