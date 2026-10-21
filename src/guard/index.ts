import { ClockedGuard } from './clocked.ts';
import { OfflineStubGuard } from './offline-stub.ts';
import type { Guard } from './types.ts';

export * from './types.ts';
export { ClockedGuard, fromInjectionResponse } from './clocked.ts';
export { OfflineStubGuard } from './offline-stub.ts';

/**
 * Picks the Guard implementation from the environment.
 * - CLOCKED_API_KEY set: the real Clocked client.
 * - Otherwise the offline stub, but only when CHECKPOINT_GUARD=offline-stub is set explicitly
 *   (tests and the smoke script do this). Without either, startup fails instead of silently running unscreened.
 */
export function createGuardFromEnv(env: NodeJS.ProcessEnv = process.env): Guard {
  const apiKey = env.CLOCKED_API_KEY?.trim();
  if (apiKey) {
    return new ClockedGuard({
      apiKey,
      ...(env.CLOCKED_BASE_URL?.trim() ? { baseUrl: env.CLOCKED_BASE_URL.trim() } : {}),
    });
  }
  if (env.CHECKPOINT_GUARD === 'offline-stub') return new OfflineStubGuard();
  throw new Error(
    'No Guard configured: set CLOCKED_API_KEY for real Clocked screening, or CHECKPOINT_GUARD=offline-stub for local tests only.',
  );
}
