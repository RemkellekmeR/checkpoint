import { createGuardFromEnv } from './guard/index.ts';
import { createInspectFromEnv } from './inspect/index.ts';
import { createProtectFromEnv } from './protect/index.ts';
import { MCP_PATH, PROTOCOL_VERSION, createCheckpointHttp } from './server.ts';

const host = process.env.CHECKPOINT_HOST ?? '127.0.0.1';
const port = Number(process.env.CHECKPOINT_PORT ?? 3333);
const allowedOrigins = (process.env.CHECKPOINT_ALLOWED_ORIGINS ?? 'localhost,127.0.0.1,[::1]')
  .split(',')
  .map((s) => s.trim())
  .filter(Boolean);

const guard = createGuardFromEnv();
const protect = createProtectFromEnv();
const inspect = createInspectFromEnv();
const app = createCheckpointHttp({ guard, protect, inspect, allowedOrigins });

app.server.listen(port, host, () => {
  const engine = guard.engine === 'clocked' ? 'Clocked Guard (live API)' : 'OFFLINE STUB guard (local tests only, NOT Clocked)';
  console.log(`checkpoint: MCP Streamable HTTP on http://${host}:${port}${MCP_PATH} (protocol ${PROTOCOL_VERSION})`);
  console.log(`checkpoint: guard engine: ${engine}`);
  console.log(
    `checkpoint: protect engine: ${protect.engine === 'clocked' ? 'Clocked Protect (live API)' : 'OFFLINE STUB protect (local tests only, NOT Clocked)'}`,
  );
  console.log(
    `checkpoint: inspect engine: ${inspect.engine === 'clocked' ? 'Clocked Inspect (live API)' : 'OFFLINE STUB inspect (local tests only, NOT Clocked)'}`,
  );
  console.log(`checkpoint: allowed origins: ${allowedOrigins.join(', ')}`);
});

for (const sig of ['SIGINT', 'SIGTERM'] as const) {
  process.on(sig, () => {
    void app.close().then(() => process.exit(0));
  });
}
