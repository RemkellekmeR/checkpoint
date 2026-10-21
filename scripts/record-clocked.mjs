#!/usr/bin/env node
/**
 * Record raw Clocked responses for the three Protect/Guard/Inspect docs examples.
 *
 * STATUS: BLOCKED until a Clocked account exists and CLOCKED_API_KEY is set. Not yet run.
 *
 * Sends the exact request bodies from Clocked's docs (fixtures/docs/*.request.json) through the pinned clocked-sdk:
 *   clocked.injection(request, { idempotencyKey })  -> POST /clocked/injection  (Guard)
 *   clocked.pii(request, { idempotencyKey })        -> POST /clocked/pii        (Protect)
 *   clocked.script(request, { idempotencyKey })     -> POST /clocked/script     (Inspect)
 * and writes each raw response body plus call metadata to fixtures/recorded/<endpoint>.<timestamp>.json.
 *
 * It spends credits (Clocked bills model time; the docs recordings suggest roughly 26 credits for all three),
 * so it requires --yes. The API key is read from the environment only and is never written to disk.
 *
 * Usage:
 *   CLOCKED_API_KEY=... node scripts/record-clocked.mjs --yes            # all three
 *   CLOCKED_API_KEY=... node scripts/record-clocked.mjs --yes injection  # one endpoint
 */
import { mkdir, readFile, writeFile } from 'node:fs/promises';
import { randomUUID } from 'node:crypto';
import { Clocked, ClockedError, VERSION } from 'clocked-sdk';

const ENDPOINTS = ['injection', 'pii', 'script'];
const root = new URL('../', import.meta.url);
const args = process.argv.slice(2);
const selected = args.filter((a) => !a.startsWith('--'));
const targets = selected.length ? selected : ENDPOINTS;

for (const t of targets) {
  if (!ENDPOINTS.includes(t)) {
    console.error(`Unknown endpoint "${t}". Choose from: ${ENDPOINTS.join(', ')}`);
    process.exit(2);
  }
}

const apiKey = process.env.CLOCKED_API_KEY?.trim();
if (!apiKey) {
  console.error('BLOCKED: CLOCKED_API_KEY is not set. Create a key at https://clocked.rezolve.ai/account, put it in .env (gitignored), then rerun.');
  process.exit(2);
}
if (!args.includes('--yes')) {
  console.error(`This will call ${targets.join(', ')} on the live Clocked API and spend credits. Rerun with --yes to proceed.`);
  process.exit(2);
}

const clocked = new Clocked({
  apiKey,
  ...(process.env.CLOCKED_BASE_URL?.trim() ? { baseUrl: process.env.CLOCKED_BASE_URL.trim() } : {}),
});

// Response headers worth keeping (billing/timing); nothing from the request side, so no Authorization header.
const KEEP_HEADERS = ['x-clocked-model-ms', 'server-timing', 'content-type', 'date', 'x-request-id'];

await mkdir(new URL('fixtures/recorded/', root), { recursive: true });
const stamp = new Date().toISOString().replace(/[:.]/g, '-');
let failures = 0;

for (const endpoint of targets) {
  const request = JSON.parse(await readFile(new URL(`fixtures/docs/${endpoint}.request.json`, root), 'utf8'));
  const idempotencyKey = randomUUID();
  const out = new URL(`fixtures/recorded/${endpoint}.${stamp}.json`, root);
  const started = Date.now();
  try {
    const res = await clocked[endpoint](request, { idempotencyKey });
    const headers = Object.fromEntries(KEEP_HEADERS.flatMap((h) => (res.headers.has(h) ? [[h, res.headers.get(h)]] : [])));
    await writeFile(
      out,
      JSON.stringify(
        {
          endpoint: `/clocked/${endpoint}`,
          recordedAt: new Date().toISOString(),
          sdk: `clocked-sdk@${VERSION}`,
          requestSource: `fixtures/docs/${endpoint}.request.json`,
          status: res.status,
          modelMs: res.modelMs,
          serverTiming: res.serverTiming,
          idempotencyKey: res.idempotencyKey,
          attempts: res.attempts,
          wallMs: Date.now() - started,
          headers,
          request,
          response: res.data,
        },
        null,
        2,
      ) + '\n',
    );
    console.log(`recorded ${endpoint}: HTTP ${res.status}, model ${res.modelMs} ms -> ${out.pathname}`);
  } catch (err) {
    failures++;
    if (err instanceof ClockedError) {
      console.error(`FAILED ${endpoint}: ${err.name} status=${err.status} error=${err.error} key=${err.idempotencyKey} attempts=${err.attempts}`);
      await writeFile(
        out.pathname.replace(/\.json$/, '.error.json'),
        JSON.stringify(
          { endpoint: `/clocked/${endpoint}`, recordedAt: new Date().toISOString(), sdk: `clocked-sdk@${VERSION}`, name: err.name, status: err.status, error: err.error, retryAsNew: err.retryAsNew, idempotencyKey: err.idempotencyKey, attempts: err.attempts, body: err.body },
          null,
          2,
        ) + '\n',
      );
    } else {
      console.error(`FAILED ${endpoint}:`, err);
    }
  }
}

console.log('Read actual credits per call off the Clocked usage page and note them in fixtures/recorded/README.md.');
process.exit(failures ? 1 : 0);
