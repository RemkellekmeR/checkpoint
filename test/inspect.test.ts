import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import type { ScriptResponse } from 'clocked-sdk';
import {
  ClockedInspect,
  OfflineStubInspect,
  createInspectFromEnv,
  decideInspect,
  fromScriptResponse,
  type InspectVerdict,
} from '../src/inspect/index.ts';
import { codePointSlice } from '../src/unicode.ts';

const json = (p: string) => JSON.parse(readFileSync(new URL(p, import.meta.url), 'utf8'));
const docReq = json('../fixtures/docs/script.request.json') as { script: string; instructions: string };
const docRes = json('../fixtures/docs/script.response.recorded-2026-10-08.json') as ScriptResponse;

test("Clocked's recorded /script response maps to deny; evidence offsets are code points of the quoted line", () => {
  const v = fromScriptResponse(docRes);
  assert.equal(v.engine, 'clocked');
  assert.equal(v.verdict, 'malicious');
  assert.equal(v.evidence.length, 1);
  for (const e of v.evidence) assert.equal(codePointSlice(docReq.script, e.start, e.end), e.line);
  assert.equal(decideInspect(v).action, 'deny');
});

test('ClockedInspect sends the documented request shape (fake client, no network)', async () => {
  const calls: unknown[] = [];
  const fake = {
    script: async (req: unknown, opts: unknown) => {
      calls.push({ req, opts });
      return { data: docRes, modelMs: 110, idempotencyKey: 'test-key' } as never;
    },
  };
  const i = new ClockedInspect({ apiKey: 'unused', client: fake, threshold: 0.5 });
  const v = await i.assess({ script: docReq.script, instructions: docReq.instructions }, { idempotencyKey: 'test-key' });
  assert.deepEqual(calls[0], {
    req: { script: docReq.script, instructions: docReq.instructions, threshold: 0.5, evidence: true },
    opts: { idempotencyKey: 'test-key' },
  });
  assert.equal(v.modelMs, 110);
});

test('policy: malicious denies, suspicious holds, benign allows, unknown labels and high severities hold', () => {
  const base: InspectVerdict = { engine: 'clocked', verdict: 'benign', malicious: 0.01, suspicious: 0.02, threshold: 0.5, category: 'benign administration', severity: 'none', evidence: [] };
  assert.equal(decideInspect(base).action, 'allow');
  assert.equal(decideInspect({ ...base, verdict: 'malicious', malicious: 0.4 }).action, 'deny');
  assert.equal(decideInspect({ ...base, malicious: 0.6 }).action, 'deny', 'probability at the threshold denies even with a benign label');
  assert.equal(decideInspect({ ...base, verdict: 'suspicious', suspicious: 0.3 }).action, 'hold');
  assert.equal(decideInspect({ ...base, suspicious: 0.7 }).action, 'hold');
  assert.equal(decideInspect({ ...base, severity: 'high' }).action, 'hold');
  assert.equal(decideInspect({ ...base, verdict: 'safe' }).action, 'hold');
});

test('offline stub: docs example is malicious with the Defender line as evidence; spooler-only script is benign', async () => {
  const stub = new OfflineStubInspect();
  const bad = await stub.assess({ script: docReq.script });
  assert.equal(bad.engine, 'offline-stub');
  assert.equal(bad.verdict, 'malicious');
  assert.deepEqual(
    bad.evidence.map((e) => [e.line, e.start, e.end]),
    docRes.evidence!.map((e) => [e.line, e.start, e.end]),
    'stub evidence matches the offsets Clocked recorded for the same line',
  );
  const good = await stub.assess({ script: 'Get-Service -Name Spooler\nRestart-Service -Name Spooler\nGet-Printer' });
  assert.equal(good.verdict, 'benign');
  assert.equal(decideInspect(good).action, 'allow');
});

test('offline stub: suspicious line after emoji gets code point offsets', async () => {
  const script = '# 🖨️😀 onboarding helper\nnet localgroup Administrators temp.admin /add\nGet-Date';
  const v = await new OfflineStubInspect().assess({ script });
  assert.equal(v.verdict, 'suspicious');
  const e = v.evidence[0]!;
  assert.equal(codePointSlice(script, e.start, e.end), 'net localgroup Administrators temp.admin /add');
  assert.equal(decideInspect(v).action, 'hold');
});

test('createInspectFromEnv: key selects Clocked, explicit flag selects stub, nothing configured throws', () => {
  assert.equal(createInspectFromEnv({ CLOCKED_API_KEY: 'placeholder-not-a-key' }).engine, 'clocked');
  assert.equal(createInspectFromEnv({ CHECKPOINT_INSPECT: 'offline-stub' }).engine, 'offline-stub');
  assert.throws(() => createInspectFromEnv({}));
});
