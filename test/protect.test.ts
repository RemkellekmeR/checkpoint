import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import type { PiiResponse } from 'clocked-sdk';
import {
  ClockedProtect,
  OfflineStubProtect,
  createProtectFromEnv,
  fromPiiResponse,
  replaceFindings,
} from '../src/protect/index.ts';
import { codePointSlice } from '../src/unicode.ts';

const json = (p: string) => JSON.parse(readFileSync(new URL(p, import.meta.url), 'utf8'));
const docReq = json('../fixtures/docs/pii.request.json') as { text: string };
const docRes = json('../fixtures/docs/pii.response.recorded-2026-10-08.json') as PiiResponse;

test("Clocked's recorded /pii response: offsets are code points into the request, anonymized_text is used as is", () => {
  const r = fromPiiResponse(docReq.text, docRes);
  assert.equal(r.engine, 'clocked');
  assert.equal(r.anonymizedBy, 'engine');
  assert.equal(r.anonymizedText, docRes.anonymized_text);
  assert.equal(r.findings.length, 6);
  for (const f of r.findings) assert.equal(codePointSlice(docReq.text, f.start, f.end), f.value);
  assert.deepEqual(r.counts, docRes.counts);
});

test('rebuilding the replace-style copy from the recorded offsets reproduces Clocked anonymized_text exactly', () => {
  assert.equal(replaceFindings(docReq.text, docRes.entities).text, docRes.anonymized_text);
});

test('if anonymized_text is absent, Checkpoint rebuilds it from offsets instead of passing the original on', () => {
  const { anonymized_text: _drop, ...withoutText } = docRes;
  const r = fromPiiResponse(docReq.text, withoutText as PiiResponse);
  assert.equal(r.anonymizedBy, 'checkpoint');
  assert.equal(r.anonymizedText, docRes.anonymized_text);
  assert.ok(!r.anonymizedText.includes('alex.chen@example.com'));
});

test('ClockedProtect sends the documented request shape (fake client, no network)', async () => {
  const calls: { req: Record<string, unknown>; opts: unknown }[] = [];
  const fake = {
    pii: async (req: Record<string, unknown>, opts: unknown) => {
      calls.push({ req, opts });
      return { data: docRes, modelMs: 176, idempotencyKey: 'test-key' } as never;
    },
  };
  const p = new ClockedProtect({ apiKey: 'unused', client: fake as never, threshold: 0.5 });
  const r = await p.anonymize({ text: docReq.text, instructions: 'ctx' }, { idempotencyKey: 'test-key' });
  const req = calls[0]!.req;
  assert.equal(req.text, docReq.text);
  assert.equal(req.anonymize, 'replace');
  assert.equal(req.instructions, 'ctx');
  assert.equal(req.threshold, 0.5);
  assert.equal((req.entities as Record<string, unknown>).employee_id, 'Employee identifiers such as EMP-90214');
  assert.equal((req.entities as Record<string, unknown>).email, null);
  assert.deepEqual(calls[0]!.opts, { idempotencyKey: 'test-key' });
  assert.equal(r.modelMs, 176);
});

test('offline stub is labeled and replaces emails, phones and EMP ids at code point offsets after emoji', async () => {
  const text = '🙏😀 Call me on 503-555-0142 or mail sam.lee@example.com, I am EMP-55120. Ticket FAC-3307, 18:00–20:00.';
  const r = await new OfflineStubProtect().anonymize({ text });
  assert.equal(r.engine, 'offline-stub');
  assert.equal(r.anonymizedText, '🙏😀 Call me on <PHONE> or mail <EMAIL>, I am <EMPLOYEE_ID>. Ticket FAC-3307, 18:00–20:00.');
  for (const f of r.findings) assert.equal(codePointSlice(text, f.start, f.end), f.value);
  assert.deepEqual(r.counts, { phone: 1, email: 1, employee_id: 1 });
});

test('offline stub leaves timestamps and ticket numbers alone', async () => {
  const text = 'Received: 2026-10-21T08:12:00-07:00 re INV-2026-884 and PO-7742';
  const r = await new OfflineStubProtect().anonymize({ text });
  assert.equal(r.anonymizedText, text);
});

test('createProtectFromEnv: key selects Clocked, explicit flag selects stub, nothing configured throws', () => {
  assert.equal(createProtectFromEnv({ CLOCKED_API_KEY: 'placeholder-not-a-key' }).engine, 'clocked');
  assert.equal(createProtectFromEnv({ CHECKPOINT_PROTECT: 'offline-stub' }).engine, 'offline-stub');
  assert.throws(() => createProtectFromEnv({}));
});
