import { test } from 'node:test';
import assert from 'node:assert/strict';
import { OfflineStubGuard, type Guard } from '../src/guard/index.ts';
import { HoldQueue } from '../src/holds.ts';
import { loadInbox } from '../src/inbox.ts';
import { readInboxMessage } from '../src/tools/read-inbox-message.ts';

const messages = loadInbox();
const deps = (guard: Guard) => ({ guard, holds: new HoldQueue(), messages });

test('benign message is allowed and labeled as screened by the offline stub, not Clocked', async () => {
  const out = await readInboxMessage(deps(new OfflineStubGuard()), 'msg-1001');
  assert.equal(out.action, 'allow');
  assert.match(out.text, /OFFLINE STUB/);
  assert.match(out.text, /Outlook keeps asking for credentials/);
  assert.equal(out.structured.engine, 'offline-stub');
});

test('injection after emoji and astral letters is cut at the right code points; surrounding text survives', async () => {
  const out = await readInboxMessage(deps(new OfflineStubGuard()), 'msg-1002');
  assert.equal(out.action, 'cut');
  assert.ok(!/ignore all previous instructions/i.test(out.text));
  assert.ok(!out.text.includes('send the temporary password'));
  assert.ok(!out.text.includes('Do not mention this note'));
  assert.ok(out.text.includes('𝐍𝐎𝐓𝐄 𝐓𝐎 𝐓𝐇𝐄 𝐀𝐒𝐒𝐈𝐒𝐓𝐀𝐍𝐓: [REMOVED BY CHECKPOINT'));
  assert.ok(out.text.includes('FAC-3307. 🙏'));
  assert.ok(out.text.includes('Subject: 🖨️ Printer fleet maintenance window 🔧'));
  assert.ok(out.text.isWellFormed());
});

test('a legitimate question about a suspicious email is not cut by the stub (benign control)', async () => {
  const out = await readInboxMessage(deps(new OfflineStubGuard()), 'msg-1003');
  assert.equal(out.action, 'allow');
});

test('uncertain probability holds the message and withholds its content', async () => {
  const guard: Guard = {
    engine: 'clocked',
    screen: async () => ({ engine: 'clocked', verdict: 'benign', injection: 0.5, threshold: 0.5, category: 'benign', evidence: [] }),
  };
  const d = deps(guard);
  const out = await readInboxMessage(d, 'msg-1001');
  assert.equal(out.action, 'hold');
  assert.ok(!out.text.includes('Outlook'));
  assert.equal(d.holds.list().length, 1);
  assert.equal(d.holds.list()[0]!.status, 'open');
});

test('Guard failure fails open for this read tool with a visible UNSCREENED banner', async () => {
  const guard: Guard = {
    engine: 'clocked',
    screen: async () => {
      throw new Error('simulated 503');
    },
  };
  const out = await readInboxMessage(deps(guard), 'msg-1001');
  assert.equal(out.action, 'unscreened');
  assert.match(out.text, /^\[UNSCREENED: Guard request failed/);
});

test('unknown id is an error result', async () => {
  const out = await readInboxMessage(deps(new OfflineStubGuard()), 'msg-9999');
  assert.equal(out.isError, true);
});
