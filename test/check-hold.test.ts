import { test } from 'node:test';
import assert from 'node:assert/strict';
import { HoldQueue } from '../src/holds.ts';
import { checkHold } from '../src/tools/check-hold.ts';

test('check_hold reports pending, then the reviewer decision, and never returns the withheld content', () => {
  const holds = new HoldQueue();
  const h = holds.open('run_remediation_script', 'suspicious script', 'Secret-Withheld-Script-Body');
  let out = checkHold(holds, h.id);
  assert.equal(out.structured.status, 'pending');
  assert.equal(out.isError, false);
  assert.ok(!out.text.includes('Secret-Withheld-Script-Body'));
  assert.ok(!JSON.stringify(out.structured).includes('Secret-Withheld-Script-Body'));

  holds.resolve(h.id, 'approved', 'reviewer@example.com');
  out = checkHold(holds, h.id);
  assert.equal(out.structured.status, 'approved');
  assert.ok(out.structured.decided_at);

  const d = holds.open('send_reply', 'r', 'x');
  holds.resolve(d.id, 'denied', 'reviewer@example.com');
  assert.equal(checkHold(holds, d.id).structured.status, 'denied');
});

test('a decided hold cannot be decided again', () => {
  const holds = new HoldQueue();
  const h = holds.open('send_reply', 'r', 'x');
  holds.resolve(h.id, 'denied', 'reviewer@example.com');
  assert.throws(() => holds.resolve(h.id, 'approved', 'someone-else'));
  assert.equal(holds.get(h.id)!.status, 'denied');
});

test('unknown hold id is an error result', () => {
  const out = checkHold(new HoldQueue(), 'hold-deadbeef');
  assert.equal(out.isError, true);
  assert.equal(out.structured.status, 'not_found');
});
