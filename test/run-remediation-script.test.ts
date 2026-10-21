import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, readdirSync } from 'node:fs';
import { join } from 'node:path';
import { loadChanges } from '../src/changes.ts';
import { HoldQueue } from '../src/holds.ts';
import { OfflineStubInspect, type Inspect } from '../src/inspect/index.ts';
import { SimulatedRunLog } from '../src/simulator.ts';
import { lineNumberAt, runRemediationScript } from '../src/tools/run-remediation-script.ts';

const changes = loadChanges();
const docScript = (JSON.parse(readFileSync(new URL('../fixtures/docs/script.request.json', import.meta.url), 'utf8')) as { script: string }).script;
const deps = (inspect: Inspect = new OfflineStubInspect()) => ({ inspect, holds: new HoldQueue(), runs: new SimulatedRunLog(), changes });

test('allowed script gets a simulated run only: recorded, executed=false, labeled offline stub', async () => {
  const d = deps();
  const out = await runRemediationScript(d, 'CHG-DEMO-204', '# check spooler\nGet-Service -Name Spooler\nRestart-Service -Name Spooler\n');
  assert.equal(out.action, 'allow');
  assert.equal(out.isError, false);
  assert.equal(out.structured.executed, false);
  const [run] = d.runs.list();
  assert.ok(run);
  assert.equal(run.executed, false);
  assert.equal(run.host, 'WS-PRN-0412');
  assert.deepEqual(run.commands, ['Get-Service -Name Spooler', 'Restart-Service -Name Spooler']);
  assert.match(out.text, /SIMULATED RUN/);
  assert.match(out.text, /Nothing was executed/);
  assert.match(out.text, /OFFLINE STUB inspect/);
});

test('malicious script (Clocked docs example) is denied with evidence line and line number; nothing queued or run', async () => {
  const d = deps();
  const out = await runRemediationScript(d, 'CHG-DEMO-204', docScript);
  assert.equal(out.action, 'deny');
  assert.equal(out.isError, true);
  const ev = out.structured.evidence as { line: string; line_number: number; offsets_match: boolean }[];
  assert.deepEqual(ev.map((e) => [e.line, e.line_number, e.offsets_match]), [['Set-MpPreference -DisableRealtimeMonitoring $true', 5, true]]);
  assert.match(out.text, /line 5: Set-MpPreference/);
  assert.equal(d.runs.list().length, 0);
  assert.equal(d.holds.list().length, 0);
});

test('suspicious script is queued for approval with the script withheld in the hold, not run', async () => {
  const d = deps();
  const script = 'Unlock-ADAccount -Identity pnair\nnet localgroup Administrators pnair /add';
  const out = await runRemediationScript(d, 'CHG-1001', script);
  assert.equal(out.action, 'hold');
  const hold = d.holds.get(out.structured.hold_id as string)!;
  assert.equal(hold.tool, 'run_remediation_script');
  assert.equal(hold.status, 'pending');
  assert.equal(hold.withheld, script);
  assert.equal(d.runs.list().length, 0);
  assert.match(out.text, /line 2: net localgroup/);
});

test('Inspect error fails closed: refused, nothing run or queued', async () => {
  const d = deps({
    engine: 'clocked',
    assess: async () => {
      throw new Error('simulated 503');
    },
  });
  const out = await runRemediationScript(d, 'CHG-DEMO-204', 'Get-Service -Name Spooler');
  assert.equal(out.action, 'refused');
  assert.equal(out.isError, true);
  assert.equal(d.runs.list().length, 0);
  assert.equal(d.holds.list().length, 0);
});

test('the change scope sent to Inspect comes from the server-side ticket, never from the agent', async () => {
  const seen: (string | undefined)[] = [];
  const spy: Inspect = { engine: 'clocked', assess: async (r) => (seen.push(r.instructions), new OfflineStubInspect().assess(r)) };
  await runRemediationScript(deps(spy), 'CHG-1001', 'Get-ADUser pnair');
  assert.deepEqual(seen, [changes.find((c) => c.id === 'CHG-1001')!.scope]);
});

test('unknown change id is refused before Inspect is called', async () => {
  let called = 0;
  const spy: Inspect = { engine: 'clocked', assess: async (r) => (called++, new OfflineStubInspect().assess(r)) };
  const out = await runRemediationScript(deps(spy), 'CHG-9999', 'Get-Date');
  assert.equal(out.action, 'unknown_change');
  assert.equal(called, 0);
});

test('evidence whose quote does not match the script at its offsets is flagged, not trusted', async () => {
  const lying: Inspect = {
    engine: 'clocked',
    assess: async () => ({ engine: 'clocked', verdict: 'malicious', malicious: 0.9, suspicious: 0.9, threshold: 0.5, category: 'x', severity: 'high', evidence: [{ line: 'not in script', start: 0, end: 5, confidence: 1 }] }),
  };
  const out = await runRemediationScript(deps(lying), 'CHG-DEMO-204', 'Get-Date');
  assert.equal((out.structured.evidence as { offsets_match: boolean }[])[0]!.offsets_match, false);
});

test('lineNumberAt counts code points, so emoji before the line do not shift it', () => {
  const s = '# 😀😀😀\nGet-Date\nStop-Computer';
  assert.equal(lineNumberAt(s, Array.from(s).indexOf('S')), 3);
});

test('nothing under src/ can execute a process: no child_process, worker_threads, vm or eval', () => {
  const files: string[] = [];
  const walk = (dir: string) => {
    for (const e of readdirSync(dir, { withFileTypes: true })) {
      const p = join(dir, e.name);
      if (e.isDirectory()) walk(p);
      else if (p.endsWith('.ts')) files.push(p);
    }
  };
  walk(new URL('../src', import.meta.url).pathname);
  assert.ok(files.length > 10);
  // Any import, dynamic import or require of a process/code-execution module, plus eval and new Function.
  const banned =
    /(?:\bfrom\s*|\bimport\s*\(\s*|\brequire\s*\(\s*|^import\s+)['"](?:node:)?(?:child_process|worker_threads|cluster|vm)['"]|\beval\s*\(|\bnew\s+Function\s*\(/m;
  for (const f of files) assert.ok(!banned.test(readFileSync(f, 'utf8')), `${f} must not import process-execution APIs`);
  // The check itself must catch the real thing.
  assert.ok(banned.test("import { spawn } from 'node:child_process';"));
  assert.ok(banned.test("const cp = await import('child_process');"));
});
