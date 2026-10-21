import { codePointLength, utf16ToCodePointIndex } from '../unicode.ts';
import type { Inspect, InspectEvidence, InspectRequest, InspectVerdict } from './types.ts';

/**
 * OFFLINE STUB. NOT CLOCKED. NOT REAL SCRIPT ANALYSIS.
 *
 * A handful of line patterns so the Inspect path (simulate / hold / deny) can be exercised in local tests and the
 * smoke script without a Clocked key or network. It ignores the approved change scope, is trivially evaded, and
 * must never be presented as a security control. Every verdict is labeled `engine: "offline-stub"`.
 * Like Clocked's endpoint, it only reads the script text; nothing is executed.
 */
const MALICIOUS: readonly { re: RegExp; category: string }[] = [
  { re: /Set-MpPreference\b.*-Disable\w+\s+\$?true|Stop-Service\b.*\b(?:WinDefend|Sense)\b/i, category: 'security blinding or EDR evasion' },
  { re: /\bmimikatz\b|\bsekurlsa::|procdump\b.*\blsass\b/i, category: 'credential theft or memory dumping' },
  { re: /vssadmin\s+delete\s+shadows|\bwevtutil\s+cl\b|\bClear-EventLog\b/i, category: 'forensic destruction or anti-forensics' },
  { re: /\b(?:IEX|Invoke-Expression)\b.*\b(?:DownloadString|Invoke-WebRequest|iwr)\b|\b(?:curl|wget)\b[^|\n]*\|\s*(?:ba|z)?sh\b/i, category: 'unsafe download or remote code execution' },
  { re: /\s-(?:EncodedCommand|enc)\s+[A-Za-z0-9+/=]{16,}/i, category: 'obfuscated or in-memory payload' },
  { re: /\brm\s+-rf\s+\/(?:\s|$)|\bFormat-Volume\b/i, category: 'ransomware or data destruction' },
];
const SUSPICIOUS: readonly { re: RegExp; category: string }[] = [
  { re: /\bnet\s+(?:user|localgroup)\b.*\/add\b|\bAdd-LocalGroupMember\b/i, category: 'unauthorized persistence or access expansion' },
  { re: /\\CurrentVersion\\Run\b/i, category: 'unauthorized persistence or access expansion' },
  { re: /Set-ExecutionPolicy\s+(?:Bypass|Unrestricted)/i, category: 'security blinding or EDR evasion' },
  { re: /\bRemove-Item\b.*-Recurse\b.*-Force\b/i, category: 'ransomware or data destruction' },
];

/** Evidence is the whole line containing a match, as Clocked quotes it, with code point offsets of that line. */
function lineEvidence(script: string, utf16Index: number): InspectEvidence {
  const lineStart = script.lastIndexOf('\n', utf16Index - 1) + 1;
  const nl = script.indexOf('\n', utf16Index);
  const lineEnd = nl === -1 ? script.length : nl;
  const line = script.slice(lineStart, lineEnd); // UTF-16 indexes from indexOf, converted to code points below
  const start = utf16ToCodePointIndex(script, lineStart);
  return { line, start, end: start + codePointLength(line), confidence: 0.9 };
}

function scan(script: string, patterns: typeof MALICIOUS): { evidence: InspectEvidence[]; category?: string } {
  const evidence: InspectEvidence[] = [];
  let category: string | undefined;
  for (const { re, category: c } of patterns) {
    const m = re.exec(script);
    if (!m) continue;
    const e = lineEvidence(script, m.index);
    if (!evidence.some((x) => x.start === e.start)) evidence.push(e);
    category ??= c;
  }
  evidence.sort((a, b) => a.start - b.start);
  return category ? { evidence, category } : { evidence };
}

export class OfflineStubInspect implements Inspect {
  readonly engine = 'offline-stub' as const;

  async assess(request: InspectRequest): Promise<InspectVerdict> {
    const bad = scan(request.script, MALICIOUS);
    if (bad.category) {
      return { engine: 'offline-stub', verdict: 'malicious', malicious: 0.95, suspicious: 0.97, threshold: 0.5, category: bad.category, severity: 'critical', evidence: bad.evidence };
    }
    const odd = scan(request.script, SUSPICIOUS);
    if (odd.category) {
      return { engine: 'offline-stub', verdict: 'suspicious', malicious: 0.2, suspicious: 0.8, threshold: 0.5, category: odd.category, severity: 'medium', evidence: odd.evidence };
    }
    return { engine: 'offline-stub', verdict: 'benign', malicious: 0.02, suspicious: 0.05, threshold: 0.5, category: 'benign administration', severity: 'none', evidence: [] };
  }
}
