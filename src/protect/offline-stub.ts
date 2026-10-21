import { codePointLength, utf16ToCodePointIndex } from '../unicode.ts';
import { countByType, replaceFindings } from './anonymize.ts';
import type { Protect, ProtectFinding, ProtectRequest, ProtectResult } from './types.ts';

/**
 * OFFLINE STUB. NOT CLOCKED. NOT REAL PII SCREENING.
 *
 * A few regexes (emails, phone numbers, IPv4 addresses, US SSNs, card-like numbers, EMP- employee ids) so the
 * Protect path can be exercised in local tests and the smoke script without a Clocked key or network. It finds no
 * names, addresses, dates of birth or medical data and must never be presented as a privacy control. Every result
 * is labeled `engine: "offline-stub"`, and the server marks tool output it touched as UNSCREENED.
 */
const PATTERNS: readonly { type: string; re: RegExp }[] = [
  { type: 'email', re: /[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}/g },
  { type: 'ssn', re: /\b\d{3}-\d{2}-\d{4}\b/g },
  { type: 'credit_card', re: /\b(?:\d{4}[ -]){3}\d{4}\b/g },
  { type: 'phone', re: /(?<![\w-])(?:\+\d{1,3}[ .-]?)?\(?\d{3}\)?[ .-]\d{3}[ .-]\d{4}\b/g },
  { type: 'ip_address', re: /\b(?:\d{1,3}\.){3}\d{1,3}\b/g },
  { type: 'employee_id', re: /\bEMP-\d{4,}\b/g },
];

export class OfflineStubProtect implements Protect {
  readonly engine = 'offline-stub' as const;

  async anonymize(request: ProtectRequest): Promise<ProtectResult> {
    const findings: ProtectFinding[] = [];
    for (const { type, re } of PATTERNS) {
      for (const m of request.text.matchAll(re)) {
        const start = utf16ToCodePointIndex(request.text, m.index);
        const end = start + codePointLength(m[0]);
        // The first pattern to claim a span wins (an SSN is not also a phone number).
        if (findings.some((f) => start < f.end && end > f.start)) continue;
        findings.push({ type, value: m[0], start, end, confidence: 0.9 });
      }
    }
    findings.sort((a, b) => a.start - b.start);
    return {
      engine: 'offline-stub',
      anonymizedText: replaceFindings(request.text, findings).text,
      anonymizedBy: 'checkpoint',
      findings,
      counts: countByType(findings),
    };
  }
}
