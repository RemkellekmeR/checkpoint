import { codePointLength, cutSpans, normalizeSpans } from '../unicode.ts';
import type { ProtectFinding } from './types.ts';

/** Clocked's `replace` operator style: a typed placeholder such as <EMAIL> or <EMPLOYEE_ID>. */
export function placeholder(type: string): string {
  return `<${type.toUpperCase().replace(/[^A-Z0-9]+/g, '_')}>`;
}

/**
 * Replaces each finding with its typed placeholder, using code point offsets (never String.slice).
 * Overlapping findings are merged first; a merged span takes the type of the earliest finding inside it.
 * Findings whose offsets do not fit the text are not applied and are counted in `rejected`.
 */
export function replaceFindings(text: string, findings: readonly ProtectFinding[]): { text: string; rejected: number } {
  const { spans } = normalizeSpans(findings, codePointLength(text));
  const sorted = [...findings].sort((a, b) => a.start - b.start || a.end - b.end);
  const r = cutSpans(text, spans, (_removed, i) => {
    const span = spans[i]!;
    const f = sorted.find((x) => x.start >= span.start && x.start < span.end);
    return placeholder(f?.type ?? 'pii');
  });
  return { text: r.text, rejected: r.rejected.length };
}

export function countByType(findings: readonly ProtectFinding[]): Record<string, number> {
  const counts: Record<string, number> = {};
  for (const f of findings) counts[f.type] = (counts[f.type] ?? 0) + 1;
  return counts;
}
