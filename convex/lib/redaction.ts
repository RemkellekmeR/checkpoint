/**
 * Redaction tripwire shared by the Convex functions and the local audit adapter (src/audit/).
 *
 * Audit records are summaries: endpoint, verdict, action, counts, offsets, hashes. They must never carry the raw
 * text that was screened (messages, replies, scripts) or the personal data Protect found. Callers build summaries
 * from counts and labels only; this check is defense in depth that rejects a record that still looks like it holds
 * raw personal data or a credential. It is a coarse pattern check, not PII detection (that is Protect's job).
 *
 * No imports, so Convex's bundler and the Node server can both load it.
 */

const RAW_PATTERNS: readonly { kind: string; re: RegExp }[] = [
  { kind: 'email', re: /[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}/ },
  { kind: 'phone', re: /\b\d{3}[-. ]\d{3}[-. ]\d{4}\b/ },
  { kind: 'ssn', re: /\b\d{3}-\d{2}-\d{4}\b/ },
  { kind: 'card', re: /\b(?:\d[ -]?){13,19}\b/ },
  { kind: 'ipv4', re: /\b(?:\d{1,3}\.){3}\d{1,3}\b/ },
  { kind: 'clocked_key', re: /\bclk_[A-Za-z0-9_-]{8,}/ },
  { kind: 'bearer', re: /\bBearer\s+[A-Za-z0-9._-]{8,}/i },
];

/** Max length of any free-text field in an audit record. Summaries are one line, not documents. */
export const MAX_SUMMARY_CHARS = 400;

/** Returns the kinds of raw-looking data found in `text` (empty when it looks clean). */
export function rawDataKinds(text: string): string[] {
  return RAW_PATTERNS.filter((p) => p.re.test(text)).map((p) => p.kind);
}

/** Throws if a free-text audit field is too long or looks like it carries raw personal data or a secret. */
export function assertRedacted(field: string, text: string): void {
  if (text.length > MAX_SUMMARY_CHARS) {
    throw new Error(`audit field ${field} is ${text.length} chars; summaries are capped at ${MAX_SUMMARY_CHARS}`);
  }
  const kinds = rawDataKinds(text);
  if (kinds.length > 0) {
    throw new Error(`audit field ${field} looks like it holds raw data (${kinds.join(', ')}); store counts or placeholders instead`);
  }
}
