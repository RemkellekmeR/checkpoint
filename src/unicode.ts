/**
 * Clocked returns text offsets as zero-based Unicode code point positions with an exclusive end
 * ("Offsets count Unicode characters, not bytes or JavaScript UTF-16 code units").
 * JavaScript strings index UTF-16 code units, so `String.prototype.slice` with those offsets
 * misplaces every span that follows an astral character (most emoji, some CJK, math symbols).
 * Everything in Checkpoint that applies a Clocked offset goes through these helpers.
 */

export interface CodePointSpan {
  /** Zero-based code point index, inclusive. */
  start: number;
  /** Zero-based code point index, exclusive. */
  end: number;
}

/** Splits a string into code points (astral characters stay whole). */
export function toCodePoints(text: string): string[] {
  return Array.from(text);
}

/** Length of a string in Unicode code points. */
export function codePointLength(text: string): number {
  let n = 0;
  for (const _ of text) n++;
  return n;
}

/** Slices by code point positions, end exclusive. */
export function codePointSlice(text: string, start: number, end?: number): string {
  return toCodePoints(text).slice(start, end).join('');
}

/** Returns true when the span fits the text and is non-empty. */
export function isValidSpan(span: CodePointSpan, length: number): boolean {
  return (
    Number.isInteger(span.start) &&
    Number.isInteger(span.end) &&
    span.start >= 0 &&
    span.end > span.start &&
    span.end <= length
  );
}

/** Sorts spans and merges overlapping or touching ones. Invalid spans are dropped and reported. */
export function normalizeSpans(
  spans: readonly CodePointSpan[],
  length: number,
): { spans: CodePointSpan[]; rejected: CodePointSpan[] } {
  const rejected: CodePointSpan[] = [];
  const valid = spans.filter((s) => {
    const ok = isValidSpan(s, length);
    if (!ok) rejected.push(s);
    return ok;
  });
  valid.sort((a, b) => a.start - b.start || a.end - b.end);
  const merged: CodePointSpan[] = [];
  for (const s of valid) {
    const last = merged[merged.length - 1];
    if (last && s.start <= last.end) {
      last.end = Math.max(last.end, s.end);
    } else {
      merged.push({ start: s.start, end: s.end });
    }
  }
  return { spans: merged, rejected };
}

export interface CutResult {
  /** The text with every span replaced. */
  text: string;
  /** The merged spans that were cut, in code point positions of the original text. */
  cut: CodePointSpan[];
  /** Spans that did not fit the text (out of range, empty, non-integer) and were not applied. */
  rejected: CodePointSpan[];
}

/**
 * Replaces each span (code point offsets into `text`) with `replacement(removed, index)`.
 * Overlapping spans are merged first so nothing is cut twice.
 */
export function cutSpans(
  text: string,
  spans: readonly CodePointSpan[],
  replacement: (removed: string, index: number) => string = () => '[REMOVED]',
): CutResult {
  const cps = toCodePoints(text);
  const { spans: merged, rejected } = normalizeSpans(spans, cps.length);
  let out = '';
  let cursor = 0;
  merged.forEach((s, i) => {
    out += cps.slice(cursor, s.start).join('');
    out += replacement(cps.slice(s.start, s.end).join(''), i);
    cursor = s.end;
  });
  out += cps.slice(cursor).join('');
  return { text: out, cut: merged, rejected };
}

/** Converts a UTF-16 index (what `String.prototype.indexOf` returns) to a code point index. */
export function utf16ToCodePointIndex(text: string, utf16Index: number): number {
  return codePointLength(text.slice(0, utf16Index));
}
