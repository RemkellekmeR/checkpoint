import { codePointLength, utf16ToCodePointIndex } from '../unicode.ts';
import type { Guard, GuardEvidence, GuardRequest, GuardVerdict } from './types.ts';

/**
 * OFFLINE STUB. NOT CLOCKED. NOT REAL INJECTION SCREENING.
 *
 * A handful of keyword patterns so the MCP server, policy and span cutting can be exercised in local tests
 * and the smoke script without a Clocked key or network. It misses almost every real attack and must never
 * be presented as a security control. Every result it produces is labeled `engine: "offline-stub"`, and the
 * server marks tool output screened by it as UNSCREENED.
 */
const PATTERNS: readonly { re: RegExp; category: string }[] = [
  { re: /ignore (?:all |any )?(?:previous|prior|earlier|the above) instructions[^.\n]*/gi, category: 'instruction override' },
  { re: /disregard (?:your|the) (?:policy|policies|rules|instructions)[^.\n]*/gi, category: 'instruction override' },
  { re: /do not (?:mention|tell|reveal) (?:this|the user)[^.\n]*/gi, category: 'social engineering' },
  { re: /(?:reveal|print|send) (?:your|the) (?:system prompt|api key|credentials)[^.\n]*/gi, category: 'system prompt or secret extraction' },
];

export class OfflineStubGuard implements Guard {
  readonly engine = 'offline-stub' as const;

  async screen(request: GuardRequest): Promise<GuardVerdict> {
    const evidence: GuardEvidence[] = [];
    let category = 'benign';
    for (const { re, category: c } of PATTERNS) {
      for (const m of request.text.matchAll(re)) {
        const start = utf16ToCodePointIndex(request.text, m.index);
        evidence.push({ quote: m[0], start, end: start + codePointLength(m[0]), confidence: 0.9 });
        if (category === 'benign') category = c;
      }
    }
    evidence.sort((a, b) => a.start - b.start);
    const hit = evidence.length > 0;
    return {
      engine: 'offline-stub',
      verdict: hit ? 'injection' : 'benign',
      injection: hit ? Math.min(0.99, 0.8 + 0.05 * evidence.length) : 0.02,
      threshold: 0.5,
      category,
      severity: hit ? (evidence.length > 1 ? 'critical' : 'high') : 'none',
      evidence,
    };
  }
}
