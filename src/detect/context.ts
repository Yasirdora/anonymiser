/**
 * Context scoring.
 *
 * Shape alone is a weak signal. A nine-digit number preceded by "SSN:" and one
 * sitting in a column of invoice numbers are the same regex match and very
 * different facts. Context turns the first into an automatic redaction and
 * leaves the second for review, which is the difference between a tool people
 * trust and one they turn off.
 */

import type { Evidence } from './types.js';

/** Keywords and negative cues that modulate a rule's confidence. */
export interface ContextSpec {
  /** Terms that, appearing near the match, corroborate it. */
  readonly supports?: readonly string[];
  /** Terms that indicate a false positive, e.g. "invoice" beside a long number. */
  readonly suppresses?: readonly string[];
  /** Characters of surrounding text examined on each side. Defaults to 48. */
  readonly window?: number;
  /**
   * When true, a match with no supporting term is dropped rather than merely
   * demoted. Reserved for shapes so generic that they are noise without a cue.
   */
  readonly requireSupport?: boolean;
  /** Confidence added per supporting term, capped at `SUPPORT_CAP`. */
  readonly supportWeight?: number;
  /** Confidence removed per suppressing term. */
  readonly suppressWeight?: number;
}

const DEFAULT_WINDOW = 48;
const DEFAULT_SUPPORT_WEIGHT = 0.12;
const DEFAULT_SUPPRESS_WEIGHT = 0.35;
const SUPPORT_CAP = 0.3;

/** The text immediately before and after a match. */
export interface ContextWindow {
  readonly before: string;
  readonly after: string;
  /** Both sides lowercased and joined, for keyword scanning. */
  readonly haystack: string;
}

/** Extract the surrounding text for a match at `[start, end)`. */
export function windowAround(
  text: string,
  start: number,
  end: number,
  size = DEFAULT_WINDOW,
): ContextWindow {
  const before = text.slice(Math.max(0, start - size), start);
  const after = text.slice(end, Math.min(text.length, end + size));
  // Underscores and hyphens fold to spaces so a structured key like
  // `social_security_number` matches the term "social security". Sensitive
  // values sit inside JSON and log payloads more often than in prose, and their
  // keys are never written with spaces.
  const haystack = `${before} ${after}`.toLowerCase().replace(/[_-]+/g, ' ');
  return { before, after, haystack };
}

/** The outcome of scoring one match against its context. */
export interface ContextScore {
  /** Confidence delta to apply to the rule's base score. */
  readonly delta: number;
  /** True when the match must be discarded entirely. */
  readonly rejected: boolean;
  readonly evidence: readonly Evidence[];
}

/**
 * Score a match against its surroundings.
 *
 * Keyword hits are counted once each; repeating "ssn" five times in a header
 * should not push an unvalidated match to certainty.
 */
export function scoreContext(
  spec: ContextSpec | undefined,
  window: ContextWindow,
): ContextScore {
  if (spec === undefined) return { delta: 0, rejected: false, evidence: [] };

  const evidence: Evidence[] = [];
  const supportWeight = spec.supportWeight ?? DEFAULT_SUPPORT_WEIGHT;
  const suppressWeight = spec.suppressWeight ?? DEFAULT_SUPPRESS_WEIGHT;

  const supportHits = matchedTerms(spec.supports, window.haystack);
  const suppressHits = matchedTerms(spec.suppresses, window.haystack);

  let delta = 0;
  if (supportHits.length > 0) {
    const gain = Math.min(SUPPORT_CAP, supportHits.length * supportWeight);
    delta += gain;
    evidence.push({
      signal: 'context:support',
      note: `nearby text mentions ${formatTerms(supportHits)}`,
      weight: gain,
    });
  }
  if (suppressHits.length > 0) {
    const loss = suppressHits.length * suppressWeight;
    delta -= loss;
    evidence.push({
      signal: 'context:suppress',
      note: `nearby text mentions ${formatTerms(suppressHits)}, which usually indicates a different kind of number`,
      weight: -loss,
    });
  }

  if (spec.requireSupport === true && supportHits.length === 0) {
    return {
      delta,
      rejected: true,
      evidence: [
        ...evidence,
        {
          signal: 'context:missing-support',
          note: 'shape matched but no corroborating label was found nearby',
          weight: -1,
        },
      ],
    };
  }

  return { delta, rejected: false, evidence };
}

/**
 * Find which terms appear in the haystack as whole words.
 *
 * Substring matching would fire "id" inside "identify" and "ssn" inside a
 * base64 blob, so alphanumeric terms are matched at word boundaries. Terms
 * containing punctuation (like "account #") are matched literally.
 */
function matchedTerms(terms: readonly string[] | undefined, haystack: string): string[] {
  if (terms === undefined || terms.length === 0) return [];
  const hits: string[] = [];
  for (const term of terms) {
    const needle = term.toLowerCase();
    if (/^[a-z0-9]+$/.test(needle)) {
      const index = haystack.indexOf(needle);
      if (index === -1) continue;
      const before = index === 0 ? ' ' : haystack[index - 1]!;
      const afterIndex = index + needle.length;
      const after = afterIndex >= haystack.length ? ' ' : haystack[afterIndex]!;
      if (!/[a-z0-9]/.test(before) && !/[a-z0-9]/.test(after)) hits.push(term);
    } else if (haystack.includes(needle)) {
      hits.push(term);
    }
  }
  return hits;
}

function formatTerms(terms: readonly string[]): string {
  const quoted = terms.slice(0, 3).map((t) => `"${t}"`);
  const extra = terms.length - quoted.length;
  return extra > 0 ? `${quoted.join(', ')} and ${extra} more` : quoted.join(', ');
}
