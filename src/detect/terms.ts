/**
 * Redacting every occurrence of a term the operator names.
 *
 * No rule set is ever complete. A project has a codename, a site has a local
 * nickname, a participant is referred to by an initial the detectors have no
 * reason to treat as a name -- and the reviewer knows all of this and the engine
 * does not. Without a way to say "this word, everywhere", the only remedy is to
 * find several hundred occurrences by hand, which is both unbearable and the
 * single most reliable way to miss one.
 *
 * This is deliberately a *detector* rather than a search-and-replace. Every
 * match becomes an ordinary finding, so it is classified, planned, verified and
 * recorded in the manifest exactly like something a rule found. A reviewer can
 * still keep an individual match, the read-back still confirms every one of them
 * is gone, and the audit record still says under what authority. A replace pass
 * bolted onto the output would have none of those properties.
 *
 * Matches are reported at {@link Confidence.VERIFIED}: a person naming a term is
 * a stronger signal than any pattern, and there is no scoring left to do.
 */

import { toBase32 } from '../internal/bytes.js';
import { sha256Text } from '../internal/hash.js';
import type { ContentNode, TextLocation } from '../model/document.js';
import { ClassifiedError } from '../errors.js';
import { Confidence, type DetectionContext, type Detector, type EntityType, type Finding } from './types.js';

/** One term to hunt for. */
export interface TermRule {
  /** The literal text to find. Not a regular expression. */
  readonly text: string;
  /** What it is, for classification. Defaults to `manual.marked`. */
  readonly type?: EntityType;
  /** Match case exactly. Off by default, because prose varies. */
  readonly matchCase?: boolean;
  /**
   * Require the match to be a whole word.
   *
   * On by default. Without it, redacting `Ann` also blanks the middle of
   * `announcement` and `Anne`, which over a long document produces a page of
   * bars in the middle of ordinary words and hides the real matches among them.
   * A reviewer redacting a fragment -- a partial account number, a URL stem --
   * turns it off deliberately.
   */
  readonly whole?: boolean;
}

/**
 * Shortest term worth accepting.
 *
 * A one- or two-character term matches thousands of times in an ordinary
 * document. The result is not a redaction, it is an unusable page, and the
 * reviewer cannot tell from the count whether the rule did what they meant.
 */
const MINIMUM_TERM = 3;

export function termDetector(terms: readonly TermRule[]): Detector {
  for (const term of terms) {
    if (term.text.trim().length < MINIMUM_TERM) {
      throw new ClassifiedError(
        'E_USAGE',
        `the term ${JSON.stringify(term.text)} is shorter than ${MINIMUM_TERM} characters; it would match inside ordinary words throughout the document`,
        { term: term.text },
      );
    }
  }

  return {
    id: 'operator-terms',
    version: '1.0.0',
    emits: [],
    // Alongside the manual marks, after every rule has had its say, so an
    // operator term can supersede a weaker automatic guess at the same span.
    stage: 3,
    detect(context: DetectionContext): readonly Finding[] {
      if (terms.length === 0) return [];

      const findings: Finding[] = [];
      for (const node of context.index.ofKind('text', 'metadata', 'annotation', 'attachment')) {
        const text = node.text;
        if (text === undefined || text.length === 0) continue;

        for (const term of terms) {
          const needle = term.text.trim();
          for (const start of occurrences(text, needle, term)) {
            findings.push(make(node, term, needle, start, start + needle.length, text));
          }
        }
      }
      return findings;
    },
  };
}

function make(
  node: ContentNode,
  term: TermRule,
  needle: string,
  start: number,
  end: number,
  text: string,
): Finding {
  const location: TextLocation = { kind: 'text', node: node.id, start, end };
  return {
    id: `f_${toBase32(sha256Text(`term ${node.id} ${start} ${needle}`), 16).toLowerCase()}`,
    ruleId: 'operator:term',
    type: term.type ?? 'manual.marked',
    location,
    // The text as it actually appears, not as it was typed: a case-insensitive
    // term must record what is being removed, or the manifest digests a value
    // that is not in the document.
    value: text.slice(start, end),
    confidence: Confidence.VERIFIED,
    evidence: [
      {
        signal: 'operator:term',
        note: `the operator asked for every occurrence of ${JSON.stringify(needle)} to be removed`,
        weight: Confidence.VERIFIED,
      },
    ],
  };
}

/**
 * Every occurrence of `needle` in `haystack`, by the term's own rules.
 *
 * Overlapping matches are impossible by construction -- the scan continues from
 * the end of each hit -- because two operations on the same characters is
 * exactly what the plan refuses.
 */
function occurrences(haystack: string, needle: string, term: TermRule): number[] {
  const out: number[] = [];
  const subject = term.matchCase === true ? haystack : haystack.toLowerCase();
  const target = term.matchCase === true ? needle : needle.toLowerCase();
  const whole = term.whole !== false;

  let from = 0;
  for (;;) {
    const index = subject.indexOf(target, from);
    if (index === -1) return out;
    const after = index + target.length;

    if (!whole || isWholeWord(haystack, index, after)) {
      out.push(index);
      from = after;
    } else {
      from = index + 1;
    }
  }
}

/**
 * Whether the span sits on word boundaries.
 *
 * A trailing apostrophe is forgiven, so a term matches its possessive:
 * redacting `Aegisfield` and leaving `Aegisfield's schedule` standing would
 * disclose the thing that was withheld one word later.
 */
function isWholeWord(text: string, start: number, end: number): boolean {
  const before = start === 0 ? ' ' : text[start - 1]!;
  const after = end >= text.length ? ' ' : text[end]!;
  return !/[\p{L}\p{N}_]/u.test(before) && !/[\p{L}\p{N}_]/u.test(after);
}
