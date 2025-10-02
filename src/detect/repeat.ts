/**
 * Repeat-occurrence detection.
 *
 * Pattern rules find a value where its evidence is: a name behind "Full Name:",
 * an address behind "Billing Address:". They do not find the same name in the
 * signature block, or the same email in the footer, because there is no label
 * there to match on.
 *
 * That is not a cosmetic gap. Redacting one occurrence of a name and leaving
 * another is a complete failure of the redaction -- the reader simply looks at
 * the second one. It is also exactly what the verifier catches, which is how
 * this detector came to exist: the pipeline refused to emit a document because
 * "Marcus Vance" was removed from the header and left in the signature.
 *
 * So once a value has been identified anywhere, every other occurrence of it in
 * the document is the same disclosure and is reported as one. This is the
 * cheapest form of coreference resolution there is, and it closes the most
 * common way a partial redaction happens.
 */

import { toBase32 } from '../internal/bytes.js';
import { sha256Text } from '../internal/hash.js';
import type { ContentNode, TextLocation } from '../model/document.js';
import { Confidence, type DetectionContext, type Detector, type EntityType, type Finding } from './types.js';

/**
 * Entity types whose values are worth chasing through the document.
 *
 * Structural risks and markings are excluded: they describe an arrangement or a
 * label rather than a value, and hunting for other copies of the string
 * "CaseTrack 7.2" would report the producer field as a finding in the body text.
 */
function isChaseable(type: EntityType): boolean {
  return !type.startsWith('risk.') && !type.startsWith('marking.');
}

/**
 * Minimum length of a value worth chasing.
 *
 * Below this a value is not distinctive enough for a second occurrence to mean
 * anything. A three-digit CVV of `123` appears inside half the numbers in a
 * financial document, and reporting each of them would be noise that buries the
 * real repeats.
 */
const MINIMUM_LENGTH = 5;

/**
 * Confidence a repeat is reported at.
 *
 * One step below the original. The value is certain -- it is a literal string
 * match against something already identified -- but the *type* is inherited
 * rather than established here, and the surrounding context was never checked.
 */
function repeatConfidence(original: number): number {
  return Math.min(original, Confidence.STRONG);
}

/**
 * Find every further occurrence of a value already identified elsewhere.
 *
 * Runs at stage 2, after the pattern and structural detectors, so it sees
 * everything they found.
 */
export function repeatValueDetector(): Detector {
  return {
    id: 'repeat-value',
    version: '1.0.0',
    emits: [],
    stage: 2,
    detect(context: DetectionContext): readonly Finding[] {
      const seeds = new Map<string, Finding>();
      const addSeed = (value: string, finding: Finding): void => {
        if (value.length < MINIMUM_LENGTH) return;
        // Keep the most confident finding for each distinct value, so the
        // repeat inherits the best available determination of what it is.
        const existing = seeds.get(value);
        if (existing === undefined || finding.confidence > existing.confidence) {
          seeds.set(value, finding);
        }
      };

      for (const finding of context.priorFindings) {
        if (!isChaseable(finding.type)) continue;
        const value = finding.value.trim();
        addSeed(value, finding);
        const normalized = finding.normalized?.trim();
        if (normalized !== undefined && normalized !== '' && normalized !== value) {
          addSeed(normalized, finding);
        }
        const digits = value.replace(/\D/g, '');
        if (
          digits.length >= 9 &&
          (finding.type.startsWith('financial.') || finding.type.startsWith('gov.'))
        ) {
          addSeed(digits, finding);
        }
        for (const part of nameComponents(finding)) addSeed(part, finding);
      }
      if (seeds.size === 0) return [];

      // Positions already claimed, so a repeat is never emitted on top of the
      // finding that seeded it.
      const claimed = new Map<string, Array<{ start: number; end: number }>>();
      for (const finding of context.priorFindings) {
        if (finding.location.kind !== 'text') continue;
        const bucket = claimed.get(finding.location.node) ?? [];
        bucket.push({ start: finding.location.start, end: finding.location.end });
        claimed.set(finding.location.node, bucket);
      }

      const findings: Finding[] = [];
      for (const node of context.index.ofKind('text', 'metadata', 'annotation', 'attachment')) {
        if (node.text === undefined || node.text.length === 0) continue;
        const taken = claimed.get(node.id) ?? [];

        for (const [value, seed] of seeds) {
          for (const start of occurrencesOf(node.text, value)) {
            const end = start + value.length;
            if (taken.some((span) => start < span.end && span.start < end)) continue;

            findings.push(makeRepeat(node, seed, value, start, end));
            // Record it so two seeds that share a substring cannot both claim
            // the same characters.
            taken.push({ start, end });
          }
        }
        claimed.set(node.id, taken);
      }
      return findings;
    },
  };
}

function makeRepeat(
  node: ContentNode,
  seed: Finding,
  value: string,
  start: number,
  end: number,
): Finding {
  const location: TextLocation = { kind: 'text', node: node.id, start, end };
  const confidence = repeatConfidence(seed.confidence);
  return {
    id: `f_${toBase32(sha256Text(`repeat ${node.id} ${start} ${value}`), 16).toLowerCase()}`,
    ruleId: 'repeat:value',
    type: seed.type,
    location,
    value,
    confidence,
    evidence: [
      {
        signal: 'repeat:identified-elsewhere',
        note: `the same value was identified as ${seed.type} elsewhere in this document; removing one occurrence and leaving this one would not redact it`,
        weight: confidence,
      },
    ],
    ...(seed.normalized !== undefined ? { normalized: seed.normalized } : {}),
  };
}

/**
 * The individual words of a personal name.
 *
 * Redacting "Chloe O'Connor" and leaving "Chloe's diagnosis" three lines later
 * has disclosed the patient. A surname or forename on its own is the same person
 * as the full name, and prose refers to people by one name far more often than
 * by both.
 *
 * Only names are broken up. Splitting an address or an account number into words
 * would chase fragments that mean nothing on their own and match everywhere --
 * a street name is not an identifier the way a surname is.
 */
function nameComponents(finding: Finding): string[] {
  if (finding.type !== 'person.name') return [];
  return finding.value
    .split(/[\s]+/)
    .map((word) => word.replace(/[^\p{L}\p{N}'\u2019-]/gu, ''))
    .filter((word) => word.length >= MINIMUM_LENGTH && /^\p{Lu}/u.test(word));
}

/**
 * Occurrences of `needle` in `haystack` that are not part of a longer word.
 *
 * Boundary-checked so redacting the surname "Vance" does not also match inside
 * "Vancouver", and case-insensitively because a signature block routinely
 * capitalises differently from the body.
 */
function occurrencesOf(haystack: string, needle: string): number[] {
  const out: number[] = [];
  const lowerHaystack = haystack.toLowerCase();
  const lowerNeedle = needle.toLowerCase();

  let from = 0;
  for (;;) {
    const index = lowerHaystack.indexOf(lowerNeedle, from);
    if (index === -1) return out;
    const before = index === 0 ? ' ' : haystack[index - 1]!;
    const afterIndex = index + needle.length;
    const after = afterIndex >= haystack.length ? ' ' : haystack[afterIndex]!;
    // A trailing apostrophe is a possessive, not a longer word: "Chloe's" is
    // still Chloe. A leading one would be part of a name like O'Connor, so only
    // the trailing side is forgiven.
    const boundaryBefore = !/[\p{L}\p{N}'\u2019]/u.test(before);
    const boundaryAfter = !/[\p{L}\p{N}]/u.test(after);
    if (boundaryBefore && boundaryAfter) out.push(index);
    from = index + 1;
  }
}
