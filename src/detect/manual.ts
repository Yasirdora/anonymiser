/**
 * Operator-supplied findings.
 *
 * No detector will ever be complete. Names are the clearest case -- there is no
 * pattern that separates a person from a place -- but every category has a tail
 * of values that no rule reaches, and a document is never safe to release just
 * because the rules went quiet.
 *
 * So the operator has to be able to say "redact that", and what they mark has
 * to travel through the same machinery as everything else: classified by the
 * same policy, verified by the same read-back, recorded in the same manifest
 * with the same weight. A tool where hand-marked redactions take a side path is
 * a tool where the audit record is incomplete precisely for the items a human
 * thought were important enough to catch by hand.
 *
 * Implementing it as a {@link Detector} rather than as a special case in the
 * pipeline is what makes that automatic. The same mechanism carries a
 * named-entity model's output, or a reviewer's decisions replayed from a
 * previous session.
 */

import { toBase32 } from '../internal/bytes.js';
import { sha256Text } from '../internal/hash.js';
import { ClassifiedError } from '../errors.js';
import { locationKey, type Location } from '../model/document.js';
import { Confidence, type DetectionContext, type Detector, type EntityType, type Finding } from './types.js';

/** A redaction an operator marked by hand. */
export interface ManualMark {
  readonly location: Location;
  /**
   * What the operator says this is.
   *
   * Drives classification and the pseudonym label, so marking something as
   * `person.name` gives it a PERSON token and the same policy treatment as a
   * detected name. Defaults to `manual.marked`, which policies treat as
   * sensitive without claiming to know what kind.
   */
  readonly type?: EntityType;
  /** Optional note from the reviewer, carried into the manifest. */
  readonly note?: string;
}

/**
 * Build a detector from hand-marked selections.
 *
 * Runs at stage 3, after everything else, so a mark that lands on something the
 * rules already found is dropped as a duplicate rather than producing a second
 * overlapping operation.
 */
export function manualDetector(marks: readonly ManualMark[]): Detector {
  return {
    id: 'manual',
    version: '1.0.0',
    emits: ['manual.marked'],
    stage: 3,
    detect(context: DetectionContext): readonly Finding[] {
      const claimed = new Set(
        context.priorFindings
          .filter((f) => f.location.kind === 'text')
          .map((f) => `${f.location.node}:${(f.location as { start: number }).start}:${(f.location as { end: number }).end}`),
      );

      const findings: Finding[] = [];
      for (const mark of marks) {
        const node = context.index.get(mark.location.node);
        if (node === undefined) {
          throw new ClassifiedError(
            'E_DANGLING_TARGET',
            `a hand-marked redaction targets node ${JSON.stringify(mark.location.node)}, which is not in this document`,
            { location: locationKey(mark.location) },
          );
        }

        const value = context.index.textAt(mark.location) ?? '';
        if (mark.location.kind === 'text') {
          const { start, end } = mark.location;
          if (claimed.has(`${mark.location.node}:${start}:${end}`)) continue;
          if (value === '') continue;
        }

        findings.push({
          id: manualFindingId(mark.location, value),
          ruleId: 'manual:marked',
          type: mark.type ?? 'manual.marked',
          location: mark.location,
          value,
          // Certainty, because a person looked at it and decided. The engine has
          // no grounds to second-guess that, and a lower score would let a
          // confidence threshold silently discard a deliberate instruction.
          confidence: Confidence.VERIFIED,
          evidence: [
            {
              signal: 'manual:operator',
              note: mark.note ?? 'marked for removal by the operator reviewing this document',
              weight: Confidence.VERIFIED,
            },
          ],
        });
      }
      return findings;
    },
  };
}

/** Content-derived id, so a mark survives a re-scan of the same document. */
export function manualFindingId(location: Location, value: string): string {
  return `m_${toBase32(sha256Text(`${locationKey(location)} ${value}`), 16).toLowerCase()}`;
}
