/**
 * The detection engine: runs detectors in stage order and resolves the overlaps
 * they inevitably produce.
 *
 * Overlap resolution is not cosmetic tidying. An unresolved set of findings
 * produces double-counted classification decisions, duplicate manifest entries,
 * and pseudonym tokens that disagree about where one entity ends and the next
 * begins.
 */

import { ClassifiedError } from '../errors.js';
import { DocumentIndex, type DocumentModel } from '../model/document.js';
import type { DetectionContext, Detector, Finding } from './types.js';

/** Options for a detection run. */
export interface DetectionOptions {
  /** Locale hints passed to detectors, e.g. `['en-GB']`. */
  readonly locales?: readonly string[];
  /** Findings below this confidence are dropped from `findings`. Defaults to 0. */
  readonly minConfidence?: number;
  /**
   * Entity types to ignore entirely. Applied after detection so that a
   * suppressed type can still corroborate another detector's finding.
   */
  readonly ignoreTypes?: readonly string[];
}

/** The outcome of a detection run. */
export interface DetectionResult {
  /** Every finding, including those superseded during resolution. */
  readonly all: readonly Finding[];
  /**
   * Findings after overlap resolution. This is the set to classify and redact;
   * `all` exists for audit and for explaining a decision to a reviewer.
   */
  readonly findings: readonly Finding[];
  /** Detector ids and versions that produced this result, for the manifest. */
  readonly detectors: readonly { readonly id: string; readonly version: string }[];
  /** Count of findings per entity type, after resolution. */
  readonly countsByType: Readonly<Record<string, number>>;
}

/**
 * Run a set of detectors over a document.
 *
 * Detectors are grouped by stage and each stage sees the findings of all
 * earlier stages. Within a stage the order is the caller's, and results are
 * sorted before being handed on, so the output does not depend on it.
 */
export function detect(
  model: DocumentModel,
  detectors: readonly Detector[],
  options: DetectionOptions = {},
): DetectionResult {
  const index = new DocumentIndex(model);
  const locales = options.locales ?? [];
  const minConfidence = options.minConfidence ?? 0;
  const ignored = new Set(options.ignoreTypes ?? []);

  const seenIds = new Set<string>();
  for (const detector of detectors) {
    if (seenIds.has(detector.id)) {
      throw new ClassifiedError('E_USAGE', `duplicate detector id ${JSON.stringify(detector.id)}`, {
        detectorId: detector.id,
      });
    }
    seenIds.add(detector.id);
  }

  const stages = [...new Set(detectors.map((d) => d.stage ?? 0))].sort((a, b) => a - b);
  const accumulated: Finding[] = [];

  for (const stage of stages) {
    const context: DetectionContext = {
      model,
      index,
      locales,
      priorFindings: [...accumulated],
    };
    for (const detector of detectors) {
      if ((detector.stage ?? 0) !== stage) continue;
      accumulated.push(...detector.detect(context));
    }
  }

  const all = sortFindings(accumulated);
  const filtered = all.filter((f) => f.confidence >= minConfidence && !ignored.has(f.type));
  const findings = resolveOverlaps(filtered);

  const countsByType: Record<string, number> = {};
  for (const finding of findings) {
    countsByType[finding.type] = (countsByType[finding.type] ?? 0) + 1;
  }

  return {
    all,
    findings,
    detectors: detectors.map((d) => ({ id: d.id, version: d.version })),
    countsByType,
  };
}

/**
 * Total order over findings.
 *
 * Deterministic output is a hard requirement -- the provenance manifest hashes
 * this list -- so the comparison falls through to the finding id, which is
 * itself content-derived and therefore stable.
 */
function sortFindings(findings: readonly Finding[]): Finding[] {
  return [...findings].sort((a, b) => {
    const nodeCmp = a.location.node.localeCompare(b.location.node);
    if (nodeCmp !== 0) return nodeCmp;
    const aStart = a.location.kind === 'text' ? a.location.start : -1;
    const bStart = b.location.kind === 'text' ? b.location.start : -1;
    if (aStart !== bStart) return aStart - bStart;
    if (a.confidence !== b.confidence) return b.confidence - a.confidence;
    return a.id.localeCompare(b.id);
  });
}

/**
 * Collapse findings that sit inside other findings.
 *
 * Two rules routinely describe the same text at different widths: a role label
 * catches "Colonel Jane Whitfield" while an honorific rule catches "Jane
 * Whitfield" inside it. Both are correct, and a redaction cannot act on both --
 * overlapping edits to one string have no well-defined result.
 *
 * On containment the wider span wins, always, even when the narrower one scored
 * higher. An oversized redaction is a cosmetic problem; an undersized one is a
 * disclosure, and dropping the outer span here would leave "Colonel" standing
 * beside a redacted name. The survivor takes the higher of the two confidences,
 * because certainty that a span *contains* something sensitive is certainty
 * about the span.
 *
 * Partial overlaps are kept. Two findings that merely abut are usually two real
 * entities -- an email address followed by a phone number -- and discarding
 * either would leave part of one in the output. The plan builder merges those
 * into a single covering operation instead.
 */
export function resolveOverlaps(findings: readonly Finding[]): Finding[] {
  const byNode = new Map<string, Finding[]>();
  const nonText: Finding[] = [];

  for (const finding of findings) {
    if (finding.location.kind !== 'text') {
      nonText.push(finding);
      continue;
    }
    const bucket = byNode.get(finding.location.node);
    if (bucket) bucket.push(finding);
    else byNode.set(finding.location.node, [finding]);
  }

  const kept: Finding[] = [];
  for (const bucket of byNode.values()) {
    // Widest first, so a subsuming finding is always seen before what it
    // subsumes; confidence and id break ties so the result is deterministic.
    const ordered = [...bucket].sort((a, b) => {
      const aSpan = a.location as { start: number; end: number };
      const bSpan = b.location as { start: number; end: number };
      const aLen = aSpan.end - aSpan.start;
      const bLen = bSpan.end - bSpan.start;
      if (aLen !== bLen) return bLen - aLen;
      if (a.confidence !== b.confidence) return b.confidence - a.confidence;
      return a.id.localeCompare(b.id);
    });

    const survivors: Finding[] = [];
    for (const candidate of ordered) {
      const span = candidate.location as { start: number; end: number };
      const containerIndex = survivors.findIndex((winner) => {
        const w = winner.location as { start: number; end: number };
        return w.start <= span.start && w.end >= span.end;
      });

      if (containerIndex === -1) {
        survivors.push(candidate);
        continue;
      }

      const container = survivors[containerIndex]!;
      if (candidate.confidence <= container.confidence) continue;

      // The narrower finding was the more confident one. Keep the wider span
      // but carry its certainty and its reasoning across, so the evidence still
      // explains why this text is being removed.
      survivors[containerIndex] = {
        ...container,
        confidence: candidate.confidence,
        evidence: [
          ...container.evidence,
          {
            signal: `subsumed:${candidate.ruleId}`,
            note: `contains a ${candidate.type} matched at higher confidence, so the wider span is removed as one unit`,
            weight: candidate.confidence - container.confidence,
          },
        ],
      };
    }
    kept.push(...survivors);
  }

  return sortFindings([...kept, ...nonText]);
}
