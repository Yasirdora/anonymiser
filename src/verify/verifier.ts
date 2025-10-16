/**
 * Verification: proving the redaction actually happened.
 *
 * This stage has no counterpart in any comparable library, and it is the reason
 * the engine exists. Applying a redaction and returning is not enough, because
 * the failure mode is invisible: a black rectangle over live text and a genuine
 * deletion render identically, and the person doing the work gets no signal
 * either way. That is precisely how the Manafort filings, the DOJ release, and
 * a long line of FOIA disclosures leaked -- not through carelessness about
 * whether to redact, but through the absence of any feedback about whether the
 * redaction worked.
 *
 * So the output is read back and searched for everything the plan promised to
 * remove. If any of it is still reachable, the pipeline refuses to hand over
 * the file.
 */

import type { LeakChannel, VerificationLeak } from '../errors.js';
import { DocumentIndex, type ContentNode, type DocumentModel } from '../model/document.js';
import type { RedactionPlan } from '../redact/plan.js';
import { retainKey } from '../redact/plan.js';
import { strategySpec } from '../redact/strategies.js';

/** Outcome of checking one output against its plan. */
export interface VerificationReport {
  /** True when nothing the plan removed is recoverable from the output. */
  readonly passed: boolean;
  /** Content that survived, with the channel it survived through. */
  readonly leaks: readonly VerificationLeak[];
  /** Operations checked. */
  readonly operationsChecked: number;
  /**
   * Operations that could not be checked, with the reason.
   *
   * An unverifiable operation is not a pass. It is reported separately so the
   * distinction between "checked and clean" and "could not check" survives into
   * the manifest, where it belongs.
   */
  readonly unverifiable: readonly { readonly operationId: string; readonly reason: string }[];
  /** True when the adapter declared it cannot faithfully read back its output. */
  readonly degraded: boolean;
}

/** Options for a verification pass. */
export interface VerifyOptions {
  /**
   * Values shorter than this are matched on word boundaries rather than as
   * substrings. Defaults to 4.
   *
   * Without it, redacting the number `42` reports a leak in every page number
   * and every year in the document, and a check that cries wolf gets disabled.
   */
  readonly shortValueThreshold?: number;
  /** Set when the adapter cannot faithfully reparse its own output. */
  readonly degraded?: boolean;
}

/**
 * Check an output against the plan that produced it.
 *
 * Deliberately paranoid about *where* it looks. Searching the primary text
 * layer alone would miss every real-world leak: the value that survives in the
 * document's Author field, in a tracked change, in a comment, in an embedded
 * spreadsheet. Each of those is a distinct channel with its own history of
 * failures, and all of them are searched.
 */
export function verify(
  plan: RedactionPlan,
  output: DocumentModel,
  options: VerifyOptions = {},
): VerificationReport {
  const index = new DocumentIndex(output);
  const threshold = options.shortValueThreshold ?? 4;
  const leaks: VerificationLeak[] = [];
  const unverifiable: { operationId: string; reason: string }[] = [];

  const haystack = buildHaystack(index);
  let checked = 0;

  for (const operation of plan.operations) {
    const spec = strategySpec(operation.strategy);

    // A strategy that never claimed to destroy anything cannot be verified as
    // having done so. Recording it as unverifiable rather than passing is the
    // whole point: an output containing one of these is not defensible, and the
    // report must say so rather than staying silent.
    if (spec.recoverability === 'recoverable') {
      unverifiable.push({
        operationId: operation.id,
        reason: `the "${operation.strategy}" strategy leaves a recoverable encoding of the original, so its removal cannot be confirmed`,
      });
      continue;
    }

    if (operation.location.kind === 'node') {
      checked++;
      const survivor = index.get(operation.location.node);
      if (survivor !== undefined && operation.strategy === 'remove') {
        leaks.push({
          operationId: operation.id,
          foundIn: describeNode(survivor),
          channel: channelForNode(survivor),
          preview: preview(survivor.text ?? survivor.id),
        });
        continue;
      }
    }

    const original = operation.originalValue;
    if (original === undefined || original.trim().length === 0) {
      unverifiable.push({
        operationId: operation.id,
        reason: 'the plan did not record the original value, so there is nothing to search for',
      });
      continue;
    }

    // Masking retains part of the original by design; only the destroyed
    // remainder is checkable, and it is not separable from the retained part
    // once written. Report it honestly instead of claiming a clean pass.
    if (spec.recoverability === 'by-design') {
      unverifiable.push({
        operationId: operation.id,
        reason: 'masking retains part of the original by design; the retained portion is expected in the output',
      });
      continue;
    }

    checked++;
    // How many times this value is *expected* to survive, because the reviewer
    // said to keep that many occurrences of it. Anything beyond that is a leak;
    // anything at or below it is the document doing as it was told.
    const allowed = plan.retainedValues[retainKey(original)] ?? 0;
    const hit = findValue(haystack, original, threshold, allowed);
    if (hit !== undefined) {
      leaks.push({
        operationId: operation.id,
        foundIn: hit.where,
        channel: hit.channel,
        preview: preview(original),
      });
    }
  }

  // A cosmetic overlay introduced by the output itself is a leak even when no
  // operation is responsible for it: the document now looks redacted somewhere
  // it is not.
  leaks.push(...detectOverlayLeaks(index));

  return {
    passed: leaks.length === 0,
    leaks,
    operationsChecked: checked,
    unverifiable,
    degraded: options.degraded === true,
  };
}

/** Every text-bearing location in the output, with its leak channel. */
interface HaystackEntry {
  readonly text: string;
  readonly normalized: string;
  readonly where: string;
  readonly channel: LeakChannel;
}

function buildHaystack(index: DocumentIndex): readonly HaystackEntry[] {
  const entries: HaystackEntry[] = [];
  for (const node of index.model.nodes) {
    if (node.text === undefined || node.text.length === 0) continue;
    entries.push({
      text: node.text,
      normalized: normalize(node.text),
      where: describeNode(node),
      channel: channelForNode(node),
    });
  }
  return entries;
}

/**
 * The first occurrence of a value beyond the number expected to remain.
 *
 * `allowed` is how many copies the reviewer deliberately kept. Occurrences are
 * counted rather than merely detected, so the check keeps its teeth: keeping one
 * of three copies means exactly one may survive, and a removal that silently did
 * nothing still produces one too many and is still caught.
 */
function findValue(
  haystack: readonly HaystackEntry[],
  original: string,
  threshold: number,
  allowed = 0,
): { where: string; channel: LeakChannel } | undefined {
  const needle = normalize(original);
  if (needle.length === 0) return undefined;

  // Short values match on word boundaries. A long one is distinctive enough
  // that a substring hit is real, and matching loosely there is what catches a
  // value that survived with different surrounding punctuation.
  const useBoundaries = original.trim().length < threshold;

  let seen = 0;
  for (const entry of haystack) {
    const count = useBoundaries
      ? countWord(entry.normalized, needle)
      : countSubstring(entry.normalized, needle);
    if (count === 0) continue;
    seen += count;
    if (seen > allowed) return entry;
  }
  return undefined;
}

/** Occurrences of `needle` in `haystack`, non-overlapping. */
function countSubstring(haystack: string, needle: string): number {
  let count = 0;
  let from = 0;
  for (;;) {
    const at = haystack.indexOf(needle, from);
    if (at === -1) return count;
    count++;
    from = at + needle.length;
  }
}

function countWord(haystack: string, needle: string): number {
  let count = 0;
  let from = 0;
  for (;;) {
    const index = haystack.indexOf(needle, from);
    if (index === -1) return count;
    const before = index === 0 ? ' ' : haystack[index - 1]!;
    const afterIndex = index + needle.length;
    const after = afterIndex >= haystack.length ? ' ' : haystack[afterIndex]!;
    if (!/[a-z0-9]/i.test(before) && !/[a-z0-9]/i.test(after)) {
      count++;
      from = afterIndex;
    } else {
      from = index + 1;
    }
  }
}

/**
 * Fold away the differences that hide a leak from a naive search.
 *
 * A value re-emitted with different spacing, different hyphen characters, or a
 * different case is the same disclosure. Normalising both sides means
 * `555-01-9999` in the plan still matches `555 01 9999` in the output.
 */
function normalize(text: string): string {
  return text
    .toLowerCase()
    // Typographic dashes and the minus sign all fold to a plain hyphen.
    .replace(/[\u2010-\u2015\u2212]/g, '-')
    // BOM and bidi/zero-width controls are how a value hides next to itself.
    .replace(/[\u200b-\u200f\u202a-\u202e\ufeff]/g, '')
    // Non-breaking, thin, and zero-width spaces fold to an ordinary space.
    .replace(/[\u00a0\u2000-\u200a\u202f\u205f\u3000]/g, ' ')
    // Hyphens and underscores fold to spaces too, so a value re-emitted with
    // different grouping still matches: "555-01-9999" removed from the body and
    // "555 01 9999" surviving in a comment are one disclosure, not two values.
    .replace(/[-_]/g, ' ')
    .replace(/\s+/g, ' ')
    .trim();
}

function channelForNode(node: ContentNode): LeakChannel {
  switch (node.kind) {
    case 'metadata':
      return 'metadata';
    case 'annotation':
      return 'annotation';
    case 'attachment':
      return 'attachment';
    default:
      return node.attrs?.['revision'] !== undefined ? 'revision-history' : 'text-layer';
  }
}

function describeNode(node: ContentNode): string {
  const page = node.page !== undefined ? ` page ${node.page + 1}` : '';
  const key = node.attrs?.['key'];
  const label = key !== undefined ? ` (${key})` : '';
  return `${node.kind} node ${node.id}${label}${page}`;
}

/**
 * Find opaque shapes still sitting over extractable text in the output.
 *
 * This catches the case where the adapter drew the redaction box but failed to
 * remove the underlying content -- the exact failure the whole pipeline is
 * built to prevent, checked one last time against the bytes that will actually
 * be handed to the user.
 */
function detectOverlayLeaks(index: DocumentIndex): VerificationLeak[] {
  const leaks: VerificationLeak[] = [];
  const shapes = [...index.ofKind('vector')].filter(
    (n) => n.attrs?.['filled'] === 'true' && n.bbox !== undefined,
  );
  if (shapes.length === 0) return leaks;

  for (const text of index.ofKind('text')) {
    if (text.bbox === undefined || text.text === undefined || text.text.trim() === '') continue;
    for (const shape of shapes) {
      if (shape.page !== text.page) continue;
      const a = shape.bbox!;
      const b = text.bbox;
      const intersects =
        a.x < b.x + b.width && b.x < a.x + a.width && a.y < b.y + b.height && b.y < a.y + a.height;
      if (!intersects) continue;
      leaks.push({
        operationId: `overlay:${shape.id}`,
        foundIn: describeNode(text),
        channel: 'underlying-raster',
        preview: preview(text.text),
      });
      break;
    }
  }
  return leaks;
}

/**
 * A loggable fragment of a leaked value.
 *
 * Enough to identify which finding leaked, not enough to disclose it: a leak
 * report ends up in logs and tickets, and reproducing the full value there
 * would turn the safety check into a second copy of the problem.
 */
function preview(value: string): string {
  const trimmed = value.trim();
  if (trimmed.length === 0) return '';
  if (trimmed.length === 1) return '*';
  // Identifiers short enough to be an SSN or a card fragment keep one character
  // at each end. The previous 3+3 form put six digits of a nine-digit SSN into
  // the log that exists to record that it leaked.
  const keep = trimmed.length <= 12 ? 1 : 1;
  const stars = Math.min(8, Math.max(1, trimmed.length - keep * 2));
  return `${trimmed.slice(0, keep)}${'*'.repeat(stars)}${trimmed.slice(-keep)}`;
}

/** Merge reports from several passes, as when a document is redacted in stages. */
export function mergeReports(reports: readonly VerificationReport[]): VerificationReport {
  return {
    passed: reports.every((r) => r.passed),
    leaks: reports.flatMap((r) => r.leaks),
    operationsChecked: reports.reduce((sum, r) => sum + r.operationsChecked, 0),
    unverifiable: reports.flatMap((r) => r.unverifiable),
    degraded: reports.some((r) => r.degraded),
  };
}
