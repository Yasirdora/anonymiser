/**
 * Redaction plans.
 *
 * A plan is a complete, inspectable description of what will be removed, how,
 * and on what authority -- produced before anything is written and reviewable
 * on its own. Applying it is a separate, mechanical step.
 *
 * Splitting the decision from the edit is what makes review possible. A
 * reviewer approves a plan, not a diff of a binary file, and the same plan
 * applied to the same input always produces the same output, so an approval
 * means something later.
 */

import { toBase32 } from '../internal/bytes.js';
import { sha256Text } from '../internal/hash.js';
import { mergeIntervals } from '../internal/interval.js';
import { ClassifiedError } from '../errors.js';
import type { ClassificationResult } from '../classify/engine.js';
import type { CompiledPolicy } from '../classify/lattice.js';
import type { EntityType, Finding } from '../detect/types.js';
import { DocumentIndex, locationKey, type DocumentModel, type Location } from '../model/document.js';
import { maskValue, PseudonymGenerator } from './pseudonym.js';
import {
  assertStrategyPermitted,
  strategySupportsLocation,
  type RedactionStrategy,
  type SafetyOptions,
} from './strategies.js';

/** The authority under which content is withheld. */
export interface RedactionReason {
  /** Stable code, e.g. `foia.b6`, `gdpr.art9`, `policy.internal-3.2`. */
  readonly code: string;
  /** Human-readable citation. */
  readonly authority: string;
  /** Optional case-specific note from the reviewer. */
  readonly note?: string;
}

/**
 * FOIA exemptions, as reason codes.
 *
 * Included because US federal releases must cite the exemption beside each
 * withholding, and a tool that makes people look that up in a separate document
 * will be used to produce releases that cite the wrong one.
 */
export const FOIA_EXEMPTIONS: Readonly<Record<string, RedactionReason>> = {
  b1: { code: 'foia.b1', authority: '5 USC 552(b)(1) - classified national defense or foreign policy information' },
  b2: { code: 'foia.b2', authority: '5 USC 552(b)(2) - internal personnel rules and practices' },
  b3: { code: 'foia.b3', authority: '5 USC 552(b)(3) - specifically exempted by other statute' },
  b4: { code: 'foia.b4', authority: '5 USC 552(b)(4) - trade secrets and confidential commercial information' },
  b5: { code: 'foia.b5', authority: '5 USC 552(b)(5) - privileged inter-agency or intra-agency memoranda' },
  b6: { code: 'foia.b6', authority: '5 USC 552(b)(6) - personnel and medical files; clearly unwarranted invasion of personal privacy' },
  b7a: { code: 'foia.b7a', authority: '5 USC 552(b)(7)(A) - law enforcement records; interference with proceedings' },
  b7c: { code: 'foia.b7c', authority: '5 USC 552(b)(7)(C) - law enforcement records; unwarranted invasion of personal privacy' },
  b7d: { code: 'foia.b7d', authority: '5 USC 552(b)(7)(D) - law enforcement records; confidential source' },
  b7e: { code: 'foia.b7e', authority: '5 USC 552(b)(7)(E) - law enforcement techniques and procedures' },
  b7f: { code: 'foia.b7f', authority: '5 USC 552(b)(7)(F) - law enforcement records; endangerment of an individual' },
  b8: { code: 'foia.b8', authority: '5 USC 552(b)(8) - financial institution examination records' },
  b9: { code: 'foia.b9', authority: '5 USC 552(b)(9) - geological and geophysical information concerning wells' },
};

/** One edit. */
export interface RedactionOperation {
  readonly id: string;
  readonly location: Location;
  readonly strategy: RedactionStrategy;
  /**
   * Text substituted for the original, resolved at plan time.
   *
   * Resolving here rather than during application keeps `apply` a pure
   * transformation, and means a reviewer sees the exact replacement text before
   * approving rather than a promise about how it will be generated.
   */
  readonly replacement?: string;
  /** Fill colour for `blackout`, as RGBA in `[0, 255]`. Defaults to opaque black. */
  readonly fill?: readonly [number, number, number, number];
  /** Mosaic block size in pixels for `pixelate`. Larger destroys more. */
  readonly blockSize?: number;
  /**
   * Set only on an operation whose caller has accepted that it is reversible.
   *
   * Per operation rather than per document on purpose. A photograph may carry
   * three blackouts and one mosaic over a face; a document-level flag would
   * describe all four as weak, and this way the manifest names the one that
   * actually is. Without it an adapter refuses a recoverable strategy outright,
   * so the acknowledgement cannot be skipped by building operations by hand.
   */
  readonly acknowledgedRecoverable?: true;
  readonly reason: RedactionReason;
  /** Findings that motivated this operation. */
  readonly findingIds: readonly string[];
  /**
   * The original content, retained in the plan for verification.
   *
   * A plan therefore contains the sensitive values and must be handled like the
   * source document. It is not part of the output and is excluded from the
   * manifest, which stores digests instead.
   */
  readonly originalValue?: string;
}

/** Identifies the engine build that produced an artifact. */
export interface EngineIdentity {
  readonly name: string;
  readonly version: string;
}

/** A complete, reviewable redaction plan. */
export interface RedactionPlan {
  readonly id: string;
  readonly documentId: string;
  /** Digest of the source this plan was built against. */
  readonly sourceDigest: string;
  readonly operations: readonly RedactionOperation[];
  readonly policyId: string;
  readonly policyVersion: string;
  readonly engine: EngineIdentity;
  /** True when the plan contains a strategy whose output can be reversed. */
  readonly containsRecoverableStrategies: boolean;
  /**
   * Values the caller deliberately left in place, and how many times.
   *
   * Verification searches the output for everything the plan removed, which is
   * the whole point of it -- but a value can appear more than once, and a
   * reviewer is entitled to remove one occurrence and keep another. Without
   * this the read-back found the kept copy, blamed it on the operation that
   * removed the other one, and refused to release a document that was exactly
   * what the reviewer asked for.
   *
   * Counts rather than a set, so the check stays a real one: the value is
   * expected in the output *this many times* and no more. A removal that
   * silently failed still shows up as one occurrence too many.
   */
  readonly retainedValues: Readonly<Record<string, number>>;
}

/** How the plan builder chooses strategies. */
export interface PlanOptions {
  /** Strategy for findings with no more specific rule. Defaults to `replace`. */
  readonly defaultStrategy?: RedactionStrategy;
  /** Strategy overrides by entity type. Prefix patterns like `gov.*` are honoured. */
  readonly strategyByType?: Readonly<Record<string, RedactionStrategy>>;
  /**
   * Findings below this confidence are left for human review rather than
   * redacted. Defaults to 0.5.
   *
   * The default was 0.7, and that was wrong. Against a real breach complaint it
   * silently left a billing address, a postcode, and a labelled account number
   * in the output -- every one of them detected, every one of them scored just
   * under the line. The engine's own premise settles the trade: an over-redacted
   * release is inconvenient, an under-redacted one is a disclosure. Callers who
   * genuinely need the opposite balance can raise it.
   */
  readonly minConfidence?: number;
  /** Required when any strategy resolves to `pseudonymize`. */
  readonly pseudonyms?: PseudonymGenerator;
  /** Replacement text for the `replace` strategy. Defaults to `[REDACTED]`. */
  readonly replacementText?: string | ((finding: Finding) => string);
  /** Characters retained by the `mask` strategy. Defaults to four, from the end. */
  readonly mask?: { readonly keep: number; readonly from?: 'start' | 'end' };
  /**
   * Findings a reviewer has decided to keep.
   *
   * Human review is a first-class step, not an afterthought: an operator looking
   * at a marked-up document will always find something the rules flagged that
   * must stay -- the sender's own name on a letter they are releasing, the date
   * the whole document is about. Excluding by finding id keeps that decision
   * durable, because finding ids are content-derived and survive a re-scan.
   */
  readonly excludeFindings?: readonly string[];
  readonly safety?: SafetyOptions;
  /**
   * Maps a finding to its withholding authority.
   *
   * Returning `undefined` means "no opinion for this one", and the default
   * applies. A reviewer cites an exemption for some withholdings and not
   * others, and forcing a total function would make the caller reinvent the
   * fallback logic that already lives here.
   */
  readonly reasonFor?: (finding: Finding) => RedactionReason | undefined;
  /** Fallback reason when `reasonFor` is not supplied. */
  readonly defaultReason?: RedactionReason;
  readonly engine?: EngineIdentity;
}

const DEFAULT_ENGINE: EngineIdentity = { name: '@anonymiser/core', version: '0.1.0' };

const DEFAULT_REASON: RedactionReason = {
  code: 'policy.sensitive-content',
  authority: 'Content matched a rule in the active classification policy',
};

/**
 * The authority for a hand-marked removal.
 *
 * A reviewer's decision is its own basis and has to read that way in the record.
 * Filing it under "matched a rule" would misattribute the judgement and hide the
 * fact that a person, not the engine, decided this had to go.
 */
const OPERATOR_REASON: RedactionReason = {
  code: 'operator.marked',
  authority: 'Marked for removal by the operator reviewing this document',
};

function defaultReasonFor(finding: Finding, fallback: RedactionReason): RedactionReason {
  return finding.ruleId.startsWith('manual:') ? OPERATOR_REASON : fallback;
}

/**
 * Build a plan from a classification result.
 *
 * Only findings the classifier actually acted on become operations. A finding
 * that no rule matched is reported to the caller but not redacted: silently
 * removing content no policy called for is how a release becomes unusable, and
 * the engine should not make that choice on the operator's behalf.
 */
export function planRedactions(
  model: DocumentModel,
  classification: ClassificationResult,
  policy: CompiledPolicy,
  options: PlanOptions = {},
): RedactionPlan {
  const index = new DocumentIndex(model);
  const minConfidence = options.minConfidence ?? 0.5;
  const engine = options.engine ?? DEFAULT_ENGINE;

  const operations: RedactionOperation[] = [];
  const claimed = new Set<string>();
  let containsRecoverable = false;

  const excluded = new Set(options.excludeFindings ?? []);
  const retainedValues: Record<string, number> = {};

  for (const portion of classification.portions) {
    for (const finding of portion.findings) {
      if (finding.confidence < minConfidence) continue;
      if (excluded.has(finding.id)) {
        // Recorded before it is dropped: this is the occurrence the reviewer
        // said to leave, and the verifier has to know to expect it.
        const key = retainKey(finding.value);
        if (key !== '') retainedValues[key] = (retainedValues[key] ?? 0) + 1;
        continue;
      }

      // Markings are the document describing itself. Removing them would strip
      // the banner the engine is about to check against.
      if (finding.type === 'marking.banner' || finding.type === 'marking.portion') continue;

      const key = locationKey(finding.location);
      if (claimed.has(key)) continue;
      claimed.add(key);

      const strategy = chooseStrategy(finding, portion.assertion.markings, policy, options);
      const kind = finding.location.kind;
      if (!strategySupportsLocation(strategy, kind)) {
        throw new ClassifiedError(
          'E_UNSUPPORTED',
          `strategy "${strategy}" cannot be applied to a ${kind} location`,
          { strategy, locationKind: kind, findingId: finding.id },
        );
      }
      assertStrategyPermitted(strategy, options.safety);
      if (strategy === 'blur' || strategy === 'pixelate') containsRecoverable = true;

      operations.push({
        id: operationId(finding.id, strategy),
        location: finding.location,
        strategy,
        ...resolveReplacement(finding, strategy, options),
        reason:
          options.reasonFor?.(finding) ??
          defaultReasonFor(finding, options.defaultReason ?? DEFAULT_REASON),
        findingIds: [finding.id],
        ...(index.textAt(finding.location) !== undefined
          ? { originalValue: index.textAt(finding.location)! }
          : { originalValue: finding.value }),
      });
    }
  }

  const merged = mergeOverlappingOperations(index, operations);
  merged.sort((a, b) => locationKey(a.location).localeCompare(locationKey(b.location)));

  return {
    id: planId(model.sourceDigest, merged),
    documentId: model.id,
    sourceDigest: model.sourceDigest,
    operations: merged,
    policyId: policy.policy.id,
    policyVersion: policy.policy.version,
    engine,
    containsRecoverableStrategies: containsRecoverable,
    retainedValues,
  };
}

/**
 * The form a retained value is counted under.
 *
 * Must fold exactly the way the verifier's own comparison folds, or a value
 * kept as `555-01-9999` would not be recognised in an output that re-emitted it
 * as `555 01 9999`. Kept deliberately simple and shared by both sides.
 */
export function retainKey(value: string): string {
  return value
    .toLowerCase()
    .replace(/[\u2010-\u2015\u2212]/g, '-')
    .replace(/[\u00a0\u2000-\u200b\u202f\u205f\u3000]/g, ' ')
    .replace(/[-_]/g, ' ')
    .replace(/\s+/g, ' ')
    .trim();
}

/**
 * Fuse operations whose spans overlap into single covering operations.
 *
 * Overlap resolution during detection collapses containment but deliberately
 * keeps partial overlaps, because two findings that share an edge are usually
 * two real entities. A redaction cannot act on both: applying overlapping edits
 * to one string has no well-defined result, and an adapter that guessed would
 * shift every later span and leave the tails of values exposed.
 *
 * So the plan fuses them here, before anything is written. The merged operation
 * covers the union of the spans and uses `replace`, because a span spanning two
 * entities is not one entity -- a pseudonym for it would assert an identity
 * that does not exist. It inherits every contributing finding and reason, so
 * the manifest still records why each part of it was withheld.
 */
function mergeOverlappingOperations(
  index: DocumentIndex,
  operations: readonly RedactionOperation[],
): RedactionOperation[] {
  const out: RedactionOperation[] = [];
  const byNode = new Map<string, RedactionOperation[]>();

  for (const operation of operations) {
    if (operation.location.kind !== 'text') {
      out.push(operation);
      continue;
    }
    const bucket = byNode.get(operation.location.node);
    if (bucket) bucket.push(operation);
    else byNode.set(operation.location.node, [operation]);
  }

  for (const [nodeId, ops] of byNode) {
    const spans = ops.map((op) => ({
      op,
      start: (op.location as { start: number }).start,
      end: (op.location as { end: number }).end,
    }));

    for (const group of mergeIntervals(spans)) {
      const members = group.members.map((m) => m.op);
      const only = members[0];
      if (members.length === 1 && only !== undefined) {
        out.push(only);
        continue;
      }

      const text = index.require(nodeId).text ?? '';
      const covered = text.slice(group.start, group.end);
      const findingIds = [...new Set(members.flatMap((m) => m.findingIds))];

      out.push({
        id: operationId(findingIds.join('+'), 'merged'),
        location: { kind: 'text', node: nodeId, start: group.start, end: group.end },
        strategy: 'replace',
        replacement: mergedReplacement(members),
        reason: {
          code: only?.reason.code ?? 'policy.sensitive-content',
          authority: [...new Set(members.map((m) => m.reason.authority))].join('; '),
          note: `covers ${members.length} overlapping findings merged into one redaction`,
        },
        findingIds,
        originalValue: covered,
      });
    }
  }

  return out;
}

/**
 * The text a merged span is replaced with.
 *
 * When every member agrees on a replacement the merged span keeps it, so a
 * caller that writes the withholding authority into the marker -- `[REDACTED
 * (b)(6)]` -- still gets a span that cites it after two adjacent findings are
 * fused. Losing the citation at exactly the moment two redactions touch would
 * make the released page inconsistent for a reason the reader cannot see.
 *
 * Members that disagree fall back to the bare marker. A span covering two
 * findings withheld under different authorities cannot honestly cite one of
 * them, and the manifest already records both against the merged operation.
 * Only `replace` members are consulted: a pseudonym stands for one identity,
 * and reusing it for a span that covers two would assert an identity that does
 * not exist.
 */
function mergedReplacement(members: readonly RedactionOperation[]): string {
  const distinct = new Set(
    members
      .filter((operation) => operation.strategy === 'replace')
      .map((operation) => operation.replacement)
      .filter((replacement): replacement is string => replacement !== undefined),
  );
  const only = distinct.size === 1 ? [...distinct][0] : undefined;
  return only ?? '[REDACTED]';
}

/**
 * Pick a strategy for one finding.
 *
 * Order of precedence: an explicit per-type override, then the handling
 * markings the policy attached to the portion, then the caller's default. The
 * middle step is what connects classification to redaction -- a portion marked
 * PSEUDONYMIZED gets tokens and one marked DO NOT PUBLISH gets removal, without
 * the caller restating the policy in redaction terms.
 */
function chooseStrategy(
  finding: Finding,
  markings: Readonly<Record<string, readonly string[]>>,
  policy: CompiledPolicy,
  options: PlanOptions,
): RedactionStrategy {
  const override = matchByType(options.strategyByType, finding.type);
  if (override !== undefined) return override;

  // Structural risks are whole objects: a metadata field, an attachment, a
  // tracked change. The finding is that the object should not be in a released
  // document at all, so it is removed rather than emptied -- leaving an
  // `Author: [REDACTED]` field behind still tells a reader the document had an
  // author worth hiding.
  if (finding.location.kind === 'node' && finding.type.startsWith('risk.')) return 'remove';

  const allMarkings = new Set(Object.values(markings).flat());
  if (allMarkings.has('no-publish')) return 'replace';
  if (allMarkings.has('pseudonymized') && options.pseudonyms !== undefined) return 'pseudonymize';
  if (allMarkings.has('aggregate-only')) return 'replace';

  void policy;
  return options.defaultStrategy ?? 'replace';
}

function matchByType(
  table: Readonly<Record<string, RedactionStrategy>> | undefined,
  type: EntityType,
): RedactionStrategy | undefined {
  if (table === undefined) return undefined;
  const exact = table[type];
  if (exact !== undefined) return exact;
  // Longest prefix wins, so `gov.ssn` beats `gov.*`.
  let best: { pattern: string; strategy: RedactionStrategy } | undefined;
  for (const [pattern, strategy] of Object.entries(table)) {
    if (!pattern.endsWith('.*')) continue;
    if (!type.startsWith(pattern.slice(0, -1))) continue;
    if (best === undefined || pattern.length > best.pattern.length) best = { pattern, strategy };
  }
  return best?.strategy;
}

function resolveReplacement(
  finding: Finding,
  strategy: RedactionStrategy,
  options: PlanOptions,
): { replacement?: string } {
  switch (strategy) {
    case 'replace': {
      const text = options.replacementText ?? '[REDACTED]';
      return { replacement: typeof text === 'function' ? text(finding) : text };
    }
    case 'pseudonymize': {
      if (options.pseudonyms === undefined) {
        throw new ClassifiedError(
          'E_USAGE',
          'the pseudonymize strategy requires a PseudonymGenerator; without a key its tokens would be reversible by anyone',
          { findingId: finding.id },
        );
      }
      return {
        replacement: options.pseudonyms.forValue(finding.type, finding.value, finding.normalized),
      };
    }
    case 'mask': {
      const mask = options.mask ?? { keep: 4, from: 'end' as const };
      return { replacement: maskValue(finding.value, mask) };
    }
    case 'synthesize':
      return { replacement: synthesize(finding) };
    // Raster strategies replace pixels, not text: there is nothing to resolve.
    // Listed individually rather than defaulted, so adding a strategy to the
    // union fails the build here until someone decides which kind it is.
    case 'remove':
    case 'blackout':
    case 'blur':
    case 'pixelate':
    case 'scramble':
    case 'hatch':
    case 'synthetic-mosaic':
      return {};
  }
}

/**
 * Fabricate a value of the same shape.
 *
 * Derived from the finding id, so it is stable across runs, and drawn from
 * ranges reserved for documentation and fiction, so a synthesised value can
 * never collide with a real one. A synthetic phone number that happens to reach
 * a real household would be a worse outcome than leaving the original in place.
 */
function synthesize(finding: Finding): string {
  const seed = sha256Text(finding.id);
  const digits = (count: number, offset = 0): string => {
    let out = '';
    for (let i = 0; i < count; i++) out += String(seed[(offset + i) % seed.length]! % 10);
    return out;
  };

  switch (finding.type) {
    case 'contact.email':
      return `user${digits(4)}@example.invalid`;
    case 'contact.phone':
      // The +1 555 01xx range is reserved for fictional use.
      return `+1555010${digits(4).slice(0, 4)}`;
    case 'gov.ssn':
      // Area 900+ is never issued.
      return `9${digits(2)}-${digits(2, 4)}-${digits(4, 8)}`;
    case 'financial.card':
      // A documentation PAN that fails Luhn, so it cannot be mistaken for live.
      return `4000${digits(12, 2)}`;
    case 'net.ipv4':
      // RFC 5737 documentation range.
      return `192.0.2.${(seed[0]! % 254) + 1}`;
    case 'person.name':
      return `Person ${toBase32(seed, 4)}`;
    case 'geo.coordinates':
      return '0.0000, 0.0000';
    default:
      return `[SYNTHETIC:${toBase32(seed, 6)}]`;
  }
}

function operationId(findingId: string, strategy: string): string {
  return `op_${toBase32(sha256Text(`${findingId} ${strategy}`), 16).toLowerCase()}`;
}

function planId(sourceDigest: string, operations: readonly RedactionOperation[]): string {
  const material = `${sourceDigest}\n${operations.map((o) => `${o.id} ${o.strategy} ${locationKey(o.location)}`).join('\n')}`;
  return `plan_${toBase32(sha256Text(material), 20).toLowerCase()}`;
}

/**
 * Check a plan against a model before applying it.
 *
 * Catches dangling targets, out-of-range spans, and contradictory operations on
 * the same content. Every one of these produces a silently wrong output if it
 * reaches the adapter, so validation is mandatory rather than advisory and
 * `applyPlan` calls it unconditionally.
 */
export function validatePlan(model: DocumentModel, plan: RedactionPlan): void {
  if (plan.sourceDigest !== model.sourceDigest) {
    throw new ClassifiedError(
      'E_CONFLICT',
      'this plan was built against different source bytes; applying it would redact the wrong positions',
      { planDigest: plan.sourceDigest, modelDigest: model.sourceDigest },
    );
  }

  const index = new DocumentIndex(model);
  const byLocation = new Map<string, RedactionOperation>();

  for (const operation of plan.operations) {
    const node = index.get(operation.location.node);
    if (node === undefined) {
      throw new ClassifiedError(
        'E_DANGLING_TARGET',
        `operation ${operation.id} targets node ${JSON.stringify(operation.location.node)}, which is not in the document`,
        { operationId: operation.id, node: operation.location.node },
      );
    }

    if (operation.location.kind === 'text') {
      const length = node.text?.length ?? 0;
      const { start, end } = operation.location;
      if (start < 0 || end > length || start >= end) {
        throw new ClassifiedError(
          'E_DANGLING_TARGET',
          `operation ${operation.id} spans [${start}, ${end}) which is outside the node's ${length} characters`,
          { operationId: operation.id, start, end, length },
        );
      }
    }

    if (!strategySupportsLocation(operation.strategy, operation.location.kind)) {
      throw new ClassifiedError(
        'E_UNSUPPORTED',
        `operation ${operation.id} applies "${operation.strategy}" to a ${operation.location.kind} location, which it cannot act on`,
        { operationId: operation.id, strategy: operation.strategy },
      );
    }

    const key = locationKey(operation.location);
    const existing = byLocation.get(key);
    if (existing !== undefined && existing.strategy !== operation.strategy) {
      throw new ClassifiedError(
        'E_CONFLICT',
        `operations ${existing.id} and ${operation.id} both target the same content with different strategies`,
        { first: existing.id, second: operation.id, location: key },
      );
    }
    byLocation.set(key, operation);
  }
}
