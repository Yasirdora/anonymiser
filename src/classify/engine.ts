/**
 * The classifier.
 *
 * Determines a sensitivity assertion for every portion of a document, rolls
 * those up into a derived banner, and compares that banner against whatever the
 * document already claims about itself.
 *
 * The comparison is the part that earns its keep. Marking software normally
 * lets an author state a classification and takes it on faith; here the stated
 * marking is evidence to be checked against the content, and a disagreement is
 * a finding in its own right.
 */

import type { DetectionResult } from '../detect/engine.js';
import type { EntityType, Finding } from '../detect/types.js';
import { DocumentIndex, type ContentNode, type DocumentModel, type NodeId } from '../model/document.js';
import type { CompiledPolicy } from './lattice.js';
import { applyDelta, dominatedBy, join, joinAll, pruneIneligibleMarkings } from './lattice.js';
import { parseMarking, renderMarking, type MarkingComparison } from './marking.js';
import type { Assertion, MosaicRule, RuleCondition } from './types.js';

/** The classification of one portion of the document. */
export interface PortionClassification {
  /** The node this portion corresponds to. */
  readonly node: NodeId;
  readonly assertion: Assertion;
  /** Rendered portion marking, ready to prepend to the passage. */
  readonly marking: string;
  /** Rules that contributed, in the order they fired. */
  readonly basis: readonly ClassificationBasis[];
  /** Findings inside this portion. */
  readonly findings: readonly Finding[];
}

/** Why a portion was classified as it was. */
export interface ClassificationBasis {
  readonly ruleId: string;
  readonly description: string;
  readonly authority: string;
  /** Findings that triggered the rule. */
  readonly findingIds: readonly string[];
}

/** A condition worth a reviewer's attention that is not an error. */
export interface ClassificationWarning {
  readonly code:
    /** The document's own banner is lower than its content warrants. */
    | 'under-marked'
    /** The banner is higher than any portion supports. */
    | 'over-marked'
    /** A marking string in the document could not be fully parsed. */
    | 'unparsed-marking'
    /**
     * The document carries a marking from a scheme this policy does not define.
     *
     * Almost always means the wrong policy is selected for the document, which
     * is worth saying loudly: classifying a SECRET//NOFORN memo under a
     * corporate scheme produces a plausible-looking banner derived from content
     * alone, with the document's own far stronger claim silently discarded.
     */
    | 'foreign-marking'
    /** A marking was dropped because the level did not permit it. */
    | 'marking-ineligible'
    /** Quasi-identifiers combine to identify individuals. */
    | 'mosaic-risk';
  readonly message: string;
  readonly detail: Readonly<Record<string, unknown>>;
}

/** The result of classifying a document. */
export interface ClassificationResult {
  /** Per-portion determinations, in document order. */
  readonly portions: readonly PortionClassification[];
  /** The join of every portion: what the banner must say. */
  readonly banner: Assertion;
  /** `banner` rendered per the policy. */
  readonly bannerMarking: string;
  /** What the document claims, if it carries a marking. */
  readonly declared?: Assertion;
  /** How the claim compares to the derivation. */
  readonly comparison?: MarkingComparison;
  readonly warnings: readonly ClassificationWarning[];
  readonly policyId: string;
  readonly policyVersion: string;
}

/** Options for a classification run. */
export interface ClassifyOptions {
  /**
   * Node roles that delimit a portion.
   *
   * Defaults to the block-level roles. A finding inside a smaller node is
   * attributed to its nearest enclosing portion, so a marking always lands on
   * something a reader can see as a unit.
   */
  readonly portionRoles?: readonly string[];
  /** Ignore findings below this confidence when classifying. Defaults to 0.5. */
  readonly minConfidence?: number;
}

const DEFAULT_PORTION_ROLES: readonly string[] = [
  'paragraph', 'heading', 'title', 'list-item', 'table-cell', 'caption',
  'footnote', 'section', 'header', 'footer', 'page',
];

/**
 * Classify a document against a policy.
 *
 * Pure and deterministic: same model, same findings, same policy, same result,
 * which is what lets the provenance manifest assert a classification rather
 * than merely record one.
 */
export function classify(
  model: DocumentModel,
  detection: DetectionResult,
  policy: CompiledPolicy,
  options: ClassifyOptions = {},
): ClassificationResult {
  const index = new DocumentIndex(model);
  const portionRoles = new Set(options.portionRoles ?? DEFAULT_PORTION_ROLES);
  const minConfidence = options.minConfidence ?? 0.5;
  const warnings: ClassificationWarning[] = [];

  const eligible = detection.findings.filter((f) => f.confidence >= minConfidence);
  const byPortion = groupByPortion(index, eligible, portionRoles);

  const portions: PortionClassification[] = [];
  for (const [nodeId, findings] of byPortion) {
    const { assertion, basis } = classifyPortion(policy, findings, index.get(nodeId));

    const withMosaic = applyMosaicRules(policy, assertion, basis, findings, 'portion', warnings, nodeId);
    const pruned = pruneIneligibleMarkings(policy, withMosaic);
    if (pruned.dropped.length > 0) {
      warnings.push({
        code: 'marking-ineligible',
        message: `dropped ${pruned.dropped.length} marking(s) not permitted at ${policy.level(pruned.assertion.level).name}`,
        detail: { node: nodeId, dropped: pruned.dropped },
      });
    }

    portions.push({
      node: nodeId,
      assertion: pruned.assertion,
      marking: renderMarking(policy, pruned.assertion, 'portion'),
      basis,
      findings,
    });
  }

  portions.sort((a, b) => documentOrder(model, a.node) - documentOrder(model, b.node));

  // Document-scope mosaic rules see every finding at once, which is how a case
  // file that spreads name, date of birth, and postcode across three sections
  // gets caught.
  let banner = joinAll(policy, portions.map((p) => p.assertion));
  const documentBasis: ClassificationBasis[] = [];
  banner = applyMosaicRules(policy, banner, documentBasis, eligible, 'document', warnings, undefined);
  banner = pruneIneligibleMarkings(policy, banner).assertion;

  const declared = readDeclaredMarking(policy, detection.findings, warnings);
  const comparison =
    declared === undefined ? undefined : compareMarkings(policy, declared, banner);

  if (comparison?.underMarked === true) {
    warnings.push({
      code: 'under-marked',
      message: `the document is marked ${renderMarking(policy, comparison.declared)} but its content requires ${renderMarking(policy, comparison.derived)}`,
      detail: { missing: comparison.missing },
    });
  }
  if (comparison?.overMarked === true) {
    warnings.push({
      code: 'over-marked',
      message: `the document is marked ${renderMarking(policy, comparison.declared)} but no portion supports more than ${renderMarking(policy, comparison.derived)}; a portion marking may be missing`,
      detail: { unsupported: comparison.unsupported },
    });
  }

  return {
    portions,
    banner,
    bannerMarking: renderMarking(policy, banner, 'banner'),
    ...(declared !== undefined ? { declared } : {}),
    ...(comparison !== undefined ? { comparison } : {}),
    warnings,
    policyId: policy.policy.id,
    policyVersion: policy.policy.version,
  };
}

/**
 * Attribute each finding to the portion that contains it.
 *
 * A finding inside a text run reports the run's node; markings belong on the
 * paragraph. Walking up to the nearest portion-role ancestor puts the marking
 * where a reader expects it and stops one sentence from acquiring three
 * different classifications.
 */
function groupByPortion(
  index: DocumentIndex,
  findings: readonly Finding[],
  portionRoles: ReadonlySet<string>,
): Map<NodeId, Finding[]> {
  const grouped = new Map<NodeId, Finding[]>();
  for (const finding of findings) {
    const portion = nearestPortion(index, finding.location.node, portionRoles);
    const bucket = grouped.get(portion);
    if (bucket) bucket.push(finding);
    else grouped.set(portion, [finding]);
  }
  return grouped;
}

function nearestPortion(
  index: DocumentIndex,
  nodeId: NodeId,
  portionRoles: ReadonlySet<string>,
): NodeId {
  const node = index.get(nodeId);
  if (node === undefined) return nodeId;
  if (node.role !== undefined && portionRoles.has(node.role)) return nodeId;
  for (const ancestor of index.ancestors(nodeId)) {
    if (ancestor.role !== undefined && portionRoles.has(ancestor.role)) return ancestor.id;
  }
  return nodeId;
}

function documentOrder(model: DocumentModel, nodeId: NodeId): number {
  const position = model.nodes.findIndex((n) => n.id === nodeId);
  return position === -1 ? Number.MAX_SAFE_INTEGER : position;
}

function classifyPortion(
  policy: CompiledPolicy,
  findings: readonly Finding[],
  node: ContentNode | undefined,
): { assertion: Assertion; basis: ClassificationBasis[] } {
  let assertion = policy.unit;
  const basis: ClassificationBasis[] = [];

  for (const rule of policy.policy.rules) {
    const matched = findings.filter((f) => matchesCondition(rule.when, f, node));
    const required = rule.when.occurrences ?? 1;
    if (matched.length < required) continue;

    assertion = applyDelta(policy, assertion, rule.assert);
    basis.push({
      ruleId: rule.id,
      description: rule.description,
      authority: rule.authority,
      findingIds: matched.map((f) => f.id),
    });
  }

  if (basis.length === 0) {
    assertion = join(policy, assertion, { level: policy.policy.defaultLevel, markings: {} });
  }
  return { assertion, basis };
}

function matchesCondition(
  condition: RuleCondition,
  finding: Finding,
  node: ContentNode | undefined,
): boolean {
  if (condition.minConfidence !== undefined && finding.confidence < condition.minConfidence) {
    return false;
  }
  if (condition.nodeRoles !== undefined) {
    if (node?.role === undefined) return false;
    if (!condition.nodeRoles.includes(node.role)) return false;
  }
  if (condition.entityTypes !== undefined) {
    if (!condition.entityTypes.some((pattern) => matchesEntityType(pattern, finding.type))) {
      return false;
    }
  }
  return true;
}

/** Exact match, or prefix match when the pattern ends in `.*`. */
function matchesEntityType(pattern: EntityType, type: EntityType): boolean {
  if (pattern === type) return true;
  if (pattern.endsWith('.*')) return type.startsWith(pattern.slice(0, -1));
  return false;
}

/**
 * Escalate for re-identification risk.
 *
 * Counts *distinct types* rather than occurrences: three postcodes in a
 * paragraph are one quasi-identifier repeated, while a postcode, a date of
 * birth, and a sex are three, and only the second case narrows the population
 * to an individual.
 */
function applyMosaicRules(
  policy: CompiledPolicy,
  assertion: Assertion,
  basis: ClassificationBasis[],
  findings: readonly Finding[],
  scope: MosaicRule['scope'],
  warnings: ClassificationWarning[],
  node: NodeId | undefined,
): Assertion {
  let result = assertion;
  for (const rule of policy.policy.mosaic) {
    if (rule.scope !== scope) continue;
    const present = new Set<EntityType>();
    const contributing: string[] = [];
    for (const finding of findings) {
      if (rule.types.some((t) => matchesEntityType(t, finding.type))) {
        present.add(finding.type);
        contributing.push(finding.id);
      }
    }
    if (present.size < rule.threshold) continue;

    result = applyDelta(policy, result, rule.assert);
    basis.push({
      ruleId: rule.id,
      description: rule.description,
      authority: rule.authority,
      findingIds: contributing,
    });
    warnings.push({
      code: 'mosaic-risk',
      message: `${present.size} distinct quasi-identifiers co-occur (${[...present].join(', ')}); in combination they narrow the population far more than any one of them does`,
      detail: { rule: rule.id, scope, types: [...present], ...(node !== undefined ? { node } : {}) },
    });
  }
  return result;
}

/**
 * Read the marking the document carries.
 *
 * Banner findings are joined rather than taking the first: a document with
 * `SECRET` on page one and `SECRET//NOFORN` on page four is claiming the
 * stronger of the two, and the engine should compare against the strongest
 * claim rather than whichever appeared first.
 */
function readDeclaredMarking(
  policy: CompiledPolicy,
  findings: readonly Finding[],
  warnings: ClassificationWarning[],
): Assertion | undefined {
  const bannerFindings = findings.filter((f) => f.type === 'marking.banner');
  if (bannerFindings.length === 0) return undefined;

  const assertions: Assertion[] = [];
  const reportedForeign = new Set<string>();

  for (const finding of bannerFindings) {
    const parsed = parseMarking(policy, finding.normalized ?? finding.value);

    if (!parsed.hasExplicitLevel) {
      // The marking named no level this policy defines. Reporting it is the
      // whole point: a document asserting something about itself in a
      // vocabulary the active policy cannot read must never be treated as
      // unmarked, because the derived banner would then rest on content alone
      // and quietly contradict the document.
      const key = parsed.assertion.markings ? finding.value.toUpperCase() : finding.value;
      if (!reportedForeign.has(key)) {
        reportedForeign.add(key);
        warnings.push({
          code: 'foreign-marking',
          message: `the document is marked "${finding.value}", which the ${policy.policy.name} policy does not define; either the wrong policy is selected for this document or the policy needs extending before this marking can be honoured`,
          detail: {
            findingId: finding.id,
            marking: finding.value,
            policyId: policy.policy.id,
            unrecognized: parsed.unrecognized,
          },
        });
      }
      continue;
    }

    if (parsed.unrecognized.length > 0) {
      warnings.push({
        code: 'unparsed-marking',
        message: `the marking "${finding.value}" contains ${parsed.unrecognized.length} segment(s) this policy does not define: ${parsed.unrecognized.join(', ')}`,
        detail: { findingId: finding.id, unrecognized: parsed.unrecognized },
      });
    }
    assertions.push(parsed.assertion);
  }

  return assertions.length === 0 ? undefined : joinAll(policy, assertions);
}

/** Compare a declared marking against a derived one, in both directions. */
export function compareMarkings(
  policy: CompiledPolicy,
  declared: Assertion,
  derived: Assertion,
): MarkingComparison {
  const underMarked = !dominatedBy(policy, derived, declared);
  const overMarked = !dominatedBy(policy, declared, derived);

  const missing: string[] = [];
  const unsupported: string[] = [];

  if (policy.level(derived.level).rank > policy.level(declared.level).rank) {
    missing.push(policy.level(derived.level).name);
  }
  if (policy.level(declared.level).rank > policy.level(derived.level).rank) {
    unsupported.push(policy.level(declared.level).name);
  }

  for (const group of policy.groups) {
    const declaredValues = new Set(declared.markings[group.id] ?? []);
    const derivedValues = new Set(derived.markings[group.id] ?? []);
    for (const id of derivedValues) {
      if (!declaredValues.has(id)) missing.push(policy.markingValue(id).name);
    }
    for (const id of declaredValues) {
      if (!derivedValues.has(id)) unsupported.push(policy.markingValue(id).name);
    }
  }

  return { declared, derived, underMarked, overMarked, missing, unsupported };
}
