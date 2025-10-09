/**
 * The assertion algebra.
 *
 * Classification markings form a lattice: levels are a chain ordered by rank,
 * each marking group is a lattice over its powerset, and an assertion is a
 * point in their product. Rolling portions up into a banner is the lattice
 * join; checking whether one marking is permitted under another is the partial
 * order.
 *
 * Stating it that way is not academic dressing. It is what makes the derived
 * banner provably correct: join is associative and commutative, so the banner
 * does not depend on the order the portions were visited, and idempotent, so
 * classifying an already-classified document changes nothing.
 */

import { ClassifiedError } from '../errors.js';
import type {
  Assertion,
  AssertionDelta,
  ClassificationPolicy,
  GroupId,
  LevelId,
  MarkingGroup,
  MarkingId,
  MarkingValue,
  SensitivityLevel,
} from './types.js';

/** A policy with its lookup tables built, validated once at construction. */
export class CompiledPolicy {
  readonly policy: ClassificationPolicy;
  readonly #levelsById: ReadonlyMap<LevelId, SensitivityLevel>;
  readonly #levelsByRank: readonly SensitivityLevel[];
  readonly #groupsById: ReadonlyMap<GroupId, MarkingGroup>;
  readonly #valueGroup: ReadonlyMap<MarkingId, GroupId>;

  constructor(policy: ClassificationPolicy) {
    const levelsById = new Map<LevelId, SensitivityLevel>();
    for (const level of policy.levels) {
      if (levelsById.has(level.id)) {
        throw new ClassifiedError('E_INVALID_POLICY', `duplicate level id ${JSON.stringify(level.id)}`, {
          policyId: policy.id,
        });
      }
      levelsById.set(level.id, level);
    }
    if (!levelsById.has(policy.defaultLevel)) {
      throw new ClassifiedError(
        'E_INVALID_POLICY',
        `defaultLevel ${JSON.stringify(policy.defaultLevel)} is not a declared level`,
        { policyId: policy.id },
      );
    }

    const groupsById = new Map<GroupId, MarkingGroup>();
    const valueGroup = new Map<MarkingId, GroupId>();
    for (const group of policy.groups) {
      if (groupsById.has(group.id)) {
        throw new ClassifiedError('E_INVALID_POLICY', `duplicate group id ${JSON.stringify(group.id)}`, {
          policyId: policy.id,
        });
      }
      groupsById.set(group.id, group);
      for (const value of group.values) {
        if (valueGroup.has(value.id)) {
          throw new ClassifiedError(
            'E_INVALID_POLICY',
            `marking ${JSON.stringify(value.id)} is declared in more than one group`,
            { policyId: policy.id, groups: [valueGroup.get(value.id), group.id] },
          );
        }
        valueGroup.set(value.id, group.id);
        if (value.minimumLevel !== undefined && !levelsById.has(value.minimumLevel)) {
          throw new ClassifiedError(
            'E_INVALID_POLICY',
            `marking ${JSON.stringify(value.id)} requires unknown level ${JSON.stringify(value.minimumLevel)}`,
            { policyId: policy.id },
          );
        }
      }
      for (const defaulted of group.defaultValues ?? []) {
        if (!group.values.some((v) => v.id === defaulted)) {
          throw new ClassifiedError(
            'E_INVALID_POLICY',
            `group ${JSON.stringify(group.id)} defaults to unknown marking ${JSON.stringify(defaulted)}`,
            { policyId: policy.id },
          );
        }
      }
    }

    this.policy = policy;
    this.#levelsById = levelsById;
    this.#levelsByRank = [...policy.levels].sort((a, b) => a.rank - b.rank);
    this.#groupsById = groupsById;
    this.#valueGroup = valueGroup;
  }

  get levels(): readonly SensitivityLevel[] {
    return this.#levelsByRank;
  }

  get groups(): readonly MarkingGroup[] {
    return [...this.policy.groups].sort((a, b) => a.order - b.order);
  }

  level(id: LevelId): SensitivityLevel {
    const level = this.#levelsById.get(id);
    if (level === undefined) {
      throw new ClassifiedError('E_INVALID_POLICY', `unknown level ${JSON.stringify(id)}`, {
        policyId: this.policy.id,
      });
    }
    return level;
  }

  group(id: GroupId): MarkingGroup {
    const group = this.#groupsById.get(id);
    if (group === undefined) {
      throw new ClassifiedError('E_INVALID_POLICY', `unknown marking group ${JSON.stringify(id)}`, {
        policyId: this.policy.id,
      });
    }
    return group;
  }

  markingValue(id: MarkingId): MarkingValue {
    return this.group(this.groupIdOf(id)).values.find((v) => v.id === id)!;
  }

  /** The group a marking value belongs to. */
  groupIdOf(id: MarkingId): GroupId {
    const groupId = this.#valueGroup.get(id);
    if (groupId === undefined) {
      throw new ClassifiedError('E_INVALID_POLICY', `unknown marking ${JSON.stringify(id)}`, {
        policyId: this.policy.id,
      });
    }
    return groupId;
  }

  /** The lowest level in the policy: the bottom of the lattice. */
  get bottom(): SensitivityLevel {
    const first = this.#levelsByRank[0];
    if (first === undefined) {
      throw new ClassifiedError('E_INVALID_POLICY', 'policy declares no levels', { policyId: this.policy.id });
    }
    return first;
  }

  /** The unclassified, unmarked assertion. Identity element for {@link join}. */
  get unit(): Assertion {
    return { level: this.bottom.id, markings: {} };
  }
}

/** Build and validate a policy. Throws `E_INVALID_POLICY` on a malformed one. */
export function compilePolicy(policy: ClassificationPolicy): CompiledPolicy {
  return new CompiledPolicy(policy);
}

/**
 * Least upper bound of two assertions.
 *
 * The level takes the higher rank. Each group combines by its own semantics,
 * with `union` groups accumulating restrictions and `intersection` groups
 * narrowing permissions. Domination is applied last, once the full value set is
 * known, so that a dominating value introduced by either operand suppresses
 * what it overrides regardless of which side contributed it.
 */
export function join(policy: CompiledPolicy, a: Assertion, b: Assertion): Assertion {
  const level = policy.level(a.level).rank >= policy.level(b.level).rank ? a.level : b.level;

  const markings: Record<GroupId, readonly MarkingId[]> = {};
  for (const group of policy.groups) {
    const left = a.markings[group.id];
    const right = b.markings[group.id];
    const combined = combineGroup(group, left, right);
    if (combined.length > 0) markings[group.id] = combined;
  }

  return applyDomination(policy, { level, markings });
}

/** Fold a list of assertions into their least upper bound. */
export function joinAll(policy: CompiledPolicy, assertions: readonly Assertion[]): Assertion {
  return assertions.reduce<Assertion>((acc, next) => join(policy, acc, next), policy.unit);
}

function combineGroup(
  group: MarkingGroup,
  left: readonly MarkingId[] | undefined,
  right: readonly MarkingId[] | undefined,
): MarkingId[] {
  if (group.combine === 'union') {
    const out = new Set<MarkingId>([...(left ?? []), ...(right ?? [])]);
    return orderByPolicy(group, out);
  }

  // Intersection. A side that carries no explicit value contributes the group's
  // declared defaults, which is what stops an unmarked portion from being
  // treated as universally permissive: a paragraph with no releasability
  // marking is releasable to the originator alone, not to everyone.
  const leftExplicit = left !== undefined && left.length > 0;
  const rightExplicit = right !== undefined && right.length > 0;

  // Neither side engages this group, so it stays absent rather than collapsing
  // to the defaults. A policy whose documents never mention releasability
  // should not sprout a releasability segment.
  if (!leftExplicit && !rightExplicit) return [];

  const defaults = group.defaultValues ?? [];
  const leftSet = expandMarkings(group, leftExplicit ? left : defaults);
  const rightSet = expandMarkings(group, rightExplicit ? right : defaults);

  const intersected = new Set<MarkingId>();
  for (const id of leftSet) if (rightSet.has(id)) intersected.add(id);

  const collapsed = collapseMarkings(group, intersected);

  // An intersection that has narrowed all the way back to the baseline grants
  // nothing beyond it, and rendering it would state a permission the document
  // does not actually carry.
  if (defaults.length > 0 && isSameSet(collapsed, defaults)) return [];

  return orderByPolicy(group, new Set(collapsed));
}

/**
 * Expand community tokens into the nations they stand for.
 *
 * `FVEY` is one banner word and five countries. Intersection has to see the
 * countries, or `REL TO USA, FVEY` ∩ `REL TO USA, GBR` becomes `USA` because
 * the tokens never matched.
 */
function expandMarkings(group: MarkingGroup, ids: readonly MarkingId[]): Set<MarkingId> {
  const out = new Set<MarkingId>();
  const byId = new Map(group.values.map((value) => [value.id, value]));
  for (const id of ids) {
    const expansion = byId.get(id)?.expandsTo;
    if (expansion !== undefined && expansion.length > 0) {
      for (const member of expansion) out.add(member);
    } else {
      out.add(id);
    }
  }
  return out;
}

/**
 * Re-compress an expanded set so a full Five Eyes intersection renders as
 * `FVEY` rather than five country names.
 */
function collapseMarkings(group: MarkingGroup, expanded: ReadonlySet<MarkingId>): MarkingId[] {
  const remaining = new Set(expanded);
  const aliases = group.values.filter(
    (value) => value.expandsTo !== undefined && value.expandsTo.length > 0,
  );

  for (const alias of aliases) {
    const members = alias.expandsTo!;
    if (members.every((id) => remaining.has(id))) {
      for (const id of members) remaining.delete(id);
      remaining.add(alias.id);
    }
  }

  return [...remaining];
}

function isSameSet(a: readonly MarkingId[], b: readonly MarkingId[]): boolean {
  if (a.length !== b.length) return false;
  const lookup = new Set(b);
  return a.every((id) => lookup.has(id));
}

/** Order values by their position in the policy, so rendering is stable. */
function orderByPolicy(group: MarkingGroup, values: ReadonlySet<MarkingId>): MarkingId[] {
  return group.values.filter((v) => values.has(v.id)).map((v) => v.id);
}

/**
 * Remove values that another present value overrides.
 *
 * Applied after combination rather than during it: domination is a property of
 * the final set, and applying it pairwise would let a dominated value survive
 * because the value that overrides it arrived from the other operand.
 */
export function applyDomination(policy: CompiledPolicy, assertion: Assertion): Assertion {
  const markings: Record<GroupId, readonly MarkingId[]> = {};

  const allValues = new Set<MarkingId>();
  for (const values of Object.values(assertion.markings)) {
    for (const id of values) allValues.add(id);
  }

  const suppressed = new Set<MarkingId>();
  for (const id of allValues) {
    for (const dominated of policy.markingValue(id).dominates ?? []) {
      suppressed.add(dominated);
    }
  }

  for (const group of policy.groups) {
    const values = assertion.markings[group.id];
    if (values === undefined) continue;
    const kept = values.filter((id) => !suppressed.has(id));
    if (kept.length > 0) markings[group.id] = kept;
  }

  return { level: assertion.level, markings };
}

/**
 * Partial order: true when `a` is no more sensitive than `b` in every respect.
 *
 * Used to check that a declared banner covers what the content requires, and to
 * decide whether a release at a given level may proceed.
 */
export function dominatedBy(policy: CompiledPolicy, a: Assertion, b: Assertion): boolean {
  if (policy.level(a.level).rank > policy.level(b.level).rank) return false;
  for (const group of policy.groups) {
    const aValues = new Set(a.markings[group.id] ?? []);
    const bValues = new Set(b.markings[group.id] ?? []);
    if (group.combine === 'union') {
      // Restrictions: every restriction on `a` must also be on `b`.
      for (const id of aValues) if (!bValues.has(id)) return false;
    } else {
      // Permissions: more countries is *less* sensitive. `a` is no more
      // sensitive than `b` when `a` permits at least everyone `b` permits.
      // Originator-only (no explicit values) is the most restricted state.
      const aPermitted = aValues.size === 0 ? null : expandMarkings(group, [...aValues]);
      const bPermitted = bValues.size === 0 ? null : expandMarkings(group, [...bValues]);
      if (aPermitted === null && bPermitted === null) continue;
      if (aPermitted === null) return false;
      if (bPermitted === null) continue;
      for (const id of bPermitted) if (!aPermitted.has(id)) return false;
    }
  }
  return true;
}

/** True when the two assertions are identical after normalisation. */
export function assertionsEqual(policy: CompiledPolicy, a: Assertion, b: Assertion): boolean {
  return dominatedBy(policy, a, b) && dominatedBy(policy, b, a);
}

/** Apply a rule's delta to an assertion, raising but never lowering it. */
export function applyDelta(
  policy: CompiledPolicy,
  base: Assertion,
  delta: AssertionDelta,
): Assertion {
  const contribution: Assertion = {
    level: delta.level ?? policy.bottom.id,
    markings: delta.markings ?? {},
  };
  return join(policy, base, contribution);
}

/**
 * Drop markings whose minimum level exceeds the assertion's level.
 *
 * A compartment that only exists at SECRET and above must not appear on a
 * CONFIDENTIAL banner. This is checked at the end of classification rather than
 * during it, because an assertion's level can rise after a marking is added.
 */
export function pruneIneligibleMarkings(
  policy: CompiledPolicy,
  assertion: Assertion,
): { assertion: Assertion; dropped: readonly MarkingId[] } {
  const rank = policy.level(assertion.level).rank;
  const markings: Record<GroupId, readonly MarkingId[]> = {};
  const dropped: MarkingId[] = [];

  for (const group of policy.groups) {
    const values = assertion.markings[group.id];
    if (values === undefined) continue;
    const kept = values.filter((id) => {
      const minimum = policy.markingValue(id).minimumLevel;
      if (minimum === undefined) return true;
      if (policy.level(minimum).rank <= rank) return true;
      dropped.push(id);
      return false;
    });
    if (kept.length > 0) markings[group.id] = kept;
  }

  return { assertion: { level: assertion.level, markings }, dropped };
}
