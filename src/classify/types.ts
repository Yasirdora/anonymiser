/**
 * The classification policy model.
 *
 * A policy describes a sensitivity scheme completely enough that the engine can
 * derive markings rather than accept them. That distinction is the point: a
 * banner line a human types is an assertion, and a banner line the engine
 * derives from the portions beneath it is a conclusion that can be checked.
 *
 * The model is built to express real marking systems -- CAPCO, NATO, the UK
 * GSCP, and ordinary corporate schemes -- without special-casing any of them.
 */

import type { NodeRole } from '../model/document.js';
import type { EntityType } from '../detect/types.js';

export type LevelId = string;
export type GroupId = string;
export type MarkingId = string;

/** One rung of the classification ladder. */
export interface SensitivityLevel {
  readonly id: LevelId;
  /** Full name as it appears in a banner, e.g. `TOP SECRET`. */
  readonly name: string;
  /** Portion-marking abbreviation, e.g. `TS`. */
  readonly abbreviation: string;
  /** Higher is more sensitive. Gaps are allowed and are useful for extension. */
  readonly rank: number;
  readonly description: string;
  /**
   * Semantic severity for presentation. A colour is deliberately not specified:
   * marking colours are set by the adopting organisation, and hard-coding the
   * US convention into the engine would be wrong everywhere else.
   */
  readonly tone: 'neutral' | 'notice' | 'caution' | 'warning' | 'critical';
}

/**
 * How the values of a marking group combine when portions are rolled up.
 *
 * This is the distinction that marking systems get wrong most often in
 * software. A restriction and a permission do not aggregate the same way:
 *
 * - `union` -- restrictions accumulate. If any portion is ORCON, the document
 *   is ORCON. Adding portions can only add constraints.
 * - `intersection` -- permissions narrow. If one portion is releasable to five
 *   nations and another to three, the document is releasable to the three they
 *   share. Adding portions can only remove permissions.
 *
 * Treating releasability as a union is the specific bug that produces a
 * document marked releasable to an ally that contains a paragraph which is not.
 */
export type CombineSemantics = 'union' | 'intersection';

/** One value within a marking group. */
export interface MarkingValue {
  readonly id: MarkingId;
  /** Full form for the banner line. */
  readonly name: string;
  /** Short form for portion markings. */
  readonly abbreviation: string;
  readonly description: string;
  /**
   * Values this one overrides when both are present.
   *
   * NOFORN dominates every REL TO: a document containing a portion releasable
   * to no foreign national is not releasable, whatever its other portions
   * permit.
   */
  readonly dominates?: readonly MarkingId[];
  /**
   * Country or community ids this value stands for when combining permissions.
   *
   * `FVEY` is one token on the banner and five nations in the lattice. Join and
   * intersection expand it before they run, so `REL TO USA, FVEY` ∩ `REL TO
   * USA, GBR` is `REL TO USA, GBR` rather than collapsing to `USA` because the
   * tokens did not match.
   */
  readonly expandsTo?: readonly MarkingId[];
  /** Minimum level at which this value may be used. */
  readonly minimumLevel?: LevelId;
}

/** A category of markings that render as one banner segment. */
export interface MarkingGroup {
  readonly id: GroupId;
  readonly name: string;
  readonly combine: CombineSemantics;
  /** Position in the banner line; lower renders first. */
  readonly order: number;
  /** Text before the values, e.g. `REL TO `. */
  readonly prefix?: string;
  /** Text after the values, e.g. the closing bracket of `[PERSONAL]`. */
  readonly suffix?: string;
  /** Separator between values within this group. */
  readonly valueSeparator: string;
  readonly values: readonly MarkingValue[];
  /**
   * Values contributed by a portion that specifies none of this group.
   *
   * Only meaningful for `intersection` groups, and essential there. A portion
   * with no releasability marking is not releasable to everyone; it is
   * releasable to the originator alone, and the intersection must reflect that
   * or the derived banner will be too permissive.
   */
  readonly defaultValues?: readonly MarkingId[];
}

/** A concrete sensitivity determination for a portion or a whole document. */
export interface Assertion {
  readonly level: LevelId;
  /** Marking values held, by group. Groups with no values are omitted. */
  readonly markings: Readonly<Record<GroupId, readonly MarkingId[]>>;
}

/** What a rule contributes when it fires. */
export interface AssertionDelta {
  /** Raise the level to at least this. Never lowers. */
  readonly level?: LevelId;
  /** Marking values to contribute, by group. */
  readonly markings?: Readonly<Record<GroupId, readonly MarkingId[]>>;
}

/** Conditions under which a classification rule applies. */
export interface RuleCondition {
  /**
   * Entity types to match. A trailing `.*` matches by prefix, so `gov.*` covers
   * every government identifier a pack might add later without a policy edit.
   */
  readonly entityTypes?: readonly EntityType[];
  /** Minimum finding confidence for the rule to fire. */
  readonly minConfidence?: number;
  /** Restrict to findings inside nodes with one of these roles. */
  readonly nodeRoles?: readonly NodeRole[];
  /** Number of distinct matching findings required within one portion. */
  readonly occurrences?: number;
}

/** A single classification rule. */
export interface ClassificationRule {
  readonly id: string;
  readonly description: string;
  readonly when: RuleCondition;
  readonly assert: AssertionDelta;
  /**
   * Citation for the determination: a statute, an exemption, an internal
   * policy paragraph. Carried through to the redaction reason and the manifest,
   * because "why was this removed" is the first question any reviewer asks.
   */
  readonly authority: string;
}

/**
 * A re-identification rule over combinations of quasi-identifiers.
 *
 * Individually harmless fields become identifying in combination: Sweeney's
 * finding that ZIP code, date of birth, and sex uniquely identify most of the
 * US population is the canonical example, and it is invisible to any engine
 * that scores findings one at a time. A mosaic rule fires on the combination
 * and escalates the portion that contains it.
 */
export interface MosaicRule {
  readonly id: string;
  readonly description: string;
  /** The quasi-identifier types under consideration. */
  readonly types: readonly EntityType[];
  /** How many distinct types must co-occur before the rule fires. */
  readonly threshold: number;
  /**
   * Scope over which co-occurrence is counted.
   *
   * `portion` is the conservative default. `document` catches the case where
   * the identifiers are spread across sections, which is how they usually
   * appear in a form or a case file.
   */
  readonly scope: 'portion' | 'document';
  readonly assert: AssertionDelta;
  readonly authority: string;
}

/** How a policy renders its markings. */
export interface BannerFormat {
  /** Separator between the level and each marking group. */
  readonly segmentSeparator: string;
  /** Wrapper for portion markings, as a `[prefix, suffix]` pair. */
  readonly portionDelimiters: readonly [string, string];
  /** Render the level in banners using its full name rather than abbreviation. */
  readonly bannerUsesFullName: boolean;
  /** Uppercase the rendered marking. */
  readonly uppercase: boolean;
}

/** A complete classification policy. */
export interface ClassificationPolicy {
  readonly id: string;
  readonly version: string;
  readonly name: string;
  /** Owning authority, e.g. `US/ODNI CAPCO`, `UK Cabinet Office`. */
  readonly authority: string;
  readonly description: string;
  /** Ordered by rank; the engine sorts defensively rather than trusting order. */
  readonly levels: readonly SensitivityLevel[];
  readonly groups: readonly MarkingGroup[];
  readonly rules: readonly ClassificationRule[];
  readonly mosaic: readonly MosaicRule[];
  /** Level assigned to a portion no rule matched. */
  readonly defaultLevel: LevelId;
  readonly banner: BannerFormat;
}
