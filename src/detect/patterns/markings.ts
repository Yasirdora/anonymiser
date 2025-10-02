/**
 * Security markings already present in the document.
 *
 * This pack is what lets the engine treat classification as a first-class
 * problem rather than a label the user types. A document that already says
 * `SECRET//NOFORN` in its header is telling you its own sensitivity, and the
 * classifier should honour that as an input, cross-check it against what the
 * content actually warrants, and flag the disagreement.
 *
 * Two disagreements matter. A banner lower than the content warrants is an
 * under-classification and a disclosure risk. A banner higher than any portion
 * mark inside it usually means a portion was missed, which is the failure that
 * produces over-redacted, unusable releases.
 */

import type { PatternPack, PatternRule } from '../pattern.js';
import { Confidence } from '../types.js';

/**
 * The US/IC banner grammar: a classification level, then any number of
 * `//`-separated control segments.
 *
 * Written against the CAPCO register's shape rather than its full vocabulary.
 * The vocabulary lives in the policy packs, where it can be updated without
 * touching a regular expression, and where an unrecognised control marking
 * becomes a reviewable finding instead of a silent non-match.
 */
const US_BANNER =
  /(?<![A-Z/])(?:TOP SECRET|SECRET|CONFIDENTIAL|UNCLASSIFIED|CUI|CONTROLLED)(?:\/\/[A-Z0-9][A-Z0-9 ,._-]{0,60})*(?![A-Z/])/g;

const usBanner: PatternRule = {
  id: 'marking.banner.us',
  type: 'marking.banner',
  pattern: US_BANNER,
  baseConfidence: Confidence.STRONG,
  description: 'a US-style classification banner line',
  validate(value) {
    // A bare level word appears constantly in prose ("this remains confidential").
    // Requiring either a control segment or an all-caps multi-word level keeps
    // the rule from firing on every sentence that discusses secrecy.
    const hasControls = value.includes('//');
    const isCompoundLevel = /^(?:TOP SECRET|UNCLASSIFIED|CUI|CONTROLLED)/.test(value);
    return hasControls || isCompoundLevel
      ? { ok: true, signal: 'structure:capco-shape', note: 'matches the CAPCO banner grammar', weight: 0.14 }
      : { ok: false, signal: 'structure:capco-shape', note: 'a bare level word with no control segment, probably prose' };
  },
  normalize: (value) => value.toUpperCase().replace(/\s+/g, ' ').trim(),
};

/**
 * Portion markings: a parenthesised abbreviation at the head of a paragraph.
 *
 * Anchored to a line or sentence start because `(S)` mid-sentence is far more
 * likely to be a footnote reference or a list label than a marking.
 */
const US_PORTION = /(?<=^|[\n.!?]\s{0,4})\((?:TS|S|C|U|CUI|R)(?:\/\/[A-Z0-9][A-Z0-9 ,._-]{0,40})*\)/gm;

const usPortion: PatternRule = {
  id: 'marking.portion.us',
  type: 'marking.portion',
  pattern: US_PORTION,
  baseConfidence: Confidence.LIKELY,
  description: 'a US-style portion marking at the start of a passage',
  normalize: (value) => value.toUpperCase().replace(/\s+/g, ' ').trim(),
};

const NATO_BANNER =
  /(?<![A-Z-])(?:COSMIC TOP SECRET|NATO SECRET|NATO CONFIDENTIAL|NATO RESTRICTED|NATO UNCLASSIFIED|CTS|NS|NC|NR|NU)(?:\s?ATOMAL)?(?![A-Z-])/g;

const natoBanner: PatternRule = {
  id: 'marking.banner.nato',
  type: 'marking.banner',
  pattern: NATO_BANNER,
  baseConfidence: Confidence.LIKELY,
  description: 'a NATO classification marking',
  validate: (value) =>
    value.length > 3
      ? { ok: true, signal: 'structure:nato-shape', note: 'a spelled-out NATO marking', weight: 0.2 }
      : { ok: false, signal: 'structure:nato-shape', note: 'a two-letter abbreviation too ambiguous to act on' },
  normalize: (value) => value.toUpperCase().replace(/\s+/g, ' ').trim(),
};

const UK_BANNER =
  /(?<![A-Z-])OFFICIAL(?:\s?-\s?SENSITIVE)?(?:\s?\[[A-Z ]{2,30}\])?|(?<![A-Z-])(?:SECRET|TOP SECRET)(?:\s?-\s?[A-Z]{2,20})?(?![A-Z-])/g;

const ukBanner: PatternRule = {
  id: 'marking.banner.uk',
  type: 'marking.banner',
  pattern: UK_BANNER,
  baseConfidence: Confidence.LIKELY,
  description: 'a UK Government Security Classification marking',
  normalize: (value) => value.toUpperCase().replace(/\s*-\s*/g, '-').replace(/\s+/g, ' ').trim(),
  locales: ['en-GB'],
};

/**
 * Declassification and handling instructions.
 *
 * Present in the same header block as the banner and carrying dates that are
 * themselves sometimes sensitive. Detected so a release workflow can check that
 * the block was updated rather than copied from the source document.
 */
const declassInstruction: PatternRule = {
  id: 'marking.declassification',
  type: 'marking.banner',
  pattern:
    /\b(?:Declassify On|Classified By|Derived From|Reason|Downgrade To|Declassification Date)\s*:\s*[^\n]{1,120}/gi,
  baseConfidence: Confidence.STRONG,
  description: 'a classification authority or declassification instruction',
  normalize: (value) => value.replace(/\s+/g, ' ').trim(),
};

/**
 * Distribution and handling caveats that appear without a banner.
 *
 * Common in corporate and legal documents that have no formal classification
 * scheme but do have a disclosure expectation the engine should respect.
 */
const handlingCaveat: PatternRule = {
  id: 'marking.handling-caveat',
  type: 'marking.banner',
  pattern:
    /\b(?:ATTORNEY[- ](?:CLIENT PRIVILEGE|WORK PRODUCT)|PRIVILEGED AND CONFIDENTIAL|COMMERCIAL[- ]IN[- ]CONFIDENCE|PROPRIETARY AND CONFIDENTIAL|INTERNAL USE ONLY|NOT FOR (?:PUBLIC )?(?:DISTRIBUTION|RELEASE)|EMBARGOED(?: UNTIL [^\n]{1,40})?|DRAFT[- ]{1,3}(?:DO NOT (?:CITE|QUOTE|DISTRIBUTE)))\b/gi,
  baseConfidence: Confidence.STRONG,
  description: 'a handling caveat asserting a disclosure restriction',
  normalize: (value) => value.toUpperCase().replace(/\s+/g, ' ').trim(),
};

export const markingsPack: PatternPack = {
  id: 'markings',
  version: '1.0.0',
  rules: [
    usBanner,
    usPortion,
    natoBanner,
    ukBanner,
    declassInstruction,
    handlingCaveat,
  ] satisfies PatternRule[],
};

export const markingRules = {
  usBanner,
  usPortion,
  natoBanner,
  ukBanner,
  declassInstruction,
  handlingCaveat,
};
