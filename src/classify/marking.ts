/**
 * Rendering and parsing of marking strings.
 *
 * Rendering is the easy direction. Parsing matters more: a document that
 * already carries markings is asserting something about itself, and the engine
 * needs to read that assertion in order to disagree with it.
 */

import type { CompiledPolicy } from './lattice.js';
import { applyDomination } from './lattice.js';
import type { Assertion, GroupId, MarkingId } from './types.js';

/** How a marking is being written. */
export type MarkingStyle =
  /** Full banner line for the top and bottom of a page. */
  | 'banner'
  /** Compact parenthesised form that prefixes a paragraph. */
  | 'portion';

/**
 * Render an assertion as a marking string.
 *
 * Groups render in policy order and are omitted entirely when empty, so an
 * unmarked CONFIDENTIAL document renders as `CONFIDENTIAL` and not as
 * `CONFIDENTIAL////`.
 */
export function renderMarking(
  policy: CompiledPolicy,
  assertion: Assertion,
  style: MarkingStyle = 'banner',
): string {
  const format = policy.policy.banner;
  const level = policy.level(assertion.level);
  const head = style === 'banner' && format.bannerUsesFullName ? level.name : level.abbreviation;

  const segments: string[] = [head];
  for (const group of policy.groups) {
    const values = assertion.markings[group.id];
    if (values === undefined || values.length === 0) continue;
    const rendered = values
      .map((id) => {
        const value = policy.markingValue(id);
        return style === 'banner' ? value.name : value.abbreviation;
      })
      .join(group.valueSeparator);
    segments.push(`${group.prefix ?? ''}${rendered}${group.suffix ?? ''}`);
  }

  const body = segments.join(format.segmentSeparator);
  const cased = format.uppercase ? body.toUpperCase() : body;
  if (style === 'portion') {
    const [open, close] = format.portionDelimiters;
    return `${open}${cased}${close}`;
  }
  return cased;
}

/** What a parse produced, including the parts it could not account for. */
export interface ParsedMarking {
  readonly assertion: Assertion;
  /** Tokens that matched no level or marking in the policy. */
  readonly unrecognized: readonly string[];
  /** True when a level token was found; a marking with no level is suspect. */
  readonly hasExplicitLevel: boolean;
}

/** A dictionary entry the lexer can match. */
interface Lexeme {
  readonly text: string;
  readonly kind: 'level' | 'marking' | 'affix';
  readonly id: string;
}

/**
 * Characters that separate markings but never occur inside one.
 *
 * A hyphen is conspicuously absent: `OFFICIAL-SENSITIVE` and `ATTORNEY-CLIENT`
 * are single markings, and splitting on hyphens would shred them.
 */
const SEPARATOR = /[\s/,;()[\]]/;

/**
 * Parse a marking string against a policy.
 *
 * Implemented as a longest-match lexer rather than a split on separators. Real
 * marking grammars differ in ways a split cannot survive: US banners separate
 * segments with `//`, the UK uses spaces and square brackets, and values are
 * routinely multi-word (`TOP SECRET`, `UK EYES ONLY`, `REL TO`). Matching the
 * longest known token at each position handles all of them with one pass and no
 * per-policy special cases.
 *
 * Deliberately tolerant. Markings in real documents are inconsistently spaced,
 * abbreviated in mixed styles, and occasionally wrapped by a PDF text extractor
 * mid-token. Anything not recognised is reported in `unrecognized` rather than
 * dropped, so a reviewer sees that the engine did not understand a segment
 * instead of assuming it was absent.
 */
export function parseMarking(policy: CompiledPolicy, input: string): ParsedMarking {
  const lexemes = buildLexicon(policy);
  const text = normalizeToken(stripPortionDelimiters(policy, input));

  let level = policy.bottom.id;
  let hasExplicitLevel = false;
  const collected = new Map<GroupId, MarkingId[]>();
  const unrecognized: string[] = [];

  let pos = 0;
  while (pos < text.length) {
    if (SEPARATOR.test(text[pos]!)) {
      pos++;
      continue;
    }

    const matched = longestMatchAt(lexemes, text, pos);
    if (matched === undefined) {
      const end = findSeparator(text, pos);
      const token = text.slice(pos, end).trim();
      if (token.length > 0) unrecognized.push(token);
      pos = end;
      continue;
    }

    if (matched.kind === 'level') {
      // Keep the highest level mentioned. A trailing lower level is either a
      // downgrade instruction or an extraction artefact; neither should lower
      // what the engine believes about the document.
      if (!hasExplicitLevel || policy.level(matched.id).rank > policy.level(level).rank) {
        level = matched.id;
      }
      hasExplicitLevel = true;
    } else if (matched.kind === 'marking') {
      const groupId = policy.groupIdOf(matched.id);
      const bucket = collected.get(groupId);
      if (bucket) bucket.push(matched.id);
      else collected.set(groupId, [matched.id]);
    }
    // `affix` lexemes are group prefixes and suffixes; recognising them keeps
    // "REL TO" out of the unrecognised list without contributing a value.

    pos += matched.text.length;
  }

  const markings: Record<GroupId, readonly MarkingId[]> = {};
  for (const group of policy.groups) {
    const values = collected.get(group.id);
    if (values === undefined || values.length === 0) continue;
    const unique = new Set(values);
    markings[group.id] = group.values.filter((v) => unique.has(v.id)).map((v) => v.id);
  }

  return {
    assertion: applyDomination(policy, { level, markings }),
    unrecognized,
    hasExplicitLevel,
  };
}

function stripPortionDelimiters(policy: CompiledPolicy, input: string): string {
  const [open, close] = policy.policy.banner.portionDelimiters;
  const trimmed = input.trim();
  if (open.length > 0 && trimmed.startsWith(open) && trimmed.endsWith(close)) {
    return trimmed.slice(open.length, trimmed.length - close.length).trim();
  }
  return trimmed;
}

/**
 * Build the lexicon, longest first.
 *
 * Order matters: `TOP SECRET` must be offered before `SECRET`, or every
 * TOP SECRET banner parses as SECRET and the engine silently under-reports the
 * most sensitive documents it will ever see.
 */
function buildLexicon(policy: CompiledPolicy): readonly Lexeme[] {
  const lexemes: Lexeme[] = [];

  for (const level of policy.levels) {
    lexemes.push({ text: normalizeToken(level.name), kind: 'level', id: level.id });
    if (level.abbreviation !== level.name) {
      lexemes.push({ text: normalizeToken(level.abbreviation), kind: 'level', id: level.id });
    }
  }

  for (const group of policy.groups) {
    for (const value of group.values) {
      lexemes.push({ text: normalizeToken(value.name), kind: 'marking', id: value.id });
      if (value.abbreviation !== value.name) {
        lexemes.push({ text: normalizeToken(value.abbreviation), kind: 'marking', id: value.id });
      }
    }
    for (const affix of [group.prefix, group.suffix]) {
      const normalized = normalizeToken(affix ?? '');
      if (normalized.length > 0) lexemes.push({ text: normalized, kind: 'affix', id: group.id });
    }
  }

  return lexemes
    .filter((l) => l.text.length > 0)
    .sort((a, b) => b.text.length - a.text.length || a.text.localeCompare(b.text));
}

/**
 * Longest lexeme matching at `pos`, requiring a separator or end of input
 * afterwards so `S` does not match the first letter of `SECRET`.
 */
function longestMatchAt(
  lexemes: readonly Lexeme[],
  text: string,
  pos: number,
): Lexeme | undefined {
  for (const lexeme of lexemes) {
    if (!text.startsWith(lexeme.text, pos)) continue;
    const after = pos + lexeme.text.length;
    if (after < text.length && !SEPARATOR.test(text[after]!)) continue;
    return lexeme;
  }
  return undefined;
}

function findSeparator(text: string, from: number): number {
  for (let i = from; i < text.length; i++) {
    if (SEPARATOR.test(text[i]!)) return i;
  }
  return text.length;
}

/** Uppercase and collapse internal whitespace, preserving structural punctuation. */
function normalizeToken(token: string): string {
  return token.toUpperCase().replace(/\s+/g, ' ').trim();
}

/**
 * Compare a marking a document carries against the one its content warrants.
 *
 * Both directions are reported because both are real failures with opposite
 * consequences: under-marking releases information that should have been held,
 * and over-marking withholds information that should have been released, which
 * is the failure mode that erodes trust in a disclosure process.
 */
export interface MarkingComparison {
  readonly declared: Assertion;
  readonly derived: Assertion;
  /** The content requires more protection than the document claims. */
  readonly underMarked: boolean;
  /** The document claims more protection than its content requires. */
  readonly overMarked: boolean;
  /** Levels and markings present in `derived` but missing from `declared`. */
  readonly missing: readonly string[];
  /** Markings present in `declared` but unsupported by any portion. */
  readonly unsupported: readonly string[];
}
