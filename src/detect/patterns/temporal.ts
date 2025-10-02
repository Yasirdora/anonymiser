/**
 * Dates, times, and monetary amounts.
 *
 * These are the quiet leaks. None of them names a person, and every one of them
 * narrows who a document could be about:
 *
 * - **Dates.** HIPAA's Safe Harbor method requires every date element more
 *   specific than a year to be removed -- admission, discharge, birth, death,
 *   and the date of any event. An incident date plus a city is often enough to
 *   find the record in a public log.
 * - **Dates hidden inside identifiers.** A trace id like
 *   `ERR_20260902_AUTH_BYPASS` carries the incident date in a form no date rule
 *   sees, because it never looks like a date. Redacting the visible date and
 *   leaving this one accomplishes nothing.
 * - **Amounts.** A transaction value is a join key. Combined with a date it
 *   picks one row out of a ledger, which is precisely how a "de-identified"
 *   financial extract gets re-identified.
 *
 * All three are prone to false positives in ordinary prose, so the rules here
 * lean on labels and shape rather than firing on every number.
 */

import type { PatternPack, PatternRule } from '../pattern.js';
import { Confidence } from '../types.js';

const MONTH = '(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)[a-z]*\\.?';

/**
 * A written-out calendar date.
 *
 * Distinctive enough to stand without a label: `September 1, 2026` and
 * `2026-09-01` are dates and nothing else.
 */
const writtenDate: PatternRule = {
  id: 'temporal.date',
  type: 'temporal.date',
  pattern: new RegExp(
    // Alternation order matters: the full instant has to be offered before the
    // bare date, or `2026-09-02T13:45:11Z` matches as `2026-09-02` and the time
    // is left standing in the document.
    `(?<![\\d/-])(?:\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}(?::\\d{2})?(?:\\.\\d+)?(?:Z|[+-]\\d{2}:?\\d{2})?` +
    `|${MONTH}\\s+\\d{1,2}(?:st|nd|rd|th)?,?\\s+\\d{4}` +
    `|\\d{1,2}(?:st|nd|rd|th)?\\s+${MONTH},?\\s+\\d{4}` +
    // The dd-MMM-yyyy form used by clinical and banking systems: 12-MAR-2011.
    `|\\d{1,2}[-/]${MONTH}[-/]\\d{2,4}` +
    `|\\d{4}-(?:0[1-9]|1[0-2])-(?:0[1-9]|[12]\\d|3[01]))(?![\\d/-])`,
    'gi',
  ),
  baseConfidence: Confidence.LIKELY,
  description: 'a calendar date, which HIPAA Safe Harbor requires be reduced to the year',
  normalize: (value) => value.toLowerCase().replace(/\s+/g, ' ').replace(/[.,]/g, ''),
};

/**
 * A numeric date.
 *
 * `08/29` and `1/2/26` are also version numbers, ratios, and page ranges, so a
 * nearby cue is required. The unlabelled four-digit-year form is admitted on
 * shape alone.
 */
const numericDate: PatternRule = {
  id: 'temporal.date.numeric',
  type: 'temporal.date',
  pattern: /(?<![\d/.-])\d{1,2}[/.-]\d{1,2}[/.-]\d{4}(?![\d/.-])/g,
  baseConfidence: Confidence.LIKELY,
  description: 'a numeric calendar date',
  normalize: (value) => value.replace(/[.-]/g, '/'),
};

/**
 * A date embedded in an identifier.
 *
 * Matched as a group inside a longer token, so the surrounding identifier is
 * reported with it: the whole `ERR_20260902_AUTH_BYPASS_NULL_POINTER` is the
 * finding, because redacting eight digits out of the middle of it would leave a
 * string that still says when the incident happened.
 */
const embeddedDate: PatternRule = {
  id: 'temporal.date.embedded',
  type: 'temporal.date',
  pattern: /\b[A-Za-z][A-Za-z0-9]*[_-](?:20|19)\d{2}(?:0[1-9]|1[0-2])(?:0[1-9]|[12]\d|3[01])[_-][A-Za-z0-9_-]{1,64}\b/g,
  baseConfidence: Confidence.STRONG,
  description: 'an identifier with a date encoded inside it',
  normalize: (value) => value.toUpperCase(),
};

/** A clock time, which narrows an event further than the date alone. */
const timestamp: PatternRule = {
  id: 'temporal.time',
  type: 'temporal.date',
  pattern: /(?<![\d:])(?:[01]?\d|2[0-3]):[0-5]\d(?::[0-5]\d)?(?:\s?(?:AM|PM|am|pm))?(?:\s?(?:UTC|GMT|Z|[+-]\d{2}:?\d{2}))?(?![\d:])/g,
  baseConfidence: Confidence.WEAK,
  description: 'a time of day',
  normalize: (value) => value.toLowerCase().replace(/\s+/g, ''),
  context: {
    supports: ['at', 'time', 'timestamp', 'occurred', 'logged', 'failed', 'started', 'incident'],
    requireSupport: true,
  },
};

/**
 * A monetary amount with an explicit currency.
 *
 * The symbol or code is required. Bare numbers with two decimal places are
 * everywhere in a technical document -- versions, coordinates, measurements --
 * and matching them would bury the real amounts.
 */
const currencyAmount: PatternRule = {
  id: 'financial.amount',
  type: 'financial.amount',
  pattern:
    /(?:[$£€¥₹]\s?\d{1,3}(?:,\d{3})*(?:\.\d{1,2})?|\d{1,3}(?:,\d{3})*(?:\.\d{1,2})?\s?(?:USD|EUR|GBP|CHF|JPY|CAD|AUD|INR))(?![\d])/g,
  baseConfidence: Confidence.STRONG,
  description: 'a monetary amount, which joins a record to a ledger row',
  normalize: (value) => value.replace(/\s+/g, ''),
};

/**
 * A locality: city and administrative division.
 *
 * HIPAA Safe Harbor removes every geographic subdivision below the state, so
 * the city half of an address is an identifier in its own right. Redacting the
 * street line and leaving "Springfield, OR" behind is a partial redaction that
 * still places the person.
 */
const US_STATES =
  'A[LKZR]|C[AOT]|D[EC]|FL|GA|HI|I[ADLN]|K[SY]|LA|M[ADEINOST]|N[CDEHJMVY]|O[HKR]|PA|RI|S[CD]|TN|TX|UT|V[AT]|W[AIVY]';

const cityState: PatternRule = {
  id: 'geo.locality.us',
  type: 'geo.locality',
  pattern: new RegExp(
    `\\b([A-Z][a-z]+(?:[ -][A-Z][a-z]+){0,2}),\\s*(?:${US_STATES})\\b\\.?(?=\\s|$|,)`,
    'g',
  ),
  baseConfidence: Confidence.LIKELY,
  description: 'a city and state, which places a person below the level Safe Harbor permits',
  normalize: (value) => value.toLowerCase().replace(/\s+/g, ' ').replace(/\.$/, ''),
  locales: ['en-US'],
};

/** A locality following an explicit address label, in any format. */
const labelledLocality: PatternRule = {
  id: 'geo.locality.labelled',
  type: 'geo.locality',
  pattern:
    /(?:City|Town|Locality|Municipality|Place\s+of\s+(?:birth|residence))[^\S\n]{0,4}[:#=][^\S\n]{0,4}([A-Z][A-Za-z' -]{2,40})/g,
  group: 1,
  baseConfidence: Confidence.STRONG,
  description: 'a place the document labels as a city or locality',
  normalize: (value) => value.toLowerCase().trim(),
};

/**
 * A city named in an address line.
 *
 * The US `City, ST` rule cannot see `128 Piccadilly, London, W1J 7JZ`. This one
 * anchors on the postcode or country that follows instead, which is how most of
 * the world writes an address.
 */
const cityBeforePostcode: PatternRule = {
  id: 'geo.locality.before-postcode',
  type: 'geo.locality',
  pattern:
    /,\s*([A-Z][a-z]+(?:[ -][A-Z][a-z]+){0,2})\s*,\s*(?=[A-Z]{1,2}\d[A-Z\d]?\s?\d[A-Z]{2}\b|\d{4,5}\b|[A-Z][a-z]+\s+(?:Kingdom|States)\b)/g,
  group: 1,
  baseConfidence: Confidence.LIKELY,
  description: 'a city named immediately before a postcode or country in an address',
  normalize: (value) => value.toLowerCase().trim(),
};

export const temporalPack: PatternPack = {
  id: 'temporal',
  version: '1.0.0',
  rules: [
    embeddedDate,
    writtenDate,
    numericDate,
    timestamp,
    currencyAmount,
    cityState,
    cityBeforePostcode,
    labelledLocality,
  ] satisfies PatternRule[],
};

export const temporalRules = {
  writtenDate,
  numericDate,
  embeddedDate,
  timestamp,
  currencyAmount,
  cityState,
  cityBeforePostcode,
  labelledLocality,
};
