/**
 * Government-issued and personal identifiers.
 *
 * Every rule with a published check digit uses it. The remainder require
 * context, because an unvalidated run of digits is not evidence of anything.
 */

import type { PatternPack, PatternRule } from '../pattern.js';
import { Confidence } from '../types.js';
import { isPlaceholder, mrzCheckDigit, stripSeparators, ukNino, usSsn } from '../validators.js';

/** The hyphenated form is unambiguous enough to stand without context. */
const ssnFormatted: PatternRule = {
  id: 'gov.ssn.us.formatted',
  type: 'gov.ssn',
  pattern: /(?<![\d-])\d{3}-\d{2}-\d{4}(?![\d-])/g,
  baseConfidence: Confidence.STRONG,
  description: 'a US Social Security Number in AAA-GG-SSSS form',
  validate: (value) =>
    usSsn(value)
      ? { ok: true, signal: 'structure:ssn-blocks', note: 'area, group, and serial blocks are all issuable', weight: 0.14 }
      : { ok: false, signal: 'structure:ssn-blocks', note: 'contains a block the SSA never issues' },
  normalize: (value) => stripSeparators(value),
  locales: ['en-US'],
};

/**
 * The unformatted form is nine digits and nothing more, which collides with
 * account numbers, part numbers, and phone numbers, so a nearby label is
 * mandatory rather than merely helpful.
 */
const ssnBare: PatternRule = {
  id: 'gov.ssn.us.bare',
  type: 'gov.ssn',
  pattern: /(?<![\d-])\d{9}(?![\d-])/g,
  baseConfidence: Confidence.WEAK,
  description: 'nine digits labelled as a US Social Security Number',
  validate: (value) =>
    usSsn(value)
      ? { ok: true, signal: 'structure:ssn-blocks', note: 'blocks are consistent with an issuable SSN', weight: 0.2 }
      : { ok: false, signal: 'structure:ssn-blocks', note: 'contains a block the SSA never issues' },
  normalize: (value) => value,
  context: {
    supports: ['ssn', 'social security', 'soc sec', 'ss#', 'ssa', 'tin', 'taxpayer'],
    suppresses: ['phone', 'zip', 'account', 'invoice', 'routing'],
    requireSupport: true,
  },
  locales: ['en-US'],
};

const usItin: PatternRule = {
  id: 'gov.tax-id.us.itin',
  type: 'gov.tax-id',
  pattern: /(?<![\d-])9\d{2}-(?:5\d|6[0-5]|7\d|8[0-8]|9[0-2]|9[4-9])-\d{4}(?![\d-])/g,
  baseConfidence: Confidence.STRONG,
  description: 'a US Individual Taxpayer Identification Number',
  normalize: (value) => stripSeparators(value),
  locales: ['en-US'],
};

const usEin: PatternRule = {
  id: 'gov.tax-id.us.ein',
  type: 'gov.tax-id',
  pattern: /(?<![\d-])\d{2}-\d{7}(?![\d-])/g,
  baseConfidence: Confidence.WEAK,
  description: 'a US Employer Identification Number',
  normalize: (value) => stripSeparators(value),
  context: {
    supports: ['ein', 'employer identification', 'federal tax', 'fein', 'tax id'],
    requireSupport: true,
  },
  locales: ['en-US'],
};

const ukNationalInsurance: PatternRule = {
  id: 'gov.national-id.uk.nino',
  type: 'gov.national-id',
  pattern: /(?<![A-Z0-9])[A-CEGHJ-PR-TW-Z][A-CEGHJ-NPR-TW-Z]\s?\d{2}\s?\d{2}\s?\d{2}\s?[A-D](?![A-Z0-9])/gi,
  baseConfidence: Confidence.STRONG,
  description: 'a UK National Insurance number',
  validate: (value) =>
    ukNino(value)
      ? { ok: true, signal: 'structure:nino-prefix', note: 'prefix and suffix letters are in the issued set', weight: 0.14 }
      : { ok: false, signal: 'structure:nino-prefix', note: 'uses a prefix HMRC does not issue' },
  normalize: (value) => stripSeparators(value).toUpperCase(),
  locales: ['en-GB'],
};

/**
 * Passport numbers have no checksum and no globally consistent format, so
 * this is a shape rule gated entirely on context.
 */
const passport: PatternRule = {
  id: 'gov.passport',
  type: 'gov.passport',
  pattern: /(?<![A-Z0-9])[A-Z]{0,2}\d{6,9}(?![A-Z0-9])/g,
  baseConfidence: Confidence.HINT,
  description: 'an identifier labelled as a passport number',
  validate: (value) =>
    isPlaceholder(value)
      ? { ok: false, signal: 'structure:placeholder', note: 'repeating characters indicate a template value' }
      : { ok: true, signal: 'structure:shape', note: 'length and character mix are consistent with a passport number', weight: 0.05 },
  normalize: (value) => value.toUpperCase(),
  context: {
    supports: ['passport', 'travel document', 'document no', 'document number', 'mrz'],
    requireSupport: true,
    supportWeight: 0.35,
  },
};

/**
 * ICAO 9303 TD3 machine-readable zone: two 44-character lines.
 *
 * The MRZ is the single richest disclosure in a scanned identity document. It
 * carries name, nationality, date of birth, sex, document number, and expiry in
 * one block, and it survives OCR far better than the printed page, so it is
 * both easy to miss visually and trivial to extract mechanically.
 */
const MRZ_TD3 = /(?<![A-Z0-9<])P[A-Z<][A-Z]{3}[A-Z0-9<]{39}\r?\n[A-Z0-9<]{44}(?![A-Z0-9<])/g;

const mrz: PatternRule = {
  id: 'gov.mrz.td3',
  type: 'gov.mrz',
  pattern: MRZ_TD3,
  baseConfidence: Confidence.STRONG,
  description: 'a passport machine-readable zone carrying name, nationality, and document number',
  validate(value) {
    const second = value.split(/\r?\n/)[1];
    if (second === undefined || second.length !== 44) {
      return { ok: false, signal: 'structure:mrz-length', note: 'second MRZ line is not 44 characters' };
    }
    // Document number occupies positions 0-8, its check digit position 9.
    const ok = mrzCheckDigit(second.slice(0, 9), second[9]!);
    return ok
      ? { ok: true, signal: 'checksum:icao9303', note: 'document number check digit is correct', weight: 0.14 }
      : { ok: false, signal: 'checksum:icao9303', note: 'document number check digit does not match' };
  },
  normalize: (value) => value.replace(/\s+/g, ''),
};

/**
 * US driver licence formats are set per state and overlap heavily with ordinary
 * alphanumeric codes, so context is required.
 */
const driverLicense: PatternRule = {
  id: 'gov.driver-license',
  type: 'gov.driver-license',
  pattern: /(?<![A-Z0-9])[A-Z]{1,2}[- ]?\d{4,12}(?![A-Z0-9])/g,
  baseConfidence: Confidence.HINT,
  description: 'an identifier labelled as a driver licence number',
  normalize: (value) => stripSeparators(value).toUpperCase(),
  context: {
    supports: ['driver', 'licence', 'license', 'dl no', 'dl#', 'dln', 'operator permit'],
    requireSupport: true,
    supportWeight: 0.35,
  },
};

/**
 * Dates of birth.
 *
 * Matched only when labelled. Under HIPAA's Safe Harbor method a date of birth
 * is a direct identifier that must be removed regardless of how ordinary it
 * looks, which is exactly why it is so often left in place.
 */
const dateOfBirth: PatternRule = {
  id: 'person.dob',
  type: 'person.dob',
  pattern:
    /(?<![\d/-])(?:\d{1,2}[/.-]\d{1,2}[/.-]\d{2,4}|\d{4}-\d{2}-\d{2}|\d{1,2}\s+(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)[a-z]*\.?,?\s+\d{4})(?![\d/-])/gi,
  baseConfidence: Confidence.WEAK,
  description: 'a date presented as a date of birth',
  normalize: (value) => value.replace(/\s+/g, ' ').toLowerCase(),
  context: {
    supports: ['dob', 'date of birth', 'born', 'birth date', 'birthdate', 'birthday', 'd.o.b'],
    requireSupport: true,
    supportWeight: 0.4,
  },
};

/**
 * A number sitting behind an unambiguous label.
 *
 * The checksum rules above drop a value whose check digit fails, which is right
 * when the shape alone is the only evidence: a nine-digit number that fails the
 * SSA block rules is probably something else.
 *
 * It is exactly wrong when the document says what the number is. `Tax ID / SSN:
 * 000-12-3456` is an SSN by declaration, and area 000 being unissuable makes it
 * a *test* SSN, not a different kind of value. Refusing to redact it because it
 * failed a validity check inverts the whole point of the tool -- and a redaction
 * engine that quietly skips the field literally labelled SSN is worse than no
 * engine at all.
 *
 * So the label wins. When one of these appears, the value is redacted whatever
 * its check digit says.
 */
const ssnLabelled: PatternRule = {
  id: 'gov.ssn.us.labelled',
  type: 'gov.ssn',
  pattern: /(?:SSN|S\.S\.N|Social\s+Security(?:\s+(?:Number|No\.?|#))?|Tax\s?ID(?:\s*\/\s*SSN)?)[^\S\n]{0,4}[:#=]?[^\S\n]{0,4}(\d{3}[- ]?\d{2}[- ]?\d{4})(?![\d-])/gi,
  group: 1,
  baseConfidence: Confidence.VERIFIED,
  description: 'a number the document itself labels as a Social Security or tax number',
  normalize: (value) => stripSeparators(value),
};

const nationalIdLabelled: PatternRule = {
  id: 'gov.national-id.labelled',
  type: 'gov.national-id',
  pattern: /(?:National\s+(?:ID|Insurance)|NRIC|Aadhaar|CPF|SIN|Personnummer|Fiscal\s+Code)[^\S\n]{0,4}(?:Number|No\.?|#)?[^\S\n]{0,4}[:#=][^\S\n]{0,4}([A-Z0-9][A-Z0-9 .-]{4,24}[A-Z0-9])/gi,
  group: 1,
  baseConfidence: Confidence.STRONG,
  description: 'a number the document labels as a national identifier',
  normalize: (value) => stripSeparators(value).toUpperCase(),
};

export const identityPack: PatternPack = {
  id: 'identity',
  version: '1.0.0',
  rules: [
    ssnLabelled,
    nationalIdLabelled,
    ssnFormatted,
    ssnBare,
    usItin,
    usEin,
    ukNationalInsurance,
    passport,
    mrz,
    driverLicense,
    dateOfBirth,
  ] satisfies PatternRule[],
};

export const identityRules = {
  ssnLabelled,
  nationalIdLabelled,
  ssnFormatted,
  ssnBare,
  usItin,
  usEin,
  ukNationalInsurance,
  passport,
  mrz,
  driverLicense,
  dateOfBirth,
};
