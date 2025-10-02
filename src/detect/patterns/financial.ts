/**
 * Financial identifiers.
 *
 * Payment cards, bank accounts, and routing numbers nearly all carry check
 * digits, which makes this the pack with the fewest false positives and the
 * strongest case for automatic redaction without human review.
 */

import type { PatternPack, PatternRule } from '../pattern.js';
import { Confidence } from '../types.js';
import { abaRouting, iban, isPlaceholder, luhn, stripSeparators } from '../validators.js';

/**
 * Issuer Identification Numbers, longest prefix first so the match is specific.
 *
 * Brand identification is not decoration: policies frequently treat a card
 * number as PCI-DSS cardholder data only when it resolves to a real scheme, and
 * the brand is recorded on the finding for the audit trail.
 */
const IIN_RANGES: ReadonlyArray<readonly [RegExp, string]> = [
  [/^4\d{12}(?:\d{3})?(?:\d{3})?$/, 'visa'],
  [/^(?:5[1-5]\d{14}|2(?:22[1-9]|2[3-9]\d|[3-6]\d{2}|7[01]\d|720)\d{12})$/, 'mastercard'],
  [/^3[47]\d{13}$/, 'amex'],
  [/^3(?:0[0-5]|[68]\d)\d{11}$/, 'diners'],
  [/^6(?:011|5\d{2}|4[4-9]\d)\d{12}$/, 'discover'],
  [/^(?:2131|1800|35\d{3})\d{11}$/, 'jcb'],
  [/^62\d{14,17}$/, 'unionpay'],
];

function cardBrand(digits: string): string | undefined {
  for (const [pattern, brand] of IIN_RANGES) {
    if (pattern.test(digits)) return brand;
  }
  return undefined;
}

/**
 * Payment card numbers, 13 to 19 digits with optional space or hyphen grouping.
 *
 * Luhn alone admits roughly one in ten random digit strings of the right
 * length, so a recognised issuer prefix is required as well. Together the two
 * checks make a false positive rare enough to redact on sight.
 */
const card: PatternRule = {
  id: 'financial.card',
  type: 'financial.card',
  pattern: /(?<![\d-])(?:\d[ -]?){11,18}\d(?![\d-])/g,
  baseConfidence: Confidence.LIKELY,
  description: 'a payment card number',
  validate(value) {
    const digits = stripSeparators(value);
    if (digits.length < 13 || digits.length > 19) {
      return { ok: false, signal: 'structure:pan-length', note: 'not between 13 and 19 digits' };
    }
    if (!luhn(digits)) {
      return { ok: false, signal: 'checksum:luhn', note: 'fails the Luhn check digit' };
    }
    if (cardBrand(digits) === undefined) {
      return { ok: false, signal: 'structure:iin', note: 'leading digits match no issuing scheme' };
    }
    return { ok: true, signal: 'checksum:luhn+iin', note: 'passes Luhn and matches a known issuer range', weight: 0.34 };
  },
  normalize: (value) => stripSeparators(value),
  context: {
    suppresses: ['isbn', 'imei', 'tracking', 'shipment'],
  },
};

const ibanRule: PatternRule = {
  id: 'financial.iban',
  type: 'financial.iban',
  pattern: /(?<![A-Z0-9])[A-Z]{2}\d{2}[ ]?(?:[A-Z0-9]{4}[ ]?){2,7}[A-Z0-9]{1,4}(?![A-Z0-9])/g,
  baseConfidence: Confidence.LIKELY,
  description: 'an International Bank Account Number',
  validate: (value) =>
    iban(value)
      ? { ok: true, signal: 'checksum:iso13616', note: 'passes the mod-97 check and matches the country length', weight: 0.34 }
      : { ok: false, signal: 'checksum:iso13616', note: 'fails the mod-97 check or has the wrong length for its country' },
  normalize: (value) => stripSeparators(value).toUpperCase(),
};

const routing: PatternRule = {
  id: 'financial.routing.aba',
  type: 'financial.routing',
  pattern: /(?<![\d-])\d{9}(?![\d-])/g,
  baseConfidence: Confidence.HINT,
  description: 'a US ABA routing transit number',
  validate: (value) =>
    abaRouting(value)
      ? { ok: true, signal: 'checksum:aba', note: 'passes the ABA weighted checksum', weight: 0.3 }
      : { ok: false, signal: 'checksum:aba', note: 'fails the ABA weighted checksum' },
  normalize: (value) => value,
  context: {
    supports: ['routing', 'aba', 'rtn', 'ach', 'wire', 'transit', 'bank'],
    requireSupport: true,
    supportWeight: 0.3,
  },
  locales: ['en-US'],
};

const swift: PatternRule = {
  id: 'financial.swift-bic',
  type: 'financial.account',
  pattern: /(?<![A-Z0-9])[A-Z]{4}[A-Z]{2}[A-Z0-9]{2}(?:[A-Z0-9]{3})?(?![A-Z0-9])/g,
  baseConfidence: Confidence.WEAK,
  description: 'a SWIFT/BIC bank identifier code',
  normalize: (value) => value.toUpperCase(),
  context: {
    supports: ['swift', 'bic', 'iban', 'beneficiary', 'correspondent', 'remit'],
    requireSupport: true,
  },
};

/**
 * Generic bank account numbers.
 *
 * No checksum exists across jurisdictions, so this is context-only and lands
 * low enough that it is surfaced for review rather than redacted automatically.
 */
const account: PatternRule = {
  id: 'financial.account.generic',
  type: 'financial.account',
  pattern: /(?<![\d-])\d{6,17}(?![\d-])/g,
  baseConfidence: Confidence.HINT,
  description: 'a number labelled as a bank account',
  validate: (value) =>
    isPlaceholder(value)
      ? { ok: false, signal: 'structure:placeholder', note: 'repeating digits indicate a template value' }
      : { ok: true, signal: 'structure:shape', note: 'length is consistent with an account number', weight: 0.05 },
  normalize: (value) => value,
  context: {
    supports: ['account', 'acct', 'a/c', 'iban', 'sort code', 'deposit', 'checking', 'savings'],
    suppresses: ['invoice', 'order', 'quantity', 'total', 'amount', 'phone', 'zip', 'postcode'],
    requireSupport: true,
    supportWeight: 0.3,
  },
};

/**
 * Cryptocurrency addresses.
 *
 * Bech32 and hex forms are distinctive enough to stand alone; the legacy
 * base58 form is constrained by its alphabet, which excludes the characters
 * most likely to appear in an ordinary word.
 */
const cryptoAddress: PatternRule = {
  id: 'financial.crypto-address',
  type: 'financial.crypto-address',
  pattern:
    /(?<![A-Za-z0-9])(?:bc1[a-z0-9]{25,62}|[13][1-9A-HJ-NP-Za-km-z]{25,34}|0x[a-fA-F0-9]{40}|[LM][1-9A-HJ-NP-Za-km-z]{26,33}|r[1-9A-HJ-NP-Za-km-z]{24,34}|4[0-9AB][1-9A-HJ-NP-Za-km-z]{93})(?![A-Za-z0-9])/g,
  baseConfidence: Confidence.LIKELY,
  description: 'a cryptocurrency wallet address',
  normalize: (value) => (value.startsWith('0x') ? value.toLowerCase() : value),
};

/**
 * Values behind an unambiguous financial label.
 *
 * Same reasoning as the labelled identity rules: when the document states what
 * a number is, the label outranks the check digit. `IBAN: US64SVBK...` is not a
 * valid IBAN -- the United States does not issue them -- but it is unarguably
 * the account number the writer meant, and skipping it because mod-97 failed is
 * how a bank detail survives into a published document.
 */
const ibanLabelled: PatternRule = {
  id: 'financial.iban.labelled',
  type: 'financial.iban',
  pattern: /(?:IBAN|International\s+Bank\s+Account)(?:\s*\/\s*\w+)?[^\S\n]{0,4}[:#=][^\S\n]{0,4}([A-Z]{2}[A-Z0-9 ]{10,40}[A-Z0-9])/gi,
  group: 1,
  baseConfidence: Confidence.VERIFIED,
  description: 'a value the document labels as an IBAN or international account number',
  normalize: (value) => stripSeparators(value).toUpperCase(),
};

const accountLabelled: PatternRule = {
  id: 'financial.account.labelled',
  type: 'financial.account',
  pattern: /(?:Account\s*(?:Number|No\.?|ID|#)|Acct\.?\s*(?:No\.?|#)?|A\/C)[^\S\n]{0,12}[:#=][^\S\n]{0,4}([A-Z0-9][A-Z0-9 .-]{3,30}[A-Z0-9])/gi,
  group: 1,
  baseConfidence: Confidence.STRONG,
  description: 'a value the document labels as an account number',
  normalize: (value) => stripSeparators(value).toUpperCase(),
};

/**
 * Card verification values.
 *
 * Three or four digits, meaningless in isolation and unmistakable behind their
 * label. PCI-DSS forbids storing them at all after authorisation, so a CVV in a
 * document is always a finding.
 */
const cvv: PatternRule = {
  id: 'financial.card.cvv',
  type: 'financial.card',
  pattern: /(?:CVV2?|CVC2?|CID|Security\s+Code|Card\s+Verification(?:\s+(?:Value|Code))?)(?:[^\S\n]{0,4}[:#=]|[^\n]{0,40}?\b(?:is|was)\b)[^\S\n]{0,4}(\d{3,4})(?!\d)/gi,
  group: 1,
  baseConfidence: Confidence.VERIFIED,
  description: 'a card verification value, which PCI-DSS forbids retaining at all',
  normalize: (value) => value,
};

/** Card expiry dates, which pair with a PAN to complete a usable card record. */
const cardExpiry: PatternRule = {
  id: 'financial.card.expiry',
  type: 'financial.card',
  pattern: /(?:Exp(?:iry|ires|iration)?\.?(?:\s*Date)?)[^\S\n]{0,12}(?:[:#=]|\bis\b)[^\S\n]{0,4}(\d{1,2}\s*[/-]\s*\d{2,4})(?![\d/-])/gi,
  group: 1,
  baseConfidence: Confidence.STRONG,
  description: 'a card expiry date',
  normalize: (value) => value.replace(/\s+/g, ''),
};

/**
 * Magnetic-stripe track data.
 *
 * `%B4532910087654321^OCONNOR/SIOBHAN^2811...?` is a full card record: number,
 * cardholder name, and expiry in one string. PCI-DSS forbids retaining it after
 * authorisation under any circumstances, and it survives redaction routinely
 * because it does not look like a card number to a rule expecting digit groups.
 */
const trackData: PatternRule = {
  id: 'financial.card.track',
  type: 'financial.card',
  pattern: /%?[A-Z]\d{12,19}\^[A-Z0-9 .\/'-]{2,60}\^\d{4,}[^\s?]{0,60}\??/g,
  baseConfidence: Confidence.VERIFIED,
  description: 'payment card magnetic-stripe track data, which PCI-DSS forbids retaining at all',
  normalize: (value) => value.toUpperCase(),
};

/**
 * A card number behind its label.
 *
 * The Luhn-plus-issuer rule above rejects a number whose check digit fails,
 * which is right on shape alone and wrong when the document names the field.
 * A mistyped or test PAN in a support ticket is still the field that has to go.
 */
const cardLabelled: PatternRule = {
  id: 'financial.card.labelled',
  type: 'financial.card',
  pattern:
    /(?:card\s*(?:number|no\.?|#)?|PAN|primary\s+account\s+number|visa|mastercard|amex|american\s+express)[^\S\n]{0,12}[:#=is][^\S\n]{0,4}((?:\d[ -]?){11,18}\d)(?![\d-])/gi,
  group: 1,
  baseConfidence: Confidence.VERIFIED,
  description: 'a number the document labels as a payment card',
  normalize: (value) => stripSeparators(value),
};

export const financialPack: PatternPack = {
  id: 'financial',
  version: '1.0.0',
  rules: [
    trackData, cardLabelled, ibanLabelled, accountLabelled, cvv, cardExpiry,
    card, ibanRule, routing, swift, account, cryptoAddress,
  ] satisfies PatternRule[],
};

export const financialRules = {
  card, iban: ibanRule, routing, swift, account, cryptoAddress,
  ibanLabelled, accountLabelled, cvv, cardExpiry, trackData, cardLabelled,
};

/** Exposed so callers can label a card finding without re-deriving the range. */
export { cardBrand };
