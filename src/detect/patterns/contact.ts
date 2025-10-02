/**
 * Contact identifiers: email, telephone, postal address, social handles.
 *
 * These are the highest-volume findings in almost every real document, so the
 * rules here lean on structural validation and context far more than shape.
 */

import { isPlaceholder, stripSeparators } from '../validators.js';
import type { PatternPack, PatternRule } from '../pattern.js';
import { Confidence } from '../types.js';

/**
 * Deliberately permissive in the local part and bounded in the domain.
 *
 * A fully RFC 5322-conformant expression is both unreadable and a backtracking
 * hazard; the shape is matched loosely here and the structure is checked in
 * `validate`, where the logic can be read and tested.
 */
const EMAIL_SHAPE = /[A-Za-z0-9!#$%&'*+/=?^_`{|}~.-]{1,64}@[A-Za-z0-9.-]{1,253}\.[A-Za-z]{2,24}/g;

const email: PatternRule = {
  id: 'contact.email',
  type: 'contact.email',
  pattern: EMAIL_SHAPE,
  baseConfidence: Confidence.STRONG,
  description: 'an email address',
  validate(value) {
    const at = value.lastIndexOf('@');
    const local = value.slice(0, at);
    const domain = value.slice(at + 1);
    const structural =
      local.length > 0 &&
      !local.startsWith('.') &&
      !local.endsWith('.') &&
      !local.includes('..') &&
      !domain.startsWith('-') &&
      !domain.includes('..') &&
      domain.split('.').every((label) => label.length > 0 && label.length <= 63);
    return structural
      ? { ok: true, signal: 'structure:rfc5322-subset', note: 'local and domain parts are well formed', weight: 0.1 }
      : { ok: false, signal: 'structure:rfc5322-subset', note: 'malformed local or domain part' };
  },
  normalize: (value) => value.toLowerCase(),
};

/**
 * A run of digits and separators, resolved by digit count rather than by shape.
 *
 * Telephone formats vary too widely across locales for a shape-based rule to be
 * both sensitive and precise, so this matches broadly and then applies the
 * E.164 length bounds. The suppression list carries the weight: order numbers,
 * invoice references, and case numbers all look like this.
 */
// The trailing group absorbs an extension, so `+44 20 7123 4567 ext 899` is one
// finding rather than a redacted number beside a bare `899`. An extension is
// part of how you reach the person and is useless to leave behind.
const PHONE_SHAPE = /(?<![\w+])\+?\d[\d\s().-]{5,18}\d(?:\s*(?:ext|extn|x|#)\.?\s*\d{1,6})?(?!\w)/gi;

const phone: PatternRule = {
  id: 'contact.phone',
  type: 'contact.phone',
  pattern: PHONE_SHAPE,
  baseConfidence: Confidence.WEAK,
  description: 'a telephone number',
  validate(value) {
    // A dotted quad is an address, not a number. Without this the rule reports
    // every IP in an incident report as a telephone number, which is both wrong
    // and worse than silence: the finding carries the wrong entity type into
    // classification and into the audit record.
    if (/^\d{1,3}(?:\.\d{1,3}){3}$/.test(value.trim())) {
      return { ok: false, signal: 'structure:dotted-quad', note: 'this is an IPv4 address, not a telephone number' };
    }
    // Likewise an SSN-shaped value: 3-2-4 with hyphens is never a phone number.
    if (/^\d{3}-\d{2}-\d{4}$/.test(value.trim())) {
      return { ok: false, signal: 'structure:ssn-shape', note: 'this is an SSN-shaped identifier, not a telephone number' };
    }
    // Measure the dialable number, not the extension digits appended to it.
    const digits = value.replace(/\s*(?:ext|extn|x|#)\.?\s*\d{1,6}\s*$/i, '').replace(/\D/g, '');
    if (digits.length < 7 || digits.length > 15) {
      return { ok: false, signal: 'structure:e164-length', note: 'digit count outside the 7-15 range E.164 allows' };
    }
    if (isPlaceholder(digits)) {
      return { ok: false, signal: 'structure:placeholder', note: 'repeating digits indicate a template value' };
    }
    // Fictional-use ranges reserved for documentation and drama.
    if (/^\+?1?555(?:01\d{2}|555\d{4})$/.test(digits)) {
      return { ok: false, signal: 'structure:reserved-range', note: 'a number in the 555-01xx range reserved for fiction' };
    }
    return { ok: true, signal: 'structure:e164-length', note: 'digit count is consistent with a dialable number', weight: 0.25 };
  },
  normalize: (value) => `+${value.replace(/\D/g, '')}`,
  context: {
    supports: [
      'phone', 'tel', 'telephone', 'mobile', 'cell', 'fax', 'contact', 'contactable',
      'call', 'reachable', 'reach', 'dial', 'hotline', 'switchboard', 'extension',
      'ext', 'whatsapp', 'sms', 'text',
    ],
    suppresses: ['invoice', 'order', 'ref', 'reference', 'case', 'docket', 'isbn', 'sku', 'part', 'serial', 'tracking'],
  },
};

/**
 * Street addresses, anchored on the thoroughfare suffix.
 *
 * Only the leading line is matched. Extending across the city and postcode
 * demands locale-specific ordering rules, and the postcode rules below already
 * cover the trailing component independently.
 */
const STREET_SHAPE =
  /\b\d{1,6}[A-Za-z]?\s+(?:[A-Z][A-Za-z'.-]{1,20}\s+){1,4}(?:Street|St|Avenue|Ave|Boulevard|Blvd|Road|Rd|Lane|Ln|Drive|Dr|Court|Ct|Place|Pl|Terrace|Ter|Way|Circle|Cir|Parkway|Pkwy|Square|Sq|Highway|Hwy)\b\.?/g;

const streetAddress: PatternRule = {
  id: 'contact.address.street',
  type: 'contact.address',
  pattern: STREET_SHAPE,
  baseConfidence: Confidence.LIKELY,
  description: 'a street address line',
  normalize: (value) => value.toLowerCase().replace(/\s+/g, ' ').trim(),
  locales: ['en'],
};

const PO_BOX_SHAPE = /\b(?:P\.?\s?O\.?\s?Box|Post\s+Office\s+Box)\s+\d{1,7}\b/gi;

const poBox: PatternRule = {
  id: 'contact.address.po-box',
  type: 'contact.address',
  pattern: PO_BOX_SHAPE,
  baseConfidence: Confidence.STRONG,
  description: 'a post office box',
  normalize: (value) => value.toLowerCase().replace(/[^a-z0-9]/g, ''),
  locales: ['en'],
};

/**
 * Social handles.
 *
 * Requires context because `@word` is also how people are mentioned in prose,
 * how email addresses begin, and how several markup languages sigil their
 * directives.
 */
const HANDLE_SHAPE = /(?<![\w@./])@[A-Za-z0-9_]{2,30}\b(?!\.[A-Za-z]{2,})/g;

const socialHandle: PatternRule = {
  id: 'contact.handle',
  type: 'contact.handle',
  pattern: HANDLE_SHAPE,
  baseConfidence: Confidence.WEAK,
  description: 'a social media handle',
  normalize: (value) => value.toLowerCase(),
  context: {
    supports: ['twitter', 'x', 'instagram', 'telegram', 'signal', 'handle', 'username', 'account', 'follow', 'mastodon', 'tiktok', 'github'],
    requireSupport: true,
  },
};

/** Uniform Resource Locators, including embedded credentials. */
const URL_SHAPE = /\bhttps?:\/\/[^\s<>"'`\]),]{4,2048}/g;

const url: PatternRule = {
  id: 'net.url',
  type: 'net.url',
  pattern: URL_SHAPE,
  baseConfidence: Confidence.STRONG,
  description: 'a web address',
  normalize: (value) => value.replace(/[.,;:)\]]+$/, '').toLowerCase(),
};

/**
 * A URL carrying credentials in its authority component.
 *
 * Separated from the general URL rule because the sensitivity is categorically
 * different: this is a live secret, not a location, and policies classify it as
 * such.
 */
const URL_CREDENTIALS_SHAPE = /\b[a-z][a-z0-9+.-]{1,20}:\/\/[^\s:/@]{1,64}:[^\s:/@]{1,128}@[^\s/]{1,253}/gi;

const urlCredentials: PatternRule = {
  id: 'secret.url-credentials',
  type: 'secret.password',
  pattern: URL_CREDENTIALS_SHAPE,
  baseConfidence: Confidence.VERIFIED,
  description: 'a URL with an embedded username and password',
};

/**
 * A whole address line behind its label.
 *
 * The thoroughfare rule above needs a suffix -- Street, Avenue, Road -- and much
 * of the world does not write one. `128 Piccadilly` and `Flat 4B` are addresses
 * with nothing for that rule to anchor on, and redacting the postcode while
 * leaving the street is a partial redaction that still finds the door.
 *
 * So when the document labels a line as an address, the line is the finding. The
 * capture stops before a postcode, which has its own rule and its own
 * classification.
 */
const labelledAddress: PatternRule = {
  id: 'contact.address.labelled',
  type: 'contact.address',
  pattern:
    // The negative lookbehind is load-bearing: "IP address", "MAC address", and
    // "email address" all contain the word and none of them introduces a postal
    // one. Without it the rule captured an IP address as a street.
    /(?<!\b(?:IP|IPv4|IPv6|MAC|email|e-mail|web|network|wallet|bitcoin|contract)\s)(?:home\s+|billing\s+|postal\s+|mailing\s+|street\s+|residential\s+)?address(?:es)?(?:\s+(?:is|are))?[^\S\n]{0,4}[:#=]?[^\S\n]{0,4}([^\n,]{3,60}(?:,[^\n,]{2,60}){0,3}?)(?=\s*,?\s*(?:[A-Z]{1,2}\d[A-Z\d]?\s?\d[A-Z]{2}\b|\d{5}(?:-\d{4})?\b|$|\.\s))/gi,
  group: 1,
  baseConfidence: Confidence.LIKELY,
  description: 'a line the document labels as a postal address',
  validate: (value) =>
    /\d/.test(value) || /\s/.test(value.trim())
      ? { ok: true, signal: 'structure:address-line', note: 'contains a number or several words, as an address does', weight: 0.15 }
      : { ok: false, signal: 'structure:address-line', note: 'a single word with no number is not an address line' },
  normalize: (value) => value.toLowerCase().replace(/\s+/g, ' ').trim(),
};

export const contactPack: PatternPack = {
  id: 'contact',
  version: '1.0.0',
  rules: [email, phone, labelledAddress, streetAddress, poBox, socialHandle, url, urlCredentials] satisfies PatternRule[],
};

/** Exported for tests and for callers assembling bespoke packs. */
export const contactRules = {
  email,
  phone,
  labelledAddress,
  streetAddress,
  poBox,
  socialHandle,
  url,
  urlCredentials,
};

/** Re-exported so pack authors can reuse the shared normalisation helper. */
export { stripSeparators };
