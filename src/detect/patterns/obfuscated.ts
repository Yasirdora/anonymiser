/**
 * Values written out in words.
 *
 * `four five three two, nine one zero zero, eight seven six five, four three
 * two one` is a payment card number. `three-eight-nine` is a CVV.
 * `Nine-Nine-Eight, Forty-Two, Zero-Zero-One-Nine` is a Social Security number.
 * None of them contains a digit, so no rule in any of the other packs can see
 * them, and they survive every redaction tool in the ecosystem.
 *
 * This is not an exotic attack. It is how people write numbers down when they
 * have been told not to put them in a ticket, how a phone transcript records
 * them, and how a support agent types what a caller dictated. The result is the
 * same disclosure with a thin layer of spelling over it.
 *
 * The approach is to transcribe runs of number words back into digits, then
 * decide what they are by length and by the label in front of them. Precision
 * comes from requiring a run of at least three consecutive number words: a
 * sentence that happens to contain "one" and "two" is not a card number.
 */

import type { PatternPack, PatternRule } from '../pattern.js';
import { Confidence } from '../types.js';
import { luhn } from '../validators.js';

/** Word to digits. Teens and tens transcribe to two digits, as dictated. */
const NUMBER_WORDS: Readonly<Record<string, string>> = {
  zero: '0', oh: '0', o: '0', nought: '0', naught: '0',
  one: '1', two: '2', three: '3', four: '4', five: '5',
  six: '6', seven: '7', eight: '8', nine: '9',
  ten: '10', eleven: '11', twelve: '12', thirteen: '13', fourteen: '14',
  fifteen: '15', sixteen: '16', seventeen: '17', eighteen: '18', nineteen: '19',
  twenty: '20', thirty: '30', forty: '40', fifty: '50',
  sixty: '60', seventy: '70', eighty: '80', ninety: '90',
};

const WORD_ALTERNATION = Object.keys(NUMBER_WORDS)
  // Longest first, so "seventeen" is not matched as "seven".
  .sort((a, b) => b.length - a.length)
  .join('|');

/**
 * A run of at least three number words.
 *
 * Three is the threshold where prose stops producing false positives: "one or
 * two" is two, "the first three" is one. It also happens to be the shortest
 * thing worth chasing, since a three-digit run is a CVV.
 *
 * The separator admits a single line break, because a dictated sixteen-digit
 * number does not fit on one line and wrapping it does not make it stop being a
 * card number. A blank line ends the run: that is a paragraph boundary, and
 * joining across one would splice two unrelated numbers into a false match.
 */
const SEPARATOR = '(?:[ ,-]|\\r?\\n(?!\\s*\\r?\\n))+';

const SPOKEN_RUN = new RegExp(
  `(?<![\\p{L}-])(?:${WORD_ALTERNATION})(?:${SEPARATOR}(?:and${SEPARATOR})?(?:${WORD_ALTERNATION})){2,}(?![\\p{L}-])`,
  'giu',
);

/**
 * Transcribe a matched run back into digits.
 *
 * A tens word followed by a unit is one number, not two: "forty-two" is 42, and
 * concatenating the mapped values would give 402 and turn a nine-digit SSN into
 * a ten-digit nothing. Everything else is read digit by digit, which is how
 * people dictate an account number.
 */
export function transcribeSpokenNumber(value: string): string {
  const words = value
    .toLowerCase()
    .split(/[ ,\n\r-]+/)
    .filter((word) => word !== '' && word !== 'and');

  const isTens = (v: string | undefined): boolean =>
    v !== undefined && v.length === 2 && v.endsWith('0') && v !== '10';
  const isUnit = (v: string | undefined): boolean =>
    v !== undefined && v.length === 1 && v !== '0';

  let out = '';
  for (let i = 0; i < words.length; i++) {
    const value = NUMBER_WORDS[words[i]!];
    if (value === undefined) continue;
    const next = NUMBER_WORDS[words[i + 1] ?? ''];
    if (isTens(value) && isUnit(next)) {
      out += String(Number(value) + Number(next));
      i++;
      continue;
    }
    out += value;
  }
  return out;
}

/**
 * A dictated payment card number.
 *
 * Thirteen to nineteen digits once transcribed. The Luhn check is applied but
 * only to raise confidence -- a dictated number is frequently mistranscribed by
 * whoever wrote it down, and a card number that fails Luhn because a digit was
 * misheard is still a card number in the document.
 */
const spokenCard: PatternRule = {
  id: 'obfuscated.card.spoken',
  type: 'financial.card',
  pattern: SPOKEN_RUN,
  baseConfidence: Confidence.LIKELY,
  description: 'a payment card number written out in words',
  validate(value) {
    const digits = transcribeSpokenNumber(value);
    if (digits.length < 13 || digits.length > 19) {
      return { ok: false, signal: 'structure:spoken-length', note: 'transcribes to a length no card uses' };
    }
    return luhn(digits)
      ? { ok: true, signal: 'checksum:luhn', note: `transcribes to ${digits.length} digits that pass the Luhn check`, weight: 0.34 }
      : { ok: true, signal: 'structure:spoken-length', note: `transcribes to ${digits.length} digits, the length of a card number`, weight: 0.2 };
  },
  normalize: (value) => transcribeSpokenNumber(value),
  context: {
    supports: ['card', 'visa', 'mastercard', 'amex', 'pan', 'account', 'number', 'digits'],
  },
};

/** A dictated Social Security number: nine digits with a matching label. */
const spokenSsn: PatternRule = {
  id: 'obfuscated.ssn.spoken',
  type: 'gov.ssn',
  pattern: SPOKEN_RUN,
  baseConfidence: Confidence.WEAK,
  description: 'a Social Security number written out in words',
  validate(value) {
    const digits = transcribeSpokenNumber(value);
    return digits.length === 9
      ? { ok: true, signal: 'structure:spoken-length', note: 'transcribes to nine digits', weight: 0.3 }
      : { ok: false, signal: 'structure:spoken-length', note: 'does not transcribe to nine digits' };
  },
  normalize: (value) => transcribeSpokenNumber(value),
  context: {
    supports: ['ssn', 'social security', 'social security number', 'sin', 'national insurance', 'tax'],
    requireSupport: true,
    supportWeight: 0.35,
  },
};

/** A dictated card verification value. */
const spokenCvv: PatternRule = {
  id: 'obfuscated.cvv.spoken',
  type: 'financial.card',
  pattern: SPOKEN_RUN,
  baseConfidence: Confidence.WEAK,
  description: 'a card verification value written out in words',
  validate(value) {
    const digits = transcribeSpokenNumber(value);
    return digits.length === 3 || digits.length === 4
      ? { ok: true, signal: 'structure:spoken-length', note: `transcribes to ${digits.length} digits`, weight: 0.3 }
      : { ok: false, signal: 'structure:spoken-length', note: 'wrong length for a verification value' };
  },
  normalize: (value) => transcribeSpokenNumber(value),
  context: {
    supports: ['cvv', 'cvc', 'cid', 'security code', 'verification', 'three digits', 'back of the card'],
    requireSupport: true,
    supportWeight: 0.35,
  },
};

/**
 * Base64 that decodes to a credential.
 *
 * Encoding is not concealment, but it does defeat every rule that looks for the
 * word "password". Decoding candidate blobs and re-testing them is cheap, and it
 * catches the specific case of a credential pasted from a config dump or a shell
 * history.
 */
const base64Credential: PatternRule = {
  id: 'obfuscated.base64-credential',
  type: 'secret.password',
  pattern: /(?<![A-Za-z0-9+/=])[A-Za-z0-9+/]{24,512}={0,2}(?![A-Za-z0-9+/=])/g,
  baseConfidence: Confidence.WEAK,
  description: 'a base64 string that decodes to a credential',
  validate(value) {
    const decoded = decodeBase64(value);
    if (decoded === undefined) {
      return { ok: false, signal: 'encoding:base64', note: 'not decodable as base64 text' };
    }
    if (!/(?:pass(?:word|wd|phrase)?|secret|token|api[_\s-]?key|credential|bearer|admin)/i.test(decoded)) {
      return { ok: false, signal: 'encoding:base64', note: 'decodes to text with no credential marker' };
    }
    return {
      ok: true,
      signal: 'encoding:base64-credential',
      note: 'decodes to text containing a credential keyword; encoding is not concealment',
      weight: 0.45,
    };
  },
  normalize: (value) => value,
};

/**
 * Decode base64 to text, returning `undefined` when the result is not printable.
 *
 * Implemented by hand rather than with `atob`, which does not exist outside a
 * browser, and rejecting non-printable output because a base64-looking string
 * that decodes to binary is a key or an image, not a credential to read.
 */
function decodeBase64(value: string): string | undefined {
  const ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
  const clean = value.replace(/=+$/, '');
  if (clean.length % 4 === 1) return undefined;

  let bits = 0;
  let accumulator = 0;
  let out = '';
  for (const ch of clean) {
    const index = ALPHABET.indexOf(ch);
    if (index === -1) return undefined;
    accumulator = (accumulator << 6) | index;
    bits += 6;
    if (bits >= 8) {
      bits -= 8;
      const byte = (accumulator >> bits) & 0xff;
      // Printable ASCII plus tab, newline, and carriage return.
      if (byte !== 9 && byte !== 10 && byte !== 13 && (byte < 32 || byte > 126)) return undefined;
      out += String.fromCharCode(byte);
    }
  }
  return out.length >= 8 ? out : undefined;
}

/**
 * Credentials in a `user:password@host` authority, with or without a scheme.
 *
 * The URL rule in the contact pack requires a scheme. Half the time the string
 * appears without one -- in a `ping` command, a connection string fragment, a
 * log line -- and the password is just as exposed.
 */
const bareCredentials: PatternRule = {
  id: 'obfuscated.bare-credentials',
  type: 'secret.password',
  pattern:
    // The password may itself contain an `@` -- `P@ssw0rd2026!` is the shape
    // people actually choose -- so the class admits it and greedy matching binds
    // the *last* `@` to the host.
    /(?<![\w@:/])[A-Za-z][\w.-]{1,32}:[^\s/]{4,64}@(?:\d{1,3}(?:\.\d{1,3}){3}|[A-Za-z0-9][\w.-]{1,60})(?::\d{2,5})?(?![\w.])/g,
  baseConfidence: Confidence.STRONG,
  description: 'a username and password pair against a host, with no scheme in front of it',
  normalize: (value) => value,
};

export const obfuscatedPack: PatternPack = {
  id: 'obfuscated',
  version: '1.0.0',
  rules: [spokenCard, spokenSsn, spokenCvv, base64Credential, bareCredentials] satisfies PatternRule[],
};

export const obfuscatedRules = {
  spokenCard,
  spokenSsn,
  spokenCvv,
  base64Credential,
  bareCredentials,
};
