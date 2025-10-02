/**
 * Checksum and structural validators.
 *
 * These are what separate a finding worth acting on from a nine-digit number.
 * A regex that matches `\d{16}` fires on order numbers and part codes; the same
 * regex gated on a Luhn check is trustworthy enough to redact automatically.
 * Every validator here is total: it returns a boolean and never throws.
 */

/** Strip spaces, hyphens, and dots -- the separators humans add to identifiers. */
export function stripSeparators(value: string): string {
  return value.replace(/[\s.\-‐-―]/g, '');
}

/**
 * Luhn mod-10. Used by payment cards, IMEI, and several national ID schemes.
 */
export function luhn(value: string): boolean {
  const digits = stripSeparators(value);
  if (digits.length < 2 || !/^\d+$/.test(digits)) return false;
  let sum = 0;
  let double = false;
  for (let i = digits.length - 1; i >= 0; i--) {
    let d = digits.charCodeAt(i) - 48;
    if (double) {
      d *= 2;
      if (d > 9) d -= 9;
    }
    sum += d;
    double = !double;
  }
  return sum % 10 === 0;
}

/**
 * IBAN, per ISO 13616: rotate the first four characters to the end, map letters
 * to numbers, and check the result is congruent to 1 mod 97.
 */
export function iban(value: string): boolean {
  const compact = stripSeparators(value).toUpperCase();
  if (!/^[A-Z]{2}\d{2}[A-Z0-9]{10,30}$/.test(compact)) return false;
  const expected = IBAN_LENGTHS[compact.slice(0, 2)];
  if (expected !== undefined && compact.length !== expected) return false;

  const rearranged = compact.slice(4) + compact.slice(0, 4);
  // Reduce progressively; the full number exceeds Number.MAX_SAFE_INTEGER.
  let remainder = 0;
  for (const ch of rearranged) {
    const code = ch.charCodeAt(0);
    const chunk = code >= 65 ? String(code - 55) : ch;
    for (const digit of chunk) {
      remainder = (remainder * 10 + (digit.charCodeAt(0) - 48)) % 97;
    }
  }
  return remainder === 1;
}

/** Registered IBAN lengths by country. Wrong length is a definitive reject. */
const IBAN_LENGTHS: Readonly<Record<string, number>> = {
  AD: 24, AE: 23, AL: 28, AT: 20, AZ: 28, BA: 20, BE: 16, BG: 22, BH: 22, BR: 29,
  BY: 28, CH: 21, CR: 22, CY: 28, CZ: 24, DE: 22, DK: 18, DO: 28, EE: 20, EG: 29,
  ES: 24, FI: 18, FO: 18, FR: 27, GB: 22, GE: 22, GI: 23, GL: 18, GR: 27, GT: 28,
  HR: 21, HU: 28, IE: 22, IL: 23, IQ: 23, IS: 26, IT: 27, JO: 30, KW: 30, KZ: 20,
  LB: 28, LC: 32, LI: 21, LT: 20, LU: 20, LV: 21, LY: 25, MC: 27, MD: 24, ME: 22,
  MK: 19, MR: 27, MT: 31, MU: 30, NL: 18, NO: 15, PK: 24, PL: 28, PS: 29, PT: 25,
  QA: 29, RO: 24, RS: 22, SA: 24, SC: 31, SE: 24, SI: 19, SK: 24, SM: 27, ST: 25,
  SV: 28, TL: 23, TN: 24, TR: 26, UA: 29, VA: 22, VG: 24, XK: 20,
};

/**
 * US Social Security Number structural rules.
 *
 * Post-2011 randomisation retired most block allocations, so only the
 * permanently-invalid forms are rejected: area 000, 666, and 900-999; group 00;
 * serial 0000. This deliberately admits numbers that were never issued -- the
 * cost of redacting a non-issued SSN is nil, the cost of missing a real one is not.
 */
export function usSsn(value: string): boolean {
  const digits = stripSeparators(value);
  if (!/^\d{9}$/.test(digits)) return false;
  const area = Number(digits.slice(0, 3));
  const group = Number(digits.slice(3, 5));
  const serial = Number(digits.slice(5));
  if (area === 0 || area === 666 || area >= 900) return false;
  if (group === 0 || serial === 0) return false;
  // Two numbers were publicly voided by the SSA after mass misuse: the one on
  // the 1938 Woolworth specimen wallet card, and the one from a 1940s pamphlet.
  // Neither will ever belong to anyone. Numbers that merely look like examples
  // are left alone -- 123-45-6789 is issuable under post-2011 randomisation,
  // and missing a real SSN costs far more than redacting a placeholder.
  if (digits === '078051120' || digits === '219099999') return false;
  return true;
}

/** ABA routing number: weighted mod-10 over nine digits. */
export function abaRouting(value: string): boolean {
  const digits = stripSeparators(value);
  if (!/^\d{9}$/.test(digits)) return false;
  const w = [3, 7, 1, 3, 7, 1, 3, 7, 1];
  let sum = 0;
  for (let i = 0; i < 9; i++) sum += (digits.charCodeAt(i) - 48) * w[i]!;
  return sum % 10 === 0;
}

/** NHS number (England, Wales, IoM): mod-11 with a weighted checksum. */
export function nhsNumber(value: string): boolean {
  const digits = stripSeparators(value);
  if (!/^\d{10}$/.test(digits)) return false;
  let sum = 0;
  for (let i = 0; i < 9; i++) sum += (digits.charCodeAt(i) - 48) * (10 - i);
  const remainder = sum % 11;
  const check = 11 - remainder;
  const expected = check === 11 ? 0 : check;
  if (check === 10) return false; // 10 is not a valid check digit
  return expected === digits.charCodeAt(9) - 48;
}

/** UK National Insurance number: prefix and suffix constraints. */
export function ukNino(value: string): boolean {
  const compact = stripSeparators(value).toUpperCase();
  if (!/^[A-Z]{2}\d{6}[A-D]$/.test(compact)) return false;
  const first = compact[0]!;
  const second = compact[1]!;
  if ('DFIQUV'.includes(first)) return false;
  if ('DFIQUVO'.includes(second)) return false;
  if (['GB', 'BG', 'NK', 'KN', 'TN', 'NT', 'ZZ'].includes(compact.slice(0, 2))) return false;
  return true;
}

/** ICAO 9303 machine-readable-zone check digit: weights cycle 7, 3, 1. */
export function mrzCheckDigit(field: string, expected: string): boolean {
  if (!/^\d$/.test(expected)) return false;
  const weights = [7, 3, 1];
  let sum = 0;
  for (let i = 0; i < field.length; i++) {
    const ch = field[i]!;
    let v: number;
    if (ch >= '0' && ch <= '9') v = ch.charCodeAt(0) - 48;
    else if (ch >= 'A' && ch <= 'Z') v = ch.charCodeAt(0) - 55;
    else if (ch === '<') v = 0;
    else return false;
    sum += v * weights[i % 3]!;
  }
  return sum % 10 === Number(expected);
}

/** ISO 6346 / generic mod-11 with explicit weights, for custom schemes. */
export function weightedMod11(digits: string, weights: readonly number[]): boolean {
  if (!/^\d+$/.test(digits) || digits.length !== weights.length + 1) return false;
  let sum = 0;
  for (let i = 0; i < weights.length; i++) sum += (digits.charCodeAt(i) - 48) * weights[i]!;
  const check = (11 - (sum % 11)) % 11;
  return check < 10 && check === digits.charCodeAt(digits.length - 1) - 48;
}

/**
 * IPv4 dotted quad with no leading zeros.
 *
 * Leading zeros are rejected because `010.1.1.1` is parsed as octal by some
 * stacks and as decimal by others; treating it as an address invites both a
 * false positive and an ambiguity the engine should not silently resolve.
 */
export function ipv4(value: string): boolean {
  const parts = value.split('.');
  if (parts.length !== 4) return false;
  for (const part of parts) {
    if (!/^\d{1,3}$/.test(part)) return false;
    if (part.length > 1 && part[0] === '0') return false;
    if (Number(part) > 255) return false;
  }
  return true;
}

/** Geographic coordinate pair within valid latitude and longitude ranges. */
export function latLon(lat: number, lon: number): boolean {
  return (
    Number.isFinite(lat) && Number.isFinite(lon) &&
    Math.abs(lat) <= 90 && Math.abs(lon) <= 180 &&
    // A bare "0, 0" is almost always a placeholder, not Null Island.
    !(lat === 0 && lon === 0)
  );
}

/**
 * Shannon entropy in bits per character.
 *
 * Used to separate real credentials from placeholders: a 32-character string of
 * `xxxxxxxx...` and a real API key match the same shape, and only entropy tells
 * them apart.
 */
export function shannonEntropy(value: string): number {
  if (value.length === 0) return 0;
  const counts = new Map<string, number>();
  for (const ch of value) counts.set(ch, (counts.get(ch) ?? 0) + 1);
  let entropy = 0;
  for (const count of counts.values()) {
    const p = count / value.length;
    entropy -= p * Math.log2(p);
  }
  return entropy;
}

/** Common placeholder values that should never be treated as real secrets. */
const PLACEHOLDER = /^(?:x+|0+|1+|a+|test|sample|example|dummy|placeholder|redacted|xxxx+|none|null|n\/a|todo|changeme|your[_-]?\w+[_-]?here)$/i;

/** True when a value is evidently a template stand-in rather than real data. */
export function isPlaceholder(value: string): boolean {
  const compact = stripSeparators(value);
  if (PLACEHOLDER.test(compact)) return true;
  // Repeating a single character never survives as a real identifier.
  if (compact.length >= 4 && new Set(compact.toLowerCase()).size === 1) return true;
  return false;
}
