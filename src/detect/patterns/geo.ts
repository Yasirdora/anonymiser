/**
 * Geospatial identifiers.
 *
 * Precision is the whole story here. A country is not identifying; a decimal
 * coordinate with five places locates a person to about a metre. Rules that
 * detect coordinates record the implied precision so a policy can distinguish
 * "somewhere in this city" from "this doorway".
 */

import type { PatternPack, PatternRule } from '../pattern.js';
import { Confidence } from '../types.js';
import { latLon } from '../validators.js';

/** Metres of ground resolution implied by a count of decimal places. */
function precisionMetres(decimals: number): number {
  return 111_320 / 10 ** decimals;
}

/**
 * Decimal degree pairs.
 *
 * At least four decimal places are required. Fewer than that resolves to
 * roughly a city block or coarser, which is rarely the disclosure anyone is
 * worried about, and two-decimal pairs collide constantly with ordinary
 * measurements and version numbers.
 */
const decimalCoordinates: PatternRule = {
  id: 'geo.coordinates.decimal',
  type: 'geo.coordinates',
  pattern: /(?<![\d.])(-?\d{1,2}\.\d{4,10})\s*[,;]\s*(-?\d{1,3}\.\d{4,10})(?![\d.])/g,
  baseConfidence: Confidence.LIKELY,
  description: 'a decimal latitude and longitude pair',
  validate(_value, match) {
    const lat = Number(match[1]);
    const lon = Number(match[2]);
    if (!latLon(lat, lon)) {
      return { ok: false, signal: 'structure:coordinate-range', note: 'outside valid latitude or longitude bounds' };
    }
    const decimals = Math.min(
      (match[1] ?? '').split('.')[1]?.length ?? 0,
      (match[2] ?? '').split('.')[1]?.length ?? 0,
    );
    const metres = precisionMetres(decimals);
    return {
      ok: true,
      signal: 'structure:coordinate-precision',
      note: `resolves to roughly ${metres < 1 ? '<1' : Math.round(metres).toString()} m on the ground`,
      weight: metres <= 100 ? 0.25 : 0.05,
    };
  },
  normalize: (value) => value.replace(/\s/g, ''),
};

/** Degrees, minutes, and seconds, as printed on maps and in EXIF displays. */
const dmsCoordinates: PatternRule = {
  id: 'geo.coordinates.dms',
  type: 'geo.coordinates',
  pattern:
    /(?<![\d.])\d{1,3}[°º]\s?\d{1,2}['′]\s?\d{1,2}(?:\.\d{1,4})?["″]?\s?[NS][,;\s]+\d{1,3}[°º]\s?\d{1,2}['′]\s?\d{1,2}(?:\.\d{1,4})?["″]?\s?[EW](?![\d.])/gi,
  baseConfidence: Confidence.STRONG,
  description: 'a degrees-minutes-seconds coordinate pair',
  normalize: (value) => value.replace(/\s+/g, ''),
};

const ukPostcode: PatternRule = {
  id: 'geo.postcode.uk',
  type: 'geo.postcode',
  pattern: /(?<![A-Z0-9])[A-Z]{1,2}\d[A-Z\d]?\s?\d[ABD-HJLNP-UW-Z]{2}(?![A-Z0-9])/gi,
  baseConfidence: Confidence.STRONG,
  description: 'a UK postcode, which resolves to about fifteen addresses',
  normalize: (value) => value.toUpperCase().replace(/\s+/g, ''),
  locales: ['en-GB'],
};

/**
 * US ZIP codes.
 *
 * The five-digit form is a bare integer and needs context. The ZIP+4 form does
 * not: it identifies a building or a side of a street, and nothing else is
 * written that way.
 */
const usZipPlusFour: PatternRule = {
  id: 'geo.postcode.us.zip4',
  type: 'geo.postcode',
  pattern: /(?<![\d-])\d{5}-\d{4}(?![\d-])/g,
  baseConfidence: Confidence.STRONG,
  description: 'a ZIP+4 code, which narrows to a building or block face',
  normalize: (value) => value,
  locales: ['en-US'],
};

const usZip: PatternRule = {
  id: 'geo.postcode.us.zip5',
  type: 'geo.postcode',
  pattern: /(?<![\d-])\d{5}(?![\d-])/g,
  baseConfidence: Confidence.HINT,
  description: 'five digits labelled as a ZIP code',
  normalize: (value) => value,
  context: {
    supports: ['zip', 'postal', 'address', 'city', 'state', 'mailing'],
    suppresses: ['year', 'amount', 'total', 'quantity', 'invoice', 'page'],
    requireSupport: true,
    supportWeight: 0.3,
  },
  locales: ['en-US'],
};

const caPostal: PatternRule = {
  id: 'geo.postcode.ca',
  type: 'geo.postcode',
  pattern: /(?<![A-Z0-9])[ABCEGHJ-NPRSTVXY]\d[ABCEGHJ-NPRSTV-Z]\s?\d[ABCEGHJ-NPRSTV-Z]\d(?![A-Z0-9])/gi,
  baseConfidence: Confidence.STRONG,
  description: 'a Canadian postal code',
  normalize: (value) => value.toUpperCase().replace(/\s+/g, ''),
  locales: ['en-CA', 'fr-CA'],
};

export const geoPack: PatternPack = {
  id: 'geo',
  version: '1.0.0',
  rules: [
    decimalCoordinates,
    dmsCoordinates,
    ukPostcode,
    usZipPlusFour,
    usZip,
    caPostal,
  ] satisfies PatternRule[],
};

export const geoRules = {
  decimalCoordinates,
  dmsCoordinates,
  ukPostcode,
  usZipPlusFour,
  usZip,
  caPostal,
};

export { precisionMetres };
