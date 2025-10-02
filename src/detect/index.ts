/**
 * Detection: finding what is sensitive, and explaining why.
 */

export * from './types.js';
export * from './pattern.js';
export * from './context.js';
export * from './engine.js';
export { structuralDetector } from './structural.js';
export { repeatValueDetector } from './repeat.js';
export { manualDetector, manualFindingId, type ManualMark } from './manual.js';
export { termDetector, type TermRule } from './terms.js';
export * from './patterns/index.js';
export {
  abaRouting,
  iban,
  isPlaceholder,
  latLon,
  luhn,
  mrzCheckDigit,
  nhsNumber,
  shannonEntropy,
  stripSeparators,
  ukNino,
  usSsn,
  weightedMod11,
  ipv4,
} from './validators.js';

import { patternDetector } from './pattern.js';
import { networkPack, personalDataPacks, secretsPack } from './patterns/index.js';
import { repeatValueDetector } from './repeat.js';
import { structuralDetector } from './structural.js';
import type { Detector } from './types.js';

/**
 * The recommended detector set.
 *
 * Personal-data patterns, plus two things that are included unconditionally:
 *
 * - **Structural risks**, because they are the half that catches the failures
 *   people actually make -- the live text under the black box, the author in
 *   the metadata, the comment nobody removed.
 * - **Credentials**, because a leaked key is immediately actionable by whoever
 *   reads it and the vendor-prefixed rules have almost no false positives.
 *   There is no document where finding an AWS key is unwelcome.
 * - **Network identifiers**, because the documents people actually redact are
 *   full of them. An incident report, a support ticket, or a breach complaint
 *   carries addresses, MAC addresses, and internal hostnames as a matter of
 *   course, and leaving them out of the default meant the tool went quiet on
 *   precisely the material it was handed.
 * - **Repeat occurrences**, because redacting a name in the header and leaving
 *   it in the signature is not a redaction. Rules find a value where its label
 *   is; this finds it everywhere else.
 */
export function standardDetectors(): Detector[] {
  return [
    patternDetector([...personalDataPacks, secretsPack, networkPack]),
    structuralDetector(),
    repeatValueDetector(),
  ];
}
