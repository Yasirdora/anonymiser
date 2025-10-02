/**
 * The bundled pattern packs.
 *
 * Packs are separable on purpose. A newsroom redacting a leaked cache wants
 * identity and contact rules and would drown in network findings; an incident
 * responder scrubbing a log bundle wants the opposite. Shipping one
 * undifferentiated list of several hundred patterns, as most libraries do,
 * guarantees a false-positive rate that trains users to ignore the output.
 */

export { contactPack, contactRules } from './contact.js';
export { financialPack, financialRules, cardBrand } from './financial.js';
export { geoPack, geoRules, precisionMetres } from './geo.js';
export { healthPack, healthRules } from './health.js';
export { identityPack, identityRules } from './identity.js';
export { markingsPack, markingRules } from './markings.js';
export { networkPack, networkRules } from './network.js';
export { obfuscatedPack, obfuscatedRules, transcribeSpokenNumber } from './obfuscated.js';
export { peoplePack, peopleRules } from './people.js';
export { secretsPack, secretRules } from './secrets.js';
export { temporalPack, temporalRules } from './temporal.js';

import { contactPack } from './contact.js';
import { financialPack } from './financial.js';
import { geoPack } from './geo.js';
import { healthPack } from './health.js';
import { identityPack } from './identity.js';
import { markingsPack } from './markings.js';
import { networkPack } from './network.js';
import { obfuscatedPack } from './obfuscated.js';
import { peoplePack } from './people.js';
import { secretsPack } from './secrets.js';
import { temporalPack } from './temporal.js';
import type { PatternPack } from '../pattern.js';

/**
 * Every bundled pack.
 *
 * Suitable as a starting point for exploratory review, not as a production
 * default: the geo and network packs in particular will fire on documents where
 * they are noise.
 */
export const allPacks: readonly PatternPack[] = [
  contactPack,
  peoplePack,
  identityPack,
  financialPack,
  healthPack,
  secretsPack,
  networkPack,
  geoPack,
  temporalPack,
  obfuscatedPack,
  markingsPack,
];

/**
 * The packs that apply to almost any document containing personal data.
 *
 * This is the recommended default. Geo is included because postcodes and
 * coordinates are named identifiers under HIPAA Safe Harbor and appear in
 * every re-identification rule; network is not, being precise but specific to
 * operational documents.
 */
export const personalDataPacks: readonly PatternPack[] = [
  contactPack,
  peoplePack,
  identityPack,
  financialPack,
  healthPack,
  geoPack,
  temporalPack,
  obfuscatedPack,
  markingsPack,
];

/** Packs for scrubbing operational output: logs, configuration, transcripts. */
export const operationalPacks: readonly PatternPack[] = [
  secretsPack,
  networkPack,
  contactPack,
];
