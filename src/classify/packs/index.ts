/**
 * Bundled classification policies.
 *
 * These are working models of real marking systems, not authoritative copies of
 * them. Vocabularies change, several compartments are themselves classified,
 * and every adopting organisation adds local values. Treat a pack as a starting
 * point to be reviewed by whoever owns marking policy where it is deployed.
 */

export { corporatePolicy } from './corporate.js';
export { natoPolicy } from './nato.js';
export { privacyPolicy } from './privacy.js';
export { ukGscpPolicy } from './uk-gscp.js';
export { usCapcoPolicy } from './us-capco.js';

import { corporatePolicy } from './corporate.js';
import { natoPolicy } from './nato.js';
import { privacyPolicy } from './privacy.js';
import { ukGscpPolicy } from './uk-gscp.js';
import { usCapcoPolicy } from './us-capco.js';
import type { ClassificationPolicy } from '../types.js';

/** Every bundled policy, keyed by id. */
export const policies: Readonly<Record<string, ClassificationPolicy>> = {
  [privacyPolicy.id]: privacyPolicy,
  [corporatePolicy.id]: corporatePolicy,
  [usCapcoPolicy.id]: usCapcoPolicy,
  [ukGscpPolicy.id]: ukGscpPolicy,
  [natoPolicy.id]: natoPolicy,
};
