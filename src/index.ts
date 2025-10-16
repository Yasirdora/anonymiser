/**
 * @anonymiser/core
 *
 * A zero-dependency, framework-agnostic engine for classifying documents,
 * deriving security markings, redacting sensitive content, proving the
 * redaction worked, and recording what was done.
 *
 * Four principles hold across the whole surface:
 *
 * 1. **A redaction that can be reversed is not a redaction.** Blur and
 *    pixelation are refused unless explicitly opted into, and the opt-in is
 *    recorded.
 * 2. **Redaction is not finished until it is verified.** Output is read back
 *    and searched for what the plan removed. A leak is an exception, not a
 *    warning.
 * 3. **Markings are derived, never asserted.** A banner is the lattice join of
 *    its portions, and a banner the document already carries is evidence to be
 *    checked rather than trusted.
 * 4. **Every removal carries an authority.** There are no anonymous
 *    redactions, and the record proves what was removed without disclosing it.
 *
 * Nothing here touches the DOM, Node built-ins, or any host global beyond the
 * ECMAScript standard library. It runs unchanged in a browser, a service
 * worker, Node, Deno, and Bun.
 */

export * from './errors.js';
export * from './adapter.js';
export * from './pipeline.js';

export * from './model/document.js';
export * from './model/geometry.js';

export * from './detect/index.js';
export * from './classify/index.js';
export * from './redact/index.js';
export * from './verify/index.js';
export * from './provenance/index.js';

export {
  concatBytes,
  fromHex,
  timingSafeEqual,
  toBase32,
  toHex,
  utf8Decode,
  utf8Encode,
} from './internal/bytes.js';
export { hmacSha256, sha256, sha256Text, Sha256 } from './internal/hash.js';
export {
  complement,
  contains,
  intersectionLength,
  mergeIntervals,
  overlaps,
  type Interval,
} from './internal/interval.js';

/** The engine's version, recorded in every plan and manifest. */
export const VERSION = '0.1.0';
