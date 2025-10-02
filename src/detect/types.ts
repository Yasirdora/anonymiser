/**
 * Detection contracts.
 *
 * A detector is a pure function from a document to findings. It may not mutate
 * the model, perform I/O, or depend on wall-clock time -- the same document and
 * the same detector set must always produce the same findings, because the
 * provenance manifest asserts exactly that.
 */

import type { DocumentIndex, DocumentModel, Location } from '../model/document.js';

/**
 * What a finding identifies.
 *
 * The known set is a taxonomy, not a closed enum: policies map entity types to
 * sensitivity, so callers adding a domain-specific type must be able to name it
 * without patching the engine.
 */
export type EntityType = KnownEntityType | (string & {});

export type KnownEntityType =
  // Direct identifiers
  | 'person.name'
  | 'person.dob'
  | 'person.age'
  | 'contact.email'
  | 'contact.phone'
  | 'contact.address'
  | 'contact.handle'
  // Government-issued identifiers
  | 'gov.ssn'
  | 'gov.tax-id'
  | 'gov.passport'
  | 'gov.driver-license'
  | 'gov.national-id'
  | 'gov.mrz'
  // Financial
  | 'financial.card'
  | 'financial.iban'
  | 'financial.account'
  | 'financial.routing'
  | 'financial.crypto-address'
  // Health
  | 'health.record-number'
  | 'health.insurance-id'
  | 'health.condition'
  // Technical
  | 'net.ipv4'
  | 'net.ipv6'
  | 'net.mac'
  | 'net.url'
  | 'net.hostname'
  | 'secret.api-key'
  | 'secret.private-key'
  | 'secret.jwt'
  | 'secret.password'
  // Geospatial and temporal
  | 'geo.coordinates'
  | 'geo.postcode'
  | 'geo.locality'
  | 'temporal.date'
  | 'financial.amount'
  // Organisational
  | 'org.name'
  | 'org.employee-id'
  /** Marked for removal by an operator rather than by a rule. */
  | 'manual.marked'
  // Security marking found in the document itself
  | 'marking.banner'
  | 'marking.portion'
  // Structural risks rather than values
  | 'risk.metadata'
  | 'risk.revision-history'
  | 'risk.attachment'
  | 'risk.hidden-content'
  | 'risk.cosmetic-redaction';

/**
 * How much the engine trusts a finding, in `[0, 1]`.
 *
 * Confidence is not probability. It is a ranking signal used for thresholds and
 * review ordering. Anything with a checksum lands at `VERIFIED`; anything from
 * shape alone lands at `WEAK` until context raises it.
 */
export const Confidence = {
  /** Structurally valid and checksum-verified. */
  VERIFIED: 0.99,
  /** Distinctive format with no plausible false-positive class. */
  STRONG: 0.85,
  /** Format matches and nearby context supports it. */
  LIKELY: 0.65,
  /** Format matches but the shape is ambiguous. */
  WEAK: 0.4,
  /** Speculative; surfaced for review, never auto-redacted. */
  HINT: 0.2,
} as const;

/** Why a detector believes a finding is real. Rendered verbatim in review UIs. */
export interface Evidence {
  /** Machine-readable reason, e.g. `checksum:luhn`, `context:keyword`. */
  readonly signal: string;
  /** Human-readable explanation, one sentence, no trailing period. */
  readonly note: string;
  /** Contribution to the final confidence, positive or negative. */
  readonly weight: number;
}

/** A single detected item. */
export interface Finding {
  /** Content-derived identifier; identical inputs yield identical ids. */
  readonly id: string;
  /** Detector rule that produced this, e.g. `pattern:financial.card`. */
  readonly ruleId: string;
  /** What was found. */
  readonly type: EntityType;
  /** Where it was found. */
  readonly location: Location;
  /** The matched value, exactly as it appears in the document. */
  readonly value: string;
  /** Trust in this finding, in `[0, 1]`. */
  readonly confidence: number;
  /** The reasoning that produced `confidence`. */
  readonly evidence: readonly Evidence[];
  /**
   * A normalised form used for cross-document consistency.
   *
   * `+1 (555) 010-9999` and `555-010-9999` must pseudonymise to the same token,
   * or a reader can re-link records across a released corpus.
   */
  readonly normalized?: string;
  /** Free-form detector output, passed through to the manifest. */
  readonly attrs?: Readonly<Record<string, string>>;
}

/** Everything a detector is given. */
export interface DetectionContext {
  readonly model: DocumentModel;
  readonly index: DocumentIndex;
  /** Locale hints, e.g. `['en-GB', 'fr-FR']`. Detectors may ignore these. */
  readonly locales: readonly string[];
  /** Findings from detectors that already ran, for detectors that build on them. */
  readonly priorFindings: readonly Finding[];
}

/** A detector contributes findings for one family of entities. */
export interface Detector {
  /** Stable identifier, unique within a registry. */
  readonly id: string;
  /** Bumped when behaviour changes; recorded in the manifest. */
  readonly version: string;
  /** Entity types this detector can emit, for capability reporting. */
  readonly emits: readonly EntityType[];
  /**
   * Detectors run in ascending stage order. Stage 0 finds values; later stages
   * may consume `priorFindings` to corroborate or suppress them.
   */
  readonly stage?: number;
  detect(context: DetectionContext): readonly Finding[];
}
