/**
 * Provenance manifests.
 *
 * A redacted document on its own answers no useful question. It cannot say what
 * was removed, on whose authority, under which policy, or whether the removal
 * was ever checked. Those are exactly the questions an auditor, an opposing
 * counsel, or a requester whose FOIA response arrived half-black will ask, and
 * "we used a tool" is not an answer.
 *
 * The manifest answers them without disclosing anything. Every entry records
 * the *digest* of a removed value rather than the value: enough to prove later
 * that a specific string was the thing removed, never enough to recover it. The
 * entries are chained, each one committing to its predecessor, so an entry
 * cannot be altered or dropped without breaking every link after it.
 */

import { concatBytes, fromHex, timingSafeEqual, toHex, utf8Encode } from '../internal/bytes.js';
import { sha256, sha256Text } from '../internal/hash.js';
import { ClassifiedError } from '../errors.js';
import type { ClassificationResult } from '../classify/engine.js';
import type { ClassificationPolicy } from '../classify/types.js';
import type { DetectionResult } from '../detect/engine.js';
import type { EngineIdentity, RedactionPlan } from '../redact/plan.js';
import type { VerificationReport } from '../verify/verifier.js';

/** One link in the chain: a single removal, committed to. */
export interface ManifestEntry {
  /** Position in the chain, from 0. */
  readonly seq: number;
  /** Hash of the previous entry, or 64 zeros for the first. */
  readonly previous: string;
  readonly operationId: string;
  readonly strategy: string;
  /** Where the removal happened, in the model's addressing scheme. */
  readonly location: string;
  /** Withholding authority code, e.g. `foia.b6`. */
  readonly reasonCode: string;
  readonly authority: string;
  /** Entity types the removal covered. */
  readonly entityTypes: readonly string[];
  /**
   * `SHA-256(salt || original value)`.
   *
   * Salted because unsalted digests of short, low-entropy values -- a
   * nine-digit SSN, a five-digit postcode -- fall to an exhaustive search in
   * seconds, which would turn the audit record into a disclosure.
   */
  readonly valueDigest: string;
  /** Length of the removed value, which is disclosed and is usually harmless. */
  readonly valueLength: number;
  /** This entry's own hash, committing to every field above. */
  readonly hash: string;
}

/** What the manifest says about the run as a whole. */
export interface ManifestSummary {
  readonly engine: EngineIdentity;
  /** Digest of the input bytes. */
  readonly sourceDigest: string;
  /** Digest of the produced bytes. */
  readonly outputDigest: string;
  /** Digest of the serialised policy, so a policy change is detectable. */
  readonly policyDigest: string;
  readonly policyId: string;
  readonly policyVersion: string;
  readonly planId: string;
  /** Detector ids and versions that produced the findings. */
  readonly detectors: readonly { readonly id: string; readonly version: string }[];
  /** The derived banner marking for the output. */
  readonly bannerMarking: string;
  readonly operationCount: number;
  readonly findingCount: number;
  /** Whether verification confirmed every destructive removal. */
  readonly verified: boolean;
  /** Operations that could not be verified. */
  readonly unverifiedCount: number;
  /**
   * True when the run used a strategy whose output can be reversed.
   *
   * A manifest carrying this flag is a record that the output is not
   * defensible. It exists so the fact cannot be lost between the person who
   * chose the option and the person who relies on the result.
   */
  readonly usedRecoverableStrategies: boolean;
  /** Caller-supplied timestamp. Omitted by default to keep runs reproducible. */
  readonly issuedAt?: string;
  /** Caller-supplied operator identity. */
  readonly issuedBy?: string;
}

/** A sealed, verifiable record of one redaction run. */
export interface ProvenanceManifest {
  readonly version: '1';
  readonly summary: ManifestSummary;
  readonly entries: readonly ManifestEntry[];
  /**
   * Hash over the summary and the final chain link.
   *
   * One value to publish, quote in a cover letter, or compare against a
   * re-run.
   */
  readonly root: string;
  /** Detached signature over `root`, when a signer was supplied. */
  readonly signature?: string;
}

const ZERO_HASH = '0'.repeat(64);

/** Inputs for building a manifest. */
export interface ManifestInput {
  readonly plan: RedactionPlan;
  readonly detection: DetectionResult;
  readonly classification: ClassificationResult;
  readonly policy: ClassificationPolicy;
  readonly verification: VerificationReport;
  /** Digest of the produced output bytes. */
  readonly outputDigest: string;
  /**
   * Salt for value digests. Must be at least 16 bytes.
   *
   * Reusing one salt across a corpus lets an auditor confirm that the same
   * value was removed from two documents, which is often the point. Using a
   * fresh salt per document prevents that linkage. Both are legitimate; the
   * choice belongs to whoever designs the audit process.
   */
  readonly digestSalt: Uint8Array;
  /** ISO 8601 timestamp. Omit for a byte-reproducible manifest. */
  readonly issuedAt?: string;
  readonly issuedBy?: string;
  /** Signs the root hash. */
  readonly sign?: (root: Uint8Array) => Uint8Array;
}

const MINIMUM_SALT_BYTES = 16;

/**
 * Build and seal a manifest.
 *
 * The chain is built in plan order, which is itself deterministic, so two runs
 * over the same input produce the same root hash. That is what makes the root
 * worth publishing: a third party can re-run the pipeline and confirm the
 * output was produced from the stated input under the stated policy.
 */
export function buildManifest(input: ManifestInput): ProvenanceManifest {
  if (input.digestSalt.length < MINIMUM_SALT_BYTES) {
    throw new ClassifiedError(
      'E_USAGE',
      `manifest digest salt must be at least ${MINIMUM_SALT_BYTES} bytes; short-value digests are otherwise trivially reversible`,
      { provided: input.digestSalt.length, required: MINIMUM_SALT_BYTES },
    );
  }

  const findingTypes = new Map<string, string>();
  for (const finding of input.detection.all) findingTypes.set(finding.id, finding.type);

  const entries: ManifestEntry[] = [];
  let previous = ZERO_HASH;

  for (const [seq, operation] of input.plan.operations.entries()) {
    const entityTypes = [
      ...new Set(operation.findingIds.map((id) => findingTypes.get(id) ?? 'unknown')),
    ].sort();

    const body = {
      seq,
      previous,
      operationId: operation.id,
      strategy: operation.strategy,
      location: locationOf(operation),
      reasonCode: operation.reason.code,
      authority: operation.reason.authority,
      entityTypes,
      valueDigest:
        operation.originalValue === undefined
          ? ZERO_HASH
          : toHex(sha256(concatBytes(input.digestSalt, utf8Encode(operation.originalValue)))),
      valueLength: operation.originalValue?.length ?? 0,
    };

    const hash = toHex(sha256Text(canonicalJson(body)));
    entries.push({ ...body, hash });
    previous = hash;
  }

  const summary: ManifestSummary = {
    engine: input.plan.engine,
    sourceDigest: input.plan.sourceDigest,
    outputDigest: input.outputDigest,
    policyDigest: toHex(sha256Text(canonicalJson(input.policy))),
    policyId: input.plan.policyId,
    policyVersion: input.plan.policyVersion,
    planId: input.plan.id,
    detectors: input.detection.detectors,
    bannerMarking: input.classification.bannerMarking,
    operationCount: input.plan.operations.length,
    findingCount: input.detection.findings.length,
    verified: input.verification.passed && !input.verification.degraded,
    unverifiedCount: input.verification.unverifiable.length,
    usedRecoverableStrategies: input.plan.containsRecoverableStrategies,
    ...(input.issuedAt !== undefined ? { issuedAt: input.issuedAt } : {}),
    ...(input.issuedBy !== undefined ? { issuedBy: input.issuedBy } : {}),
  };

  const rootBytes = sha256Text(canonicalJson({ summary, tail: previous }));
  const root = toHex(rootBytes);
  const signature = input.sign === undefined ? undefined : toHex(input.sign(rootBytes));

  return {
    version: '1',
    summary,
    entries,
    root,
    ...(signature !== undefined ? { signature } : {}),
  };
}

/** The outcome of checking a manifest's integrity. */
export interface ManifestVerification {
  readonly valid: boolean;
  /** Index of the first broken link, or `-1` when the chain is intact. */
  readonly brokenAt: number;
  readonly problems: readonly string[];
}

/**
 * Recompute a manifest's chain and root.
 *
 * Reports the first break rather than merely failing, because where the chain
 * broke says what happened: a break at entry 12 means entries 0 through 11 are
 * still trustworthy and something was altered at 12.
 */
export function verifyManifest(manifest: ProvenanceManifest): ManifestVerification {
  const problems: string[] = [];
  let previous = ZERO_HASH;

  for (const [index, entry] of manifest.entries.entries()) {
    if (entry.seq !== index) {
      problems.push(`entry ${index} declares sequence ${entry.seq}; an entry has been reordered or removed`);
      return { valid: false, brokenAt: index, problems };
    }
    if (entry.previous !== previous) {
      problems.push(`entry ${index} does not chain to its predecessor`);
      return { valid: false, brokenAt: index, problems };
    }

    const { hash, ...body } = entry;
    const recomputed = toHex(sha256Text(canonicalJson(body)));
    if (recomputed !== hash) {
      problems.push(`entry ${index} has been altered since it was sealed`);
      return { valid: false, brokenAt: index, problems };
    }
    previous = hash;
  }

  const expectedRoot = toHex(sha256Text(canonicalJson({ summary: manifest.summary, tail: previous })));
  if (expectedRoot !== manifest.root) {
    problems.push('the summary or the final entry has been altered since the manifest was sealed');
    return { valid: false, brokenAt: manifest.entries.length, problems };
  }

  return { valid: true, brokenAt: -1, problems };
}

/**
 * Confirm that a specific value is the one a manifest entry recorded.
 *
 * Lets a holder of the original prove what was removed, without the manifest
 * ever having contained it. This is how a disclosure dispute gets settled: the
 * agency shows the manifest, the requester challenges an entry, and the agency
 * demonstrates the match under the original salt.
 */
export function confirmRemovedValue(
  entry: ManifestEntry,
  value: string,
  salt: Uint8Array,
): boolean {
  const digest = sha256(concatBytes(salt, utf8Encode(value)));
  let expected: Uint8Array;
  try {
    expected = fromHex(entry.valueDigest);
  } catch {
    return false;
  }
  return timingSafeEqual(digest, expected);
}

function locationOf(operation: RedactionPlan['operations'][number]): string {
  const { location } = operation;
  switch (location.kind) {
    case 'text':
      return `${location.node}:t:${location.start}-${location.end}`;
    case 'region': {
      const { x, y, width, height } = location.rect;
      return `${location.node}:r:${x},${y},${width},${height}`;
    }
    case 'node':
      return `${location.node}:n`;
  }
}

/**
 * Deterministic JSON: object keys sorted, no incidental whitespace.
 *
 * `JSON.stringify` preserves insertion order, so two structurally identical
 * objects built by different code paths serialise differently and hash
 * differently. Every digest in this file depends on that not happening.
 */
export function canonicalJson(value: unknown): string {
  if (value === null || typeof value !== 'object') return JSON.stringify(value) ?? 'null';
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(',')}]`;

  const entries = Object.entries(value as Record<string, unknown>)
    .filter(([, v]) => v !== undefined)
    .sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0));

  return `{${entries.map(([k, v]) => `${JSON.stringify(k)}:${canonicalJson(v)}`).join(',')}}`;
}
