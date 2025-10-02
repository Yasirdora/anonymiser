/**
 * The format adapter contract.
 *
 * Adding a format means writing one of these. Nothing else in the engine
 * changes: detection, classification, planning, verification, and provenance
 * all operate on the model an adapter produces.
 *
 * The `reparse` requirement is what makes verification possible, and it is the
 * reason this interface asks for three methods rather than two. An adapter that
 * can write an output but cannot read its own output back is an adapter whose
 * redactions cannot be checked, and unchecked redaction is the thing this
 * engine exists to prevent.
 */

import type { DocumentModel } from './model/document.js';
import type { RedactionOperation, RedactionStrategy } from './redact/index.js';

/** What an adapter can and cannot do, declared up front. */
export interface AdapterCapabilities {
  /** Strategies this adapter can carry out. */
  readonly strategies: readonly RedactionStrategy[];
  /** Whether document and object metadata can be removed. */
  readonly removesMetadata: boolean;
  /** Whether embedded files can be removed. */
  readonly removesAttachments: boolean;
  /**
   * Whether prior revisions and incremental updates can be removed.
   *
   * A format that keeps history and an adapter that cannot flatten it is a
   * combination where redaction is not achievable, and the engine needs to know
   * that before it starts rather than after.
   */
  readonly removesRevisionHistory: boolean;
  /**
   * Whether `reparse` returns a faithful model of the output.
   *
   * `false` means verification runs in a degraded mode and the result is
   * reported as unverified rather than passing.
   */
  readonly verifiable: boolean;
}

/** Options passed to a parse. */
export interface ParseOptions {
  /** Identifier to give the resulting model. Defaults to a content digest. */
  readonly documentId?: string;
  /** Locale hints, forwarded to detectors. */
  readonly locales?: readonly string[];
}

/**
 * Reads a format into the model and writes operations back out.
 *
 * Implementations must be pure with respect to their inputs: `apply` may not
 * mutate the model it is given, and two calls with the same arguments must
 * produce byte-identical output.
 */
export interface DocumentAdapter<TSource = unknown, TOutput = unknown> {
  readonly id: string;
  readonly version: string;
  /** IANA media types this adapter handles. */
  readonly mediaTypes: readonly string[];
  readonly capabilities: AdapterCapabilities;

  parse(source: TSource, options?: ParseOptions): DocumentModel;

  /**
   * Produce a new document with the operations applied.
   *
   * Operations arrive validated: every target exists, every span is in range,
   * and every strategy is one this adapter declared. An adapter that encounters
   * something it cannot do should throw `E_UNSUPPORTED` rather than silently
   * skip it -- a skipped operation is a leak.
   */
  apply(model: DocumentModel, operations: readonly RedactionOperation[]): TOutput;

  /** Read back a produced output, so the result can be checked. */
  reparse(output: TOutput): DocumentModel;
}
