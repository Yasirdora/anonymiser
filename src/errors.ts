/**
 * Every failure the engine raises is one of these, carrying a stable `code`
 * that callers can branch on without string-matching messages. UI layers are
 * expected to surface `code` and `detail` rather than the raw message.
 */

export type ClassifiedErrorCode =
  /** Input could not be understood by the selected adapter. */
  | 'E_PARSE'
  /** A policy, pattern, or plan was structurally invalid. */
  | 'E_INVALID_POLICY'
  /** A redaction plan referenced content that does not exist in the model. */
  | 'E_DANGLING_TARGET'
  /** Two operations demand contradictory outcomes for the same content. */
  | 'E_CONFLICT'
  /** A cosmetic (reversible) strategy was requested without explicit opt-in. */
  | 'E_COSMETIC_REFUSED'
  /** Redacted content was still recoverable from the produced output. */
  | 'E_VERIFICATION_FAILED'
  /** The adapter cannot perform an operation the plan requires. */
  | 'E_UNSUPPORTED'
  /** A provenance manifest failed integrity or signature checks. */
  | 'E_MANIFEST_INVALID'
  /** Caller misuse: bad arguments, wrong order, missing capability. */
  | 'E_USAGE';

/** Base class for all engine failures. */
export class ClassifiedError extends Error {
  readonly code: ClassifiedErrorCode;
  readonly detail: Readonly<Record<string, unknown>>;

  constructor(
    code: ClassifiedErrorCode,
    message: string,
    detail: Readonly<Record<string, unknown>> = {},
  ) {
    super(message);
    this.name = 'ClassifiedError';
    this.code = code;
    this.detail = detail;
  }
}

/**
 * Raised when the output still contains content the plan promised to remove.
 *
 * This is deliberately fatal. The entire class of redaction disasters this
 * engine exists to prevent -- a black rectangle drawn over live text -- looks
 * identical to success on screen, so the only safe default is to refuse to hand
 * back an output that failed its own check.
 */
export class VerificationFailedError extends ClassifiedError {
  readonly leaks: readonly VerificationLeak[];

  constructor(leaks: readonly VerificationLeak[]) {
    super(
      'E_VERIFICATION_FAILED',
      `redaction verification failed: ${leaks.length} item(s) still recoverable from the output`,
      { leaks },
    );
    this.name = 'VerificationFailedError';
    this.leaks = leaks;
  }
}

/** A single piece of content that survived redaction. */
export interface VerificationLeak {
  /** The operation that was supposed to eliminate this content. */
  readonly operationId: string;
  /** Where in the re-parsed output the content was found. */
  readonly foundIn: string;
  /** How the leak was detected. */
  readonly channel: LeakChannel;
  /** Redacted preview of the leaked value, safe to log. */
  readonly preview: string;
}

/**
 * The routes by which supposedly-removed content escapes. Named explicitly
 * because each one corresponds to a documented real-world redaction failure.
 */
export type LeakChannel =
  /** Value still present in the primary text layer. */
  | 'text-layer'
  /** Value present in document or embedded-object metadata. */
  | 'metadata'
  /** Value present in an annotation, comment, or form field. */
  | 'annotation'
  /** Value recoverable from a prior revision or incremental update. */
  | 'revision-history'
  /** Value present in an embedded file or attachment. */
  | 'attachment'
  /** Pixels beneath an overlay were not destroyed. */
  | 'underlying-raster'
  /** A cosmetic transform (blur/pixelate) that is statistically reversible. */
  | 'reversible-transform';
