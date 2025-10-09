/**
 * Redaction strategies, and the safety model that governs them.
 *
 * This file contains the engine's central opinion, so it is worth stating
 * plainly: **a redaction that can be reversed is not a redaction.**
 *
 * Blur and pixelation are reversible. Dan Petro's Unredacter recovers text from
 * pixelated screenshots by rendering candidate strings in the same font and
 * matching the output; Positive Security demonstrated the same attack against
 * pixelated video with no guessing at all. The transform is deterministic and
 * the search space of English words in a known font is small, so the pixels
 * that remain are a lossy encoding of the original rather than a destruction of
 * it. They look like a redaction to a human reviewer and are not one.
 *
 * Every image tool in the ecosystem offers blur as the default control. This
 * engine classifies it as unsafe, refuses it unless the caller explicitly opts
 * in, and records the opt-in in the provenance manifest so that a document
 * redacted this way can never be mistaken for a defensible one.
 */

import { ClassifiedError } from '../errors.js';

/** How a piece of content is removed or obscured. */
export type RedactionStrategy =
  /** Delete the content. Surrounding text closes up. */
  | 'remove'
  /** Replace with fixed text, e.g. `[REDACTED]`. Preserves layout and page count. */
  | 'replace'
  /** Keep a declared portion and destroy the rest, e.g. `****1234`. */
  | 'mask'
  /** Replace with a stable token derived from the value, e.g. `PERSON_K4H2`. */
  | 'pseudonymize'
  /** Replace with plausible fabricated data of the same shape. */
  | 'synthesize'
  /** Overwrite a raster region with opaque pixels. */
  | 'blackout'
  /** Gaussian blur over a raster region. Reversible; refused by default. */
  | 'blur'
  /** Mosaic downsampling over a raster region. Reversible; refused by default. */
  | 'pixelate'
  /** Overwrite a raster region with deterministic noise. Destructive. */
  | 'scramble'
  /** Overwrite a raster region with hazard hatching. Destructive. */
  | 'hatch';

/** How recoverable the original is from the output. */
export type Recoverability =
  /** The original is not present in the output in any form. */
  | 'none'
  /** A declared portion is retained by design; the rest is gone. */
  | 'by-design'
  /** The output is a lossy encoding of the original and can be attacked. */
  | 'recoverable';

/** The safety properties of one strategy. */
export interface StrategySpec {
  readonly id: RedactionStrategy;
  /** Whether the original content is destroyed rather than covered. */
  readonly destructive: boolean;
  readonly recoverability: Recoverability;
  /** Content kinds this strategy can be applied to. */
  readonly appliesTo: readonly ('text' | 'region' | 'node')[];
  /** Whether the strategy keeps the same character count, preserving layout. */
  readonly preservesLength: boolean;
  readonly description: string;
  /**
   * For unsafe strategies, the published attack that defeats them. Surfaced in
   * the error message, because "this is unsafe" persuades nobody without it.
   */
  readonly knownAttack?: string;
}

const SPECS: Readonly<Record<RedactionStrategy, StrategySpec>> = {
  remove: {
    id: 'remove',
    destructive: true,
    recoverability: 'none',
    appliesTo: ['text', 'node'],
    preservesLength: false,
    description: 'Deletes the content entirely and closes the gap.',
  },
  replace: {
    id: 'replace',
    destructive: true,
    recoverability: 'none',
    appliesTo: ['text', 'node'],
    preservesLength: false,
    description: 'Substitutes fixed replacement text, leaving a visible marker that something was removed.',
  },
  mask: {
    id: 'mask',
    destructive: true,
    recoverability: 'by-design',
    appliesTo: ['text'],
    preservesLength: true,
    description: 'Retains a declared number of characters and destroys the rest, as in the last four digits of a card.',
  },
  pseudonymize: {
    id: 'pseudonymize',
    destructive: true,
    recoverability: 'none',
    appliesTo: ['text'],
    preservesLength: false,
    description:
      'Substitutes a stable token derived from the value under a secret key, so the same entity reads consistently across a corpus without disclosing it.',
  },
  synthesize: {
    id: 'synthesize',
    destructive: true,
    recoverability: 'none',
    appliesTo: ['text'],
    preservesLength: false,
    description:
      'Substitutes plausible fabricated data of the same type, for documents that must stay readable as examples.',
  },
  blackout: {
    id: 'blackout',
    destructive: true,
    recoverability: 'none',
    appliesTo: ['region'],
    preservesLength: false,
    description: 'Overwrites the pixels in a region with a solid colour.',
  },
  blur: {
    id: 'blur',
    destructive: false,
    recoverability: 'recoverable',
    appliesTo: ['region'],
    preservesLength: false,
    description: 'Applies a Gaussian blur. Retains the information in lower spatial frequencies.',
    knownAttack:
      'Blurring is a linear, deterministic transform. Rendering candidate text in the same font and blurring it with the same radius reproduces the output, which reduces recovery to a search over a small candidate set (Petro, Unredacter, 2022).',
  },
  pixelate: {
    id: 'pixelate',
    destructive: false,
    recoverability: 'recoverable',
    appliesTo: ['region'],
    preservesLength: false,
    description: 'Averages pixels into blocks. Each block is the mean of what it replaced.',
    knownAttack:
      'Each block preserves the mean of the pixels beneath it, which is enough to identify the source text by matching against rendered candidates (Depix; Petro, Unredacter, 2022). Positive Security demonstrated exact recovery from pixelated video without guessing (2022).',
  },
  scramble: {
    id: 'scramble',
    destructive: true,
    recoverability: 'none',
    appliesTo: ['region'],
    preservesLength: false,
    description:
      'Overwrites every pixel with deterministic noise. The replacement is a function of the operation, not of what it replaced, so nothing of the original survives.',
  },
  hatch: {
    id: 'hatch',
    destructive: true,
    recoverability: 'none',
    appliesTo: ['region'],
    preservesLength: false,
    description:
      'Fills the region and draws hazard stripes into the fill. Destroys as completely as a blackout, and cannot be mistaken for a scanning artifact.',
  },
};

/** The safety properties of a strategy. */
export function strategySpec(strategy: RedactionStrategy): StrategySpec {
  const spec = SPECS[strategy];
  if (spec === undefined) {
    throw new ClassifiedError('E_USAGE', `unknown redaction strategy ${JSON.stringify(strategy)}`, {
      strategy,
    });
  }
  return spec;
}

/** Every strategy the engine knows, for capability reporting and UI listings. */
export function allStrategies(): readonly StrategySpec[] {
  return Object.values(SPECS);
}

/** Strategies that produce a defensible redaction. */
export function safeStrategies(): readonly StrategySpec[] {
  return allStrategies().filter((s) => s.recoverability !== 'recoverable');
}

/** Controls the safety guard. */
export interface SafetyOptions {
  /**
   * Permit strategies whose output is recoverable.
   *
   * There are legitimate reasons to want one -- an illustration of what a bad
   * redaction looks like, a low-stakes screenshot where the visual effect
   * matters more than the secrecy -- so this is a decision the caller can make.
   * It is not a decision the caller can make silently: the manifest records it
   * and the result is marked as not defensible.
   */
  readonly allowRecoverableStrategies?: boolean;
}

/**
 * Reject a strategy that cannot deliver what the caller believes they are
 * getting.
 *
 * Called at plan time rather than apply time, so the refusal arrives while the
 * user is still deciding rather than after they have shipped the file.
 */
export function assertStrategyPermitted(
  strategy: RedactionStrategy,
  options: SafetyOptions = {},
): void {
  const spec = strategySpec(strategy);
  if (spec.recoverability !== 'recoverable') return;
  if (options.allowRecoverableStrategies === true) return;

  throw new ClassifiedError(
    'E_COSMETIC_REFUSED',
    `the "${strategy}" strategy does not destroy the content it covers and can be reversed. ${spec.knownAttack ?? ''} Use "blackout" for image regions, or pass allowRecoverableStrategies to accept a redaction that is not defensible.`,
    { strategy, recoverability: spec.recoverability, knownAttack: spec.knownAttack },
  );
}

/**
 * Whether a strategy can be applied to a location of the given kind.
 *
 * `blackout` on a text span is a category error -- it is the exact mistake that
 * produces a black rectangle over live text -- so the plan builder checks this
 * before an adapter is ever asked to perform it.
 */
export function strategySupportsLocation(
  strategy: RedactionStrategy,
  kind: 'text' | 'region' | 'node',
): boolean {
  return strategySpec(strategy).appliesTo.includes(kind);
}
