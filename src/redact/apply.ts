/**
 * Shared application helpers.
 *
 * Rewriting a string with a set of operations looks trivial and is not: spans
 * are expressed against the original offsets, so applying them left to right
 * invalidates every subsequent one. Getting this wrong shifts redactions by a
 * few characters and leaves the tail of each value exposed, which is a
 * disclosure that looks like a rendering bug.
 *
 * Adapters are free to write their own application logic, but this is the
 * correct implementation and they should use it.
 */

import { ClassifiedError } from '../errors.js';
import type { RedactionOperation } from './plan.js';

/** The result of rewriting one node's text. */
export interface TextRewrite {
  readonly text: string;
  /**
   * Offset mapping from original positions to new ones.
   *
   * Positions inside a removed span map to the start of its replacement.
   * Adapters that carry per-glyph geometry use this to keep boxes aligned after
   * the text length changes.
   */
  readonly mapOffset: (originalOffset: number) => number;
  /** Operations that were applied, in the order they took effect. */
  readonly applied: readonly RedactionOperation[];
}

/**
 * Rewrite a node's text according to the operations that target it.
 *
 * The output is built forward in one pass while the input offsets stay bound to
 * the original string, so no operation is ever read through a position another
 * operation already moved. Overlapping spans are rejected rather than silently
 * merged: two operations disagreeing about the same characters is a planning
 * error, and resolving it here would hide it.
 */
export function applyTextOperations(
  original: string,
  operations: readonly RedactionOperation[],
): TextRewrite {
  const spans = operations
    .filter((op) => op.location.kind === 'text')
    .map((op) => ({ op, span: op.location as { start: number; end: number } }))
    .sort((a, b) => a.span.start - b.span.start || a.span.end - b.span.end);

  for (let i = 1; i < spans.length; i++) {
    const previous = spans[i - 1]!;
    const current = spans[i]!;
    if (current.span.start < previous.span.end) {
      throw new ClassifiedError(
        'E_CONFLICT',
        `operations ${previous.op.id} and ${current.op.id} target overlapping spans of the same text`,
        {
          first: { id: previous.op.id, ...previous.span },
          second: { id: current.op.id, ...current.span },
        },
      );
    }
  }

  // Build the new string forward, recording each edit so the offset map can be
  // a walk over the edits rather than a per-character table.
  interface Edit {
    readonly from: number;
    readonly end: number;
    readonly newStart: number;
    readonly replacementLength: number;
  }

  const edits: Edit[] = [];
  let out = '';
  let cursor = 0;

  for (const { op, span } of spans) {
    out += original.slice(cursor, span.start);
    const replacement = replacementFor(op);
    edits.push({
      from: span.start,
      end: span.end,
      newStart: out.length,
      replacementLength: replacement.length,
    });
    out += replacement;
    cursor = span.end;
  }
  out += original.slice(cursor);

  const mapOffset = (offset: number): number => {
    let delta = 0;
    for (const edit of edits) {
      // Everything from here on starts after the offset, so no further edit
      // can shift it.
      if (offset < edit.from) break;
      // Inside a rewritten span: collapse to the start of its replacement,
      // which is where a caller drawing a box should begin.
      if (offset < edit.end) return edit.newStart;
      delta += edit.replacementLength - (edit.end - edit.from);
    }
    return offset + delta;
  };

  return { text: out, mapOffset, applied: spans.map((s) => s.op) };
}

function replacementFor(operation: RedactionOperation): string {
  switch (operation.strategy) {
    case 'remove':
      return '';
    case 'replace':
    case 'pseudonymize':
    case 'mask':
    case 'synthesize':
      return operation.replacement ?? '';
    default:
      throw new ClassifiedError(
        'E_UNSUPPORTED',
        `strategy "${operation.strategy}" cannot be applied to text`,
        { operationId: operation.id, strategy: operation.strategy },
      );
  }
}

/** Group operations by the node they target. */
export function groupOperationsByNode(
  operations: readonly RedactionOperation[],
): ReadonlyMap<string, RedactionOperation[]> {
  const grouped = new Map<string, RedactionOperation[]>();
  for (const operation of operations) {
    const bucket = grouped.get(operation.location.node);
    if (bucket) bucket.push(operation);
    else grouped.set(operation.location.node, [operation]);
  }
  return grouped;
}

/**
 * Overwrite a rectangular region of an RGBA buffer with a solid colour.
 *
 * The pixels are replaced, not composited: a fill with alpha below 255 would
 * leave the original values recoverable by inverting the blend, which is the
 * raster equivalent of drawing a box over live text. The alpha channel of the
 * fill is written as-is but the colour is not blended with what was underneath.
 */
/**
 * Replace a region with the average colour of each block.
 *
 * Offered because a face in a photograph is not a string: the search space is
 * not a dictionary, and covering it entirely destroys the evidentiary value of
 * the picture along with the identity. It is **not** a redaction, and the engine
 * says so everywhere it can -- {@link assertStrategyPermitted} refuses it
 * without an explicit opt-in, the plan records that the artifact contains a
 * recoverable strategy, and verification reports such an artifact as
 * unverifiable rather than passing it.
 *
 * Never use it on text. Unredacter recovers pixelated text by rendering
 * candidate strings through the same mosaic and matching the result; the block
 * averages are a lossy encoding of the original, not a destruction of it.
 */
export function pixelateRegion(
  pixels: Uint8ClampedArray,
  imageWidth: number,
  imageHeight: number,
  region: { x: number; y: number; width: number; height: number },
  blockSize: number,
): void {
  const x0 = Math.max(0, Math.floor(region.x));
  const y0 = Math.max(0, Math.floor(region.y));
  const x1 = Math.min(imageWidth, Math.ceil(region.x + region.width));
  const y1 = Math.min(imageHeight, Math.ceil(region.y + region.height));
  // Below four pixels a block averages so little that the mosaic is a
  // transparent film over the original rather than a transform of it.
  const size = Math.max(4, Math.floor(blockSize));

  for (let blockY = y0; blockY < y1; blockY += size) {
    const blockBottom = Math.min(blockY + size, y1);
    for (let blockX = x0; blockX < x1; blockX += size) {
      const blockRight = Math.min(blockX + size, x1);

      let r = 0, g = 0, b = 0, a = 0, count = 0;
      for (let y = blockY; y < blockBottom; y++) {
        let index = (y * imageWidth + blockX) * 4;
        for (let x = blockX; x < blockRight; x++) {
          r += pixels[index]!;
          g += pixels[index + 1]!;
          b += pixels[index + 2]!;
          a += pixels[index + 3]!;
          count++;
          index += 4;
        }
      }
      if (count === 0) continue;

      const avgR = Math.round(r / count);
      const avgG = Math.round(g / count);
      const avgB = Math.round(b / count);
      const avgA = Math.round(a / count);
      for (let y = blockY; y < blockBottom; y++) {
        let index = (y * imageWidth + blockX) * 4;
        for (let x = blockX; x < blockRight; x++) {
          pixels[index] = avgR;
          pixels[index + 1] = avgG;
          pixels[index + 2] = avgB;
          pixels[index + 3] = avgA;
          index += 4;
        }
      }
    }
  }
}

/**
 * A small deterministic generator, seeded from a string.
 *
 * Deterministic on purpose. `Math.random` would make a scrambled release
 * different on every run, which quietly costs the pipeline its reproducibility:
 * the manifest's promise is that re-running over the same input under the same
 * policy yields the same output digest, and a third party checking that claim
 * would find it false for any document containing noise. Seeding from the
 * operation gives noise that is unrelated to the pixels it replaces -- which is
 * all the destruction requires -- and the same noise every time.
 */
function seeded(seed: string): () => number {
  let h = 0x811c9dc5;
  for (let i = 0; i < seed.length; i++) {
    h ^= seed.charCodeAt(i);
    h = Math.imul(h, 0x01000193) >>> 0;
  }
  return () => {
    h ^= h << 13; h >>>= 0;
    h ^= h >> 17;
    h ^= h << 5; h >>>= 0;
    return h / 0x100000000;
  };
}

/**
 * Overwrite a region with noise.
 *
 * As destructive as a solid fill -- every channel of every pixel is replaced,
 * and the replacement is a function of the seed rather than of what was there.
 * It exists because a solid black rectangle on a scanned page is ambiguous: it
 * reads as a redaction to someone expecting one and as a scanning artifact or a
 * toner fault to someone who is not. Noise is unmistakably deliberate.
 */
export function scrambleRegion(
  pixels: Uint8ClampedArray,
  imageWidth: number,
  imageHeight: number,
  region: { x: number; y: number; width: number; height: number },
  seed: string,
): void {
  const x0 = Math.max(0, Math.floor(region.x));
  const y0 = Math.max(0, Math.floor(region.y));
  const x1 = Math.min(imageWidth, Math.ceil(region.x + region.width));
  const y1 = Math.min(imageHeight, Math.ceil(region.y + region.height));
  const next = seeded(seed);

  for (let y = y0; y < y1; y++) {
    let index = (y * imageWidth + x0) * 4;
    for (let x = x0; x < x1; x++) {
      const value = Math.floor(next() * 256);
      pixels[index] = value;
      pixels[index + 1] = value;
      pixels[index + 2] = value;
      pixels[index + 3] = 255;
      index += 4;
    }
  }
}

/**
 * Overwrite a region with hazard hatching.
 *
 * The region is filled solid first and the stripes are drawn into the fill, so
 * this destroys exactly as completely as a blackout -- the pattern is applied to
 * the replacement, never to the original. Some registries prefer it precisely
 * because a striped block cannot be mistaken for anything but an intentional
 * withholding.
 */
export function hatchRegion(
  pixels: Uint8ClampedArray,
  imageWidth: number,
  imageHeight: number,
  region: { x: number; y: number; width: number; height: number },
): void {
  const x0 = Math.max(0, Math.floor(region.x));
  const y0 = Math.max(0, Math.floor(region.y));
  const x1 = Math.min(imageWidth, Math.ceil(region.x + region.width));
  const y1 = Math.min(imageHeight, Math.ceil(region.y + region.height));

  // Scaled to the region, so the stripes stay legible on a thumbnail and do not
  // become a solid block on a large scan.
  const period = Math.max(6, Math.round(Math.min(x1 - x0, y1 - y0) / 6));
  const bar = Math.max(2, Math.round(period * 0.45));

  for (let y = y0; y < y1; y++) {
    let index = (y * imageWidth + x0) * 4;
    for (let x = x0; x < x1; x++) {
      const on = (((x - x0 + (y - y0)) % period) + period) % period < bar;
      const value = on ? 34 : 12;
      pixels[index] = value;
      pixels[index + 1] = value;
      pixels[index + 2] = value;
      pixels[index + 3] = 255;
      index += 4;
    }
  }
}

export function blackoutRegion(
  pixels: Uint8ClampedArray,
  imageWidth: number,
  imageHeight: number,
  region: { x: number; y: number; width: number; height: number },
  fill: readonly [number, number, number, number] = [0, 0, 0, 255],
): void {
  const x0 = Math.max(0, Math.floor(region.x));
  const y0 = Math.max(0, Math.floor(region.y));
  const x1 = Math.min(imageWidth, Math.ceil(region.x + region.width));
  const y1 = Math.min(imageHeight, Math.ceil(region.y + region.height));

  const [r, g, b] = fill;
  // Alpha is forced opaque. A fill of `[0,0,0,0]` would punch a transparent
  // hole: the RGB is gone from this buffer, but compositing the result over a
  // known background recovers it. That is the raster equivalent of a covering
  // rectangle, and this function exists to prevent that.
  for (let y = y0; y < y1; y++) {
    let index = (y * imageWidth + x0) * 4;
    for (let x = x0; x < x1; x++) {
      pixels[index] = r;
      pixels[index + 1] = g;
      pixels[index + 2] = b;
      pixels[index + 3] = 255;
      index += 4;
    }
  }
}
