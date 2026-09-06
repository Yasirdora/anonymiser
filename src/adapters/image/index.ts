/**
 * The image adapter.
 *
 * Operates on decoded RGBA pixels and, separately, on the container bytes that
 * carry metadata. Splitting the two is what keeps the adapter dependency-free
 * and universal: the caller decodes pixels with whatever their platform already
 * has -- a `<canvas>`, an `OffscreenCanvas`, a native decoder -- and this
 * adapter does the parts that are actually about redaction.
 *
 * Region redaction here is destructive by construction. The pixels under a
 * blackout are overwritten in the buffer, so there is nothing underneath to
 * recover; blur and pixelate are refused at plan time by the safety model,
 * which is the correct answer for an image tool and the opposite of what every
 * other one does.
 */

import { toHex } from '../../internal/bytes.js';
import { sha256 } from '../../internal/hash.js';
import { ClassifiedError } from '../../errors.js';
import type { AdapterCapabilities, DocumentAdapter, ParseOptions } from '../../adapter.js';
import type { ContentNode, DocumentModel } from '../../model/document.js';
import { snapRectOutward, type Rect } from '../../model/geometry.js';
import { blackoutRegion, hatchRegion, pixelateRegion, scrambleRegion, syntheticPixelateRegion } from '../../redact/apply.js';
import { assertStrategyPermitted } from '../../redact/strategies.js';
import type { RedactionOperation } from '../../redact/plan.js';
import { gpsToDecimal } from './exif.js';
import { detectFormat, scanContainer, stripMetadata } from './container.js';

export * from './exif.js';
export * from './container.js';

/** An image as this adapter sees it. */
export interface RasterDocument {
  readonly width: number;
  readonly height: number;
  /** RGBA, 8 bits per channel, row-major, length `width * height * 4`. */
  readonly pixels: Uint8ClampedArray;
  /**
   * The original container bytes, when available.
   *
   * Supplying these lets the adapter report and strip metadata. Without them it
   * can still redact pixels, but it cannot tell the caller that the file it
   * came from carries GPS coordinates.
   */
  readonly container?: Uint8Array;
  /** Text recovered from the image by OCR, when the caller has run it. */
  readonly ocr?: readonly OcrBlock[];
}

/** A recognised block of text with its position in the image. */
export interface OcrBlock {
  readonly id: string;
  readonly text: string;
  readonly rect: Rect;
  /** OCR engine confidence in `[0, 1]`, when reported. */
  readonly confidence?: number;
}

const CAPABILITIES: AdapterCapabilities = {
  strategies: ['blackout', 'remove', 'pixelate', 'scramble', 'hatch', 'synthetic-mosaic'],
  removesMetadata: true,
  removesAttachments: false,
  removesRevisionHistory: false,
  verifiable: true,
};

/**
 * Padding added around every burned-in region, in pixels.
 *
 * Glyph and OCR bounding boxes routinely under-report by a pixel or two at the
 * edges, and a bar that clips a descender leaves a legible sliver of the
 * character below it. Two pixels costs nothing visually and closes that gap.
 */
const REGION_PADDING = 2;

export const imageAdapter: DocumentAdapter<RasterDocument, RasterDocument> = {
  id: 'image',
  version: '1.0.0',
  mediaTypes: ['image/png', 'image/jpeg', 'image/webp', 'image/bmp'],
  capabilities: CAPABILITIES,

  parse(source: RasterDocument, options: ParseOptions = {}): DocumentModel {
    const expected = source.width * source.height * 4;
    if (source.pixels.length !== expected) {
      throw new ClassifiedError(
        'E_PARSE',
        `pixel buffer is ${source.pixels.length} bytes; ${source.width}x${source.height} RGBA needs ${expected}`,
        { width: source.width, height: source.height, received: source.pixels.length },
      );
    }

    const nodes: ContentNode[] = [];
    const pageRect: Rect = { x: 0, y: 0, width: source.width, height: source.height };

    nodes.push({
      id: 'image',
      kind: 'raster',
      page: 0,
      bbox: pageRect,
      role: 'page',
      raster: { width: source.width, height: source.height, pixels: source.pixels },
    });

    // OCR output is what makes an image searchable by the classification and
    // detection layers. Without it a photograph of a passport is opaque to
    // every text rule in the engine, which is how scanned documents end up
    // released unredacted.
    for (const block of source.ocr ?? []) {
      nodes.push({
        id: `ocr:${block.id}`,
        kind: 'text',
        parent: 'image',
        page: 0,
        bbox: block.rect,
        role: 'paragraph',
        text: block.text,
        attrs: {
          source: 'ocr',
          ...(block.confidence !== undefined ? { confidence: String(block.confidence) } : {}),
        },
      });
    }

    if (source.container !== undefined) {
      nodes.push(...metadataNodes(source.container));
    }

    const digest = toHex(
      sha256(source.container ?? new Uint8Array(source.pixels.buffer.slice(0))),
    );

    return {
      id: options.documentId ?? `img_${digest.slice(0, 16)}`,
      mediaType: mediaTypeFor(source.container),
      adapterId: 'image',
      origin: 'top-left',
      pages: [pageRect],
      nodes,
      sourceDigest: digest,
      ...(source.container !== undefined ? { raw: source.container } : {}),
    };
  },

  apply(model: DocumentModel, operations: readonly RedactionOperation[]): RasterDocument {
    const imageNode = model.nodes.find((n) => n.kind === 'raster');
    if (imageNode?.raster === undefined) {
      throw new ClassifiedError('E_PARSE', 'the model contains no raster node', {
        modelId: model.id,
      });
    }

    const { width, height } = imageNode.raster;
    // Copy before writing: `apply` must not mutate its input, or a failed
    // verification would leave the caller holding a half-redacted original.
    const pixels = new Uint8ClampedArray(imageNode.raster.pixels);

    let stripAllMetadata = false;
    let pixelOps = false;

    for (const operation of operations) {
      switch (operation.location.kind) {
        case 'region': {
          pixelOps = true;
          const raster = ['blackout', 'pixelate', 'scramble', 'hatch', 'synthetic-mosaic'] as const;
          if (!(raster as readonly string[]).includes(operation.strategy)) {
            throw new ClassifiedError(
              'E_UNSUPPORTED',
              `the image adapter applies only ${raster.map((s) => `"${s}"`).join(', ')} to regions, not "${operation.strategy}"`,
              { operationId: operation.id, strategy: operation.strategy },
            );
          }
          // Refuses unless the caller has said, in so many words, that it will
          // accept an artifact that is not defensible. The check lives here
          // rather than in the caller so that no host can reach the mosaic by
          // building operations directly.
          assertStrategyPermitted(operation.strategy, {
            allowRecoverableStrategies: operation.acknowledgedRecoverable === true,
          });
          const padded = snapRectOutward(inflate(operation.location.rect, REGION_PADDING));
          if (operation.strategy === 'pixelate') {
            pixelateRegion(pixels, width, height, padded, operation.blockSize ?? 16);
          } else if (operation.strategy === 'synthetic-mosaic') {
            syntheticPixelateRegion(pixels, width, height, padded, operation.blockSize ?? 16, operation.id);
          } else if (operation.strategy === 'scramble') {
            scrambleRegion(pixels, width, height, padded, operation.id);
          } else if (operation.strategy === 'hatch') {
            hatchRegion(pixels, width, height, padded);
          } else {
            blackoutRegion(pixels, width, height, padded, operation.fill ?? [0, 0, 0, 255]);
          }
          break;
        }
        case 'text': {
          // A text operation on an OCR block redacts the pixels it covers.
          // There is no text layer in an image to edit, so the box is the only
          // meaningful action, and it must destroy rather than cover.
          const node = model.nodes.find((n) => n.id === operation.location.node);
          if (node?.bbox === undefined) break;
          pixelOps = true;
          const padded = snapRectOutward(inflate(node.bbox, REGION_PADDING));
          blackoutRegion(pixels, width, height, padded, operation.fill ?? [0, 0, 0, 255]);
          break;
        }
        case 'node': {
          const node = model.nodes.find((n) => n.id === operation.location.node);
          if (node?.kind === 'metadata') stripAllMetadata = true;
          else if (node?.bbox !== undefined) {
            pixelOps = true;
            blackoutRegion(
              pixels,
              width,
              height,
              snapRectOutward(inflate(node.bbox, REGION_PADDING)),
              operation.fill ?? [0, 0, 0, 255],
            );
          }
          break;
        }
      }
    }

    // Pixel edits live in `pixels`. Returning the original JPEG/PNG alongside
    // them would ship the unredacted photograph to any host that saved
    // `output.container`. Metadata-only runs may still hand back a scrubbed
    // container so a publish with nothing painted stays bit-identical.
    const container = pixelOps
      ? undefined
      : stripAllMetadata && model.raw !== undefined
        ? stripMetadata(model.raw)
        : model.raw;

    return {
      width,
      height,
      pixels,
      ...(container !== undefined ? { container } : {}),
    };
  },

  reparse(output: RasterDocument): DocumentModel {
    return imageAdapter.parse(output);
  },
};

/**
 * Turn container metadata into model nodes.
 *
 * Each field becomes a node the detection and classification layers can see, so
 * a GPS coordinate in EXIF is classified by exactly the same rule as one written
 * in the body of a report. Decoding coordinates into decimal degrees here is
 * what lets the geo detector recognise them at all -- as raw EXIF rationals they
 * match nothing.
 */
function metadataNodes(container: Uint8Array): ContentNode[] {
  const scan = scanContainer(container);
  const nodes: ContentNode[] = [];

  for (const block of scan.blocks) {
    if (block.fields !== undefined) {
      const byName = new Map(block.fields.map((f) => [f.name, f.value]));

      for (const field of block.fields) {
        nodes.push({
          id: `exif:${field.ifd}:${field.name}`,
          kind: 'metadata',
          text: field.value,
          attrs: { key: field.name, ifd: field.ifd, block: block.kind },
        });
      }

      const latitude = byName.get('GPSLatitude');
      const longitude = byName.get('GPSLongitude');
      if (latitude !== undefined && longitude !== undefined) {
        const lat = gpsToDecimal(latitude, byName.get('GPSLatitudeRef') ?? 'N');
        const lon = gpsToDecimal(longitude, byName.get('GPSLongitudeRef') ?? 'E');
        if (lat !== undefined && lon !== undefined) {
          nodes.push({
            id: 'exif:GPS:decimal',
            kind: 'metadata',
            text: `${lat.toFixed(6)}, ${lon.toFixed(6)}`,
            attrs: { key: 'GPSPosition', ifd: 'GPS', block: block.kind },
          });
        }
      }
      continue;
    }

    if (block.text !== undefined && block.text.trim() !== '') {
      nodes.push({
        id: `meta:${block.kind}:${block.offset}`,
        kind: 'metadata',
        text: block.text,
        attrs: { key: block.kind, block: block.kind },
      });
      continue;
    }

    nodes.push({
      id: `meta:${block.kind}:${block.offset}`,
      kind: 'metadata',
      text: block.description,
      attrs: { key: block.kind, block: block.kind, opaque: 'true' },
    });
  }

  return nodes;
}

function inflate(rect: Rect, padding: number): Rect {
  return {
    x: rect.x - padding,
    y: rect.y - padding,
    width: rect.width + padding * 2,
    height: rect.height + padding * 2,
  };
}

function mediaTypeFor(container: Uint8Array | undefined): string {
  if (container === undefined) return 'image/x-rgba';
  switch (detectFormat(container)) {
    case 'jpeg':
      return 'image/jpeg';
    case 'png':
      return 'image/png';
    default:
      return 'application/octet-stream';
  }
}

/**
 * Scrub a container's metadata without touching its pixels.
 *
 * The common case, and worth having as a one-liner: publishing a photograph
 * usually needs no pixel redaction at all, only the removal of the GPS
 * coordinates and device serial number the camera wrote into it.
 */
export function scrubImageMetadata(container: Uint8Array): {
  readonly bytes: Uint8Array;
  readonly removed: ReturnType<typeof scanContainer>;
} {
  const removed = scanContainer(container);
  return { bytes: stripMetadata(container), removed };
}
