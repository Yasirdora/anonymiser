/**
 * JPEG and PNG container surgery.
 *
 * Both formats are sequences of length-prefixed blocks, which means metadata
 * can be located and excised without decoding a single pixel. That matters:
 * decode-and-re-encode strips metadata as a side effect but also recompresses
 * the image, degrading it and changing every byte. Cutting the blocks out
 * leaves the image data bit-identical and removes only what was asked for.
 *
 * Written against the container specifications directly, with no dependency and
 * no decoder.
 */

import { ClassifiedError } from '../../errors.js';
import { readExif, type ExifField } from './exif.js';

/** A metadata block found in a container. */
export interface MetadataBlock {
  /** Block identifier: a JPEG marker name or a PNG chunk type. */
  readonly kind: string;
  /** Byte offset of the block within the file. */
  readonly offset: number;
  readonly length: number;
  /** What the block carries, when it is recognised. */
  readonly description: string;
  /** Decoded fields, for EXIF blocks. */
  readonly fields?: readonly ExifField[];
  /** Decoded text, for textual blocks. */
  readonly text?: string;
}

/** What a container scan found. */
export interface ContainerScan {
  readonly format: 'jpeg' | 'png' | 'unknown';
  readonly blocks: readonly MetadataBlock[];
  /** Total bytes occupied by removable metadata. */
  readonly metadataBytes: number;
}

const JPEG_SOI = 0xffd8;
const PNG_SIGNATURE = [0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a];

/** Identify the container format from its leading bytes. */
export function detectFormat(bytes: Uint8Array): ContainerScan['format'] {
  if (bytes.length >= 2 && ((bytes[0]! << 8) | bytes[1]!) === JPEG_SOI) return 'jpeg';
  if (bytes.length >= 8 && PNG_SIGNATURE.every((b, i) => bytes[i] === b)) return 'png';
  return 'unknown';
}

/** Locate every metadata block, without modifying anything. */
export function scanContainer(bytes: Uint8Array): ContainerScan {
  const format = detectFormat(bytes);
  const blocks =
    format === 'jpeg' ? scanJpeg(bytes) : format === 'png' ? scanPng(bytes) : [];
  return {
    format,
    blocks,
    metadataBytes: blocks.reduce((sum, b) => sum + b.length, 0),
  };
}

/**
 * Remove every metadata block, leaving the image data untouched.
 *
 * Returns the original array when there is nothing to remove, so callers can
 * detect a no-op by identity.
 */
export function stripMetadata(bytes: Uint8Array): Uint8Array {
  const scan = scanContainer(bytes);
  if (scan.blocks.length === 0) return bytes;

  const ranges = scan.blocks
    .map((b) => ({ start: b.offset, end: b.offset + b.length }))
    .sort((a, b) => a.start - b.start);

  const out = new Uint8Array(bytes.length - scan.metadataBytes);
  let write = 0;
  let read = 0;
  for (const range of ranges) {
    const keep = range.start - read;
    if (keep > 0) {
      out.set(bytes.subarray(read, range.start), write);
      write += keep;
    }
    read = range.end;
  }
  if (read < bytes.length) out.set(bytes.subarray(read), write);

  // PNG has no length field spanning the file, so removing chunks needs no
  // fix-up. JPEG segments are self-delimiting for the same reason.
  return out;
}

/**
 * Walk JPEG markers.
 *
 * Segments run from the SOI to the start of scan; after SOS the file is entropy
 * -coded image data with no further segment structure worth walking, so the
 * scan stops there rather than trying to interpret compressed bytes as markers.
 */
function scanJpeg(bytes: Uint8Array): MetadataBlock[] {
  const blocks: MetadataBlock[] = [];
  let offset = 2; // past SOI

  while (offset + 4 <= bytes.length) {
    if (bytes[offset] !== 0xff) {
      // Fill bytes are legal between segments; anything else means the stream
      // is malformed or we have run into image data.
      offset++;
      continue;
    }
    const marker = bytes[offset + 1]!;

    // Standalone markers carry no length.
    if (marker === 0xd8 || (marker >= 0xd0 && marker <= 0xd9) || marker === 0x01) {
      offset += 2;
      continue;
    }
    // Start of scan: compressed data follows.
    if (marker === 0xda) break;

    const length = (bytes[offset + 2]! << 8) | bytes[offset + 3]!;
    if (length < 2 || offset + 2 + length > bytes.length) break;

    const payload = bytes.subarray(offset + 4, offset + 2 + length);
    const block = describeJpegSegment(marker, payload, offset, length + 2);
    if (block !== undefined) blocks.push(block);

    offset += 2 + length;
  }

  return blocks;
}

function describeJpegSegment(
  marker: number,
  payload: Uint8Array,
  offset: number,
  totalLength: number,
): MetadataBlock | undefined {
  // APP1: EXIF or XMP.
  if (marker === 0xe1) {
    if (startsWithAscii(payload, 'Exif\0\0')) {
      return {
        kind: 'APP1/Exif',
        offset,
        length: totalLength,
        description: 'EXIF metadata: camera, timestamps, and possibly GPS coordinates',
        fields: readExif(payload.subarray(6)),
      };
    }
    if (startsWithAscii(payload, 'http://ns.adobe.com/xap/1.0/')) {
      return {
        kind: 'APP1/XMP',
        offset,
        length: totalLength,
        description: 'XMP metadata: authorship, editing history, and application state',
        text: decodeAscii(payload).slice(0, 4096),
      };
    }
    return { kind: 'APP1', offset, length: totalLength, description: 'application metadata segment' };
  }

  // APP13: Photoshop IRB, which carries IPTC captions and credits.
  if (marker === 0xed) {
    return {
      kind: 'APP13/IPTC',
      offset,
      length: totalLength,
      description: 'IPTC metadata: caption, credit, byline, and location fields',
      text: decodeAscii(payload).slice(0, 4096),
    };
  }

  // APP2 with an ICC profile is colour management, not metadata; removing it
  // changes how the image renders and is not this function's business.
  if (marker === 0xe2 && startsWithAscii(payload, 'ICC_PROFILE')) return undefined;

  // Remaining APPn segments are vendor extensions of unknown content. They are
  // removed because "unknown content written by the capture device" is exactly
  // the category that has historically carried serial numbers and location.
  if (marker >= 0xe0 && marker <= 0xef) {
    if (marker === 0xe0) return undefined; // APP0/JFIF is structural
    return {
      kind: `APP${marker - 0xe0}`,
      offset,
      length: totalLength,
      description: 'vendor application segment of unknown content',
    };
  }

  // COM: free-text comment.
  if (marker === 0xfe) {
    return {
      kind: 'COM',
      offset,
      length: totalLength,
      description: 'embedded comment',
      text: decodeAscii(payload).slice(0, 4096),
    };
  }

  return undefined;
}

/**
 * Walk PNG chunks.
 *
 * Every chunk is `length | type | data | crc`, so the walk is exact and any
 * inconsistency means the file is truncated or corrupt.
 */
function scanPng(bytes: Uint8Array): MetadataBlock[] {
  const blocks: MetadataBlock[] = [];
  let offset = 8; // past the signature

  while (offset + 12 <= bytes.length) {
    const length =
      (bytes[offset]! << 24) | (bytes[offset + 1]! << 16) | (bytes[offset + 2]! << 8) | bytes[offset + 3]!;
    if (length < 0 || offset + 12 + length > bytes.length) break;

    const type = decodeAscii(bytes.subarray(offset + 4, offset + 8));
    const data = bytes.subarray(offset + 8, offset + 8 + length);
    const total = length + 12;

    const block = describePngChunk(type, data, offset, total);
    if (block !== undefined) blocks.push(block);

    if (type === 'IEND') break;
    offset += total;
  }

  return blocks;
}

function describePngChunk(
  type: string,
  data: Uint8Array,
  offset: number,
  totalLength: number,
): MetadataBlock | undefined {
  switch (type) {
    case 'tEXt':
    case 'iTXt':
      return {
        kind: type,
        offset,
        length: totalLength,
        description: 'textual metadata chunk',
        text: decodeAscii(data).replace(/\0/g, ': ').slice(0, 4096),
      };
    case 'zTXt':
      return {
        kind: type,
        offset,
        length: totalLength,
        description: 'compressed textual metadata chunk',
      };
    case 'eXIf':
      return {
        kind: type,
        offset,
        length: totalLength,
        description: 'EXIF metadata: camera, timestamps, and possibly GPS coordinates',
        fields: readExif(data),
      };
    case 'tIME':
      return { kind: type, offset, length: totalLength, description: 'last-modification timestamp' };
    case 'dSIG':
      return { kind: type, offset, length: totalLength, description: 'digital signature chunk' };
    default:
      return undefined;
  }
}

function startsWithAscii(bytes: Uint8Array, prefix: string): boolean {
  if (bytes.length < prefix.length) return false;
  for (let i = 0; i < prefix.length; i++) {
    if (bytes[i] !== prefix.charCodeAt(i)) return false;
  }
  return true;
}

function decodeAscii(bytes: Uint8Array): string {
  let out = '';
  for (let i = 0; i < bytes.length; i++) out += String.fromCharCode(bytes[i]!);
  return out;
}

/** Read a PNG's declared dimensions from its IHDR chunk. */
export function pngDimensions(bytes: Uint8Array): { width: number; height: number } {
  if (detectFormat(bytes) !== 'png' || bytes.length < 24) {
    throw new ClassifiedError('E_PARSE', 'not a PNG, or the header is truncated', {});
  }
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  return { width: view.getUint32(16), height: view.getUint32(20) };
}

/** Read a JPEG's dimensions from its first start-of-frame marker. */
export function jpegDimensions(bytes: Uint8Array): { width: number; height: number } {
  let offset = 2;
  while (offset + 9 <= bytes.length) {
    if (bytes[offset] !== 0xff) {
      offset++;
      continue;
    }
    const marker = bytes[offset + 1]!;
    // SOF0-SOF15, excluding the DHT, JPG, and DAC markers that share the range.
    if (marker >= 0xc0 && marker <= 0xcf && marker !== 0xc4 && marker !== 0xc8 && marker !== 0xcc) {
      const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
      return { height: view.getUint16(offset + 5), width: view.getUint16(offset + 7) };
    }
    if (marker === 0xda || marker === 0xd9) break;
    if (marker === 0xd8 || (marker >= 0xd0 && marker <= 0xd7) || marker === 0x01) {
      offset += 2;
      continue;
    }
    const length = (bytes[offset + 2]! << 8) | bytes[offset + 3]!;
    if (length < 2) break;
    offset += 2 + length;
  }
  throw new ClassifiedError('E_PARSE', 'no start-of-frame marker found in the JPEG', {});
}
