/**
 * DEFLATE decompression (RFC 1951) and the zlib wrapper (RFC 1950).
 *
 * Almost every stream in a PDF is Flate-encoded, so nothing can be read out of
 * one without this. Browsers ship `DecompressionStream` and Node ships `zlib`,
 * but both are async or platform-specific, and the engine's contract is a
 * synchronous, isomorphic core with no host dependencies. So it is implemented
 * here: fixed and dynamic Huffman blocks, stored blocks, and the LZ77 window.
 *
 * Roughly 200 lines, and it is the price of being able to say the engine has no
 * dependencies and means it.
 */

import { ClassifiedError } from '../../errors.js';

/** Bit reader, least-significant-bit first, as DEFLATE requires. */
class BitReader {
  readonly #data: Uint8Array;
  #position = 0;
  #bitBuffer = 0;
  #bitCount = 0;

  constructor(data: Uint8Array) {
    this.#data = data;
  }

  /** Read `count` bits (0-24), LSB first. */
  bits(count: number): number {
    while (this.#bitCount < count) {
      if (this.#position >= this.#data.length) {
        throw new ClassifiedError('E_PARSE', 'compressed stream ended mid-symbol', {});
      }
      this.#bitBuffer |= this.#data[this.#position++]! << this.#bitCount;
      this.#bitCount += 8;
    }
    const value = this.#bitBuffer & ((1 << count) - 1);
    this.#bitBuffer >>>= count;
    this.#bitCount -= count;
    return value;
  }

  /** Discard bits up to the next byte boundary. */
  alignToByte(): void {
    this.#bitBuffer = 0;
    this.#bitCount = 0;
  }

  /** Read whole bytes directly, for stored blocks. */
  bytes(count: number): Uint8Array {
    if (this.#position + count > this.#data.length) {
      throw new ClassifiedError('E_PARSE', 'stored block runs past the end of the stream', {});
    }
    const out = this.#data.subarray(this.#position, this.#position + count);
    this.#position += count;
    return out;
  }

  get exhausted(): boolean {
    return this.#position >= this.#data.length && this.#bitCount === 0;
  }
}

/**
 * A canonical Huffman decoding table.
 *
 * Built as counts-per-length plus symbols-in-order, which is the compact form
 * RFC 1951 section 3.2.2 describes and decodes with one comparison per bit.
 */
interface HuffmanTable {
  readonly counts: Uint16Array;
  readonly symbols: Uint16Array;
}

function buildHuffman(lengths: Uint8Array | number[]): HuffmanTable {
  const counts = new Uint16Array(16);
  for (const length of lengths) counts[length]!++;
  counts[0] = 0;

  const offsets = new Uint16Array(16);
  for (let i = 1; i < 16; i++) offsets[i] = offsets[i - 1]! + counts[i - 1]!;

  const symbols = new Uint16Array(lengths.length);
  for (let symbol = 0; symbol < lengths.length; symbol++) {
    const length = lengths[symbol]!;
    if (length !== 0) symbols[offsets[length]!++] = symbol;
  }
  return { counts, symbols };
}

function decodeSymbol(reader: BitReader, table: HuffmanTable): number {
  let code = 0;
  let first = 0;
  let index = 0;
  for (let length = 1; length < 16; length++) {
    code |= reader.bits(1);
    const count = table.counts[length]!;
    if (code - first < count) return table.symbols[index + (code - first)]!;
    index += count;
    first = (first + count) << 1;
    code <<= 1;
  }
  throw new ClassifiedError('E_PARSE', 'invalid Huffman code in compressed stream', {});
}

// RFC 1951 section 3.2.5: length and distance base values and extra-bit counts.
const LENGTH_BASE = [
  3, 4, 5, 6, 7, 8, 9, 10, 11, 13, 15, 17, 19, 23, 27, 31, 35, 43, 51, 59, 67, 83, 99, 115,
  131, 163, 195, 227, 258,
];
const LENGTH_EXTRA = [
  0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2, 3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5, 0,
];
const DISTANCE_BASE = [
  1, 2, 3, 4, 5, 7, 9, 13, 17, 25, 33, 49, 65, 97, 129, 193, 257, 385, 513, 769, 1025, 1537,
  2049, 3073, 4097, 6145, 8193, 12289, 16385, 24577,
];
const DISTANCE_EXTRA = [
  0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6, 7, 7, 8, 8, 9, 9, 10, 10, 11, 11, 12, 12, 13, 13,
];
/** Order in which code-length code lengths appear in a dynamic block header. */
const CODE_LENGTH_ORDER = [16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15];

let fixedLiteral: HuffmanTable | undefined;
let fixedDistance: HuffmanTable | undefined;

function fixedTables(): { literal: HuffmanTable; distance: HuffmanTable } {
  if (fixedLiteral === undefined || fixedDistance === undefined) {
    const literalLengths = new Uint8Array(288);
    literalLengths.fill(8, 0, 144);
    literalLengths.fill(9, 144, 256);
    literalLengths.fill(7, 256, 280);
    literalLengths.fill(8, 280, 288);
    fixedLiteral = buildHuffman(literalLengths);
    fixedDistance = buildHuffman(new Uint8Array(30).fill(5));
  }
  return { literal: fixedLiteral, distance: fixedDistance };
}

/** Hard cap so a hostile Flate stream cannot exhaust the tab. */
const MAX_INFLATE_BYTES = 64 * 1024 * 1024;

/** Growable output buffer. The LZ77 window reads back into what is written. */
class OutputBuffer {
  #data: Uint8Array;
  #length = 0;
  readonly #limit: number;

  constructor(initial = 1 << 16, limit = MAX_INFLATE_BYTES) {
    this.#limit = limit;
    this.#data = new Uint8Array(Math.min(initial, limit));
  }

  #ensure(extra: number): void {
    const needed = this.#length + extra;
    if (needed > this.#limit) {
      throw new ClassifiedError(
        'E_PARSE',
        `decompressed stream exceeded ${this.#limit} bytes; refusing a possible decompression bomb`,
        { limit: this.#limit, requested: needed },
      );
    }
    if (needed <= this.#data.length) return;
    let size = this.#data.length * 2;
    while (size < needed) size *= 2;
    if (size > this.#limit) size = this.#limit;
    const grown = new Uint8Array(size);
    grown.set(this.#data.subarray(0, this.#length));
    this.#data = grown;
  }

  push(byte: number): void {
    this.#ensure(1);
    this.#data[this.#length++] = byte;
  }

  append(bytes: Uint8Array): void {
    this.#ensure(bytes.length);
    this.#data.set(bytes, this.#length);
    this.#length += bytes.length;
  }

  /**
   * Copy `length` bytes from `distance` back.
   *
   * Copied one byte at a time on purpose: an LZ77 match may overlap its own
   * output (distance 1, length 100 means "repeat this byte 100 times"), so a
   * bulk copy would read bytes that have not been written yet.
   */
  copyBack(distance: number, length: number): void {
    if (distance > this.#length) {
      throw new ClassifiedError('E_PARSE', 'back-reference points before the start of the stream', {
        distance,
        available: this.#length,
      });
    }
    this.#ensure(length);
    let from = this.#length - distance;
    for (let i = 0; i < length; i++) this.#data[this.#length++] = this.#data[from++]!;
  }

  toBytes(): Uint8Array {
    return this.#data.slice(0, this.#length);
  }
}

/** Decompress a raw DEFLATE stream (no zlib header). */
export function inflateRaw(data: Uint8Array): Uint8Array {
  const reader = new BitReader(data);
  const out = new OutputBuffer(Math.max(1 << 16, data.length * 4));

  for (;;) {
    const isFinal = reader.bits(1);
    const type = reader.bits(2);

    if (type === 0) {
      reader.alignToByte();
      // The stored-block header is four bytes: length, then its complement.
      const header = reader.bytes(4);
      const length = header[0]! | (header[1]! << 8);
      const check = header[2]! | (header[3]! << 8);
      if ((length ^ 0xffff) !== check) {
        throw new ClassifiedError('E_PARSE', 'stored block length check failed', {});
      }
      out.append(reader.bytes(length));
    } else if (type === 1 || type === 2) {
      let literal: HuffmanTable;
      let distance: HuffmanTable;

      if (type === 1) {
        ({ literal, distance } = fixedTables());
      } else {
        const literalCount = reader.bits(5) + 257;
        const distanceCount = reader.bits(5) + 1;
        const codeLengthCount = reader.bits(4) + 4;

        const codeLengths = new Uint8Array(19);
        for (let i = 0; i < codeLengthCount; i++) {
          codeLengths[CODE_LENGTH_ORDER[i]!] = reader.bits(3);
        }
        const codeLengthTable = buildHuffman(codeLengths);

        // Literal and distance lengths share one run-length-coded sequence.
        const lengths = new Uint8Array(literalCount + distanceCount);
        let index = 0;
        while (index < lengths.length) {
          const symbol = decodeSymbol(reader, codeLengthTable);
          if (symbol < 16) {
            lengths[index++] = symbol;
          } else if (symbol === 16) {
            const previous = index > 0 ? lengths[index - 1]! : 0;
            let repeat = 3 + reader.bits(2);
            while (repeat-- > 0 && index < lengths.length) lengths[index++] = previous;
          } else if (symbol === 17) {
            let repeat = 3 + reader.bits(3);
            while (repeat-- > 0 && index < lengths.length) lengths[index++] = 0;
          } else {
            let repeat = 11 + reader.bits(7);
            while (repeat-- > 0 && index < lengths.length) lengths[index++] = 0;
          }
        }

        literal = buildHuffman(lengths.subarray(0, literalCount));
        distance = buildHuffman(lengths.subarray(literalCount));
      }

      for (;;) {
        const symbol = decodeSymbol(reader, literal);
        if (symbol === 256) break;
        if (symbol < 256) {
          out.push(symbol);
          continue;
        }
        const lengthIndex = symbol - 257;
        if (lengthIndex >= LENGTH_BASE.length) {
          throw new ClassifiedError('E_PARSE', 'invalid length symbol in compressed stream', { symbol });
        }
        const length = LENGTH_BASE[lengthIndex]! + reader.bits(LENGTH_EXTRA[lengthIndex]!);
        const distanceSymbol = decodeSymbol(reader, distance);
        if (distanceSymbol >= DISTANCE_BASE.length) {
          throw new ClassifiedError('E_PARSE', 'invalid distance symbol in compressed stream', {});
        }
        const back = DISTANCE_BASE[distanceSymbol]! + reader.bits(DISTANCE_EXTRA[distanceSymbol]!);
        out.copyBack(back, length);
      }
    } else {
      throw new ClassifiedError('E_PARSE', 'reserved block type in compressed stream', { type });
    }

    if (isFinal) break;
    if (reader.exhausted) break;
  }

  return out.toBytes();
}

/**
 * Decompress a zlib stream (RFC 1950): two header bytes, then DEFLATE.
 *
 * The Adler-32 trailer is not verified. A PDF whose stream is subtly corrupt is
 * still a PDF whose text must be examined, and refusing to read it would hide
 * exactly the content the caller is trying to check.
 */
export function inflate(data: Uint8Array): Uint8Array {
  if (data.length < 2) {
    throw new ClassifiedError('E_PARSE', 'stream too short to be zlib-compressed', {});
  }
  const cmf = data[0]!;
  const flg = data[1]!;
  const looksLikeZlib = (cmf & 0x0f) === 8 && ((cmf << 8) | flg) % 31 === 0;
  return inflateRaw(looksLikeZlib ? data.subarray(2) : data);
}
