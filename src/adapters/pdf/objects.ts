/**
 * PDF object syntax: the lexer, the object store, and stream decoding.
 *
 * The object store is built by scanning the whole file for `N G obj` markers
 * rather than by walking the cross-reference table. That is a deliberate
 * inversion of how a renderer works, and it is the right choice here for two
 * reasons.
 *
 * First, robustness: the documents most in need of checking are the ones
 * produced by tools that left the xref inconsistent, and a parser that gives up
 * on them is useless precisely when it matters.
 *
 * Second, and more importantly: an incremental update leaves the *previous*
 * version of every changed object still in the file. Walking the xref shows only
 * the current one. Scanning shows both — which is how the engine finds text that
 * a "redaction" merely superseded rather than removed. That failure has a long
 * public history, and it is invisible to any tool that reads the file the way a
 * viewer does.
 */

import { ClassifiedError } from '../../errors.js';
import { inflate } from './inflate.js';

export type PdfValue =
  | null
  | boolean
  | number
  | PdfName
  | PdfString
  | PdfRef
  | PdfArray
  | PdfDict
  | PdfStream;

export type PdfArray = PdfValue[];

export interface PdfName { readonly kind: 'name'; readonly name: string }
export interface PdfString { readonly kind: 'string'; readonly bytes: Uint8Array }
export interface PdfRef { readonly kind: 'ref'; readonly num: number; readonly gen: number }
export interface PdfDict { readonly kind: 'dict'; readonly map: Map<string, PdfValue> }
export interface PdfStream { readonly kind: 'stream'; readonly dict: PdfDict; readonly raw: Uint8Array }

/**
 * Type guards.
 *
 * All of them accept `undefined`, because every lookup into a PDF dictionary
 * may miss and the alternative is a null check at each of the ~40 call sites.
 */
type Maybe = PdfValue | undefined;
const tagged = (v: Maybe, kind: string): boolean =>
  typeof v === 'object' && v !== null && !Array.isArray(v) && (v as { kind: string }).kind === kind;

export const isName = (v: Maybe): v is PdfName => tagged(v, 'name');
export const isString = (v: Maybe): v is PdfString => tagged(v, 'string');
export const isRef = (v: Maybe): v is PdfRef => tagged(v, 'ref');
export const isDict = (v: Maybe): v is PdfDict => tagged(v, 'dict');
export const isStream = (v: Maybe): v is PdfStream => tagged(v, 'stream');
export const isArray = (v: Maybe): v is PdfArray => Array.isArray(v);

const WHITESPACE = new Set([0x00, 0x09, 0x0a, 0x0c, 0x0d, 0x20]);
const DELIMITER = new Set([0x28, 0x29, 0x3c, 0x3e, 0x5b, 0x5d, 0x7b, 0x7d, 0x2f, 0x25]);

const isWhite = (b: number): boolean => WHITESPACE.has(b);
const isDelim = (b: number): boolean => DELIMITER.has(b);
const isRegular = (b: number): boolean => !isWhite(b) && !isDelim(b);

/** Latin-1 decode. PDF's base syntax is byte-oriented, not Unicode. */
export function latin1(bytes: Uint8Array): string {
  let out = '';
  for (let i = 0; i < bytes.length; i++) out += String.fromCharCode(bytes[i]!);
  return out;
}

/** A recursive-descent reader over PDF object syntax. */
export class PdfLexer {
  readonly data: Uint8Array;
  pos: number;

  constructor(data: Uint8Array, pos = 0) {
    this.data = data;
    this.pos = pos;
  }

  skipSpace(): void {
    for (;;) {
      while (this.pos < this.data.length && isWhite(this.data[this.pos]!)) this.pos++;
      // Comments run to end of line and may appear anywhere whitespace may.
      if (this.data[this.pos] === 0x25) {
        while (this.pos < this.data.length && this.data[this.pos] !== 0x0a && this.data[this.pos] !== 0x0d) {
          this.pos++;
        }
        continue;
      }
      return;
    }
  }

  /** Parse one object. Returns `undefined` at end of input or on a stray token. */
  parseValue(depth = 0): PdfValue | undefined {
    if (depth > 64) return null; // defends against a crafted deeply-nested file
    this.skipSpace();
    if (this.pos >= this.data.length) return undefined;

    const byte = this.data[this.pos]!;

    if (byte === 0x2f) return this.#parseName();
    if (byte === 0x28) return this.#parseLiteralString();
    if (byte === 0x5b) return this.#parseArray(depth);
    if (byte === 0x3c) {
      return this.data[this.pos + 1] === 0x3c ? this.#parseDict(depth) : this.#parseHexString();
    }
    if (byte === 0x5d || byte === 0x3e || byte === 0x7d || byte === 0x29) {
      this.pos++;
      return undefined;
    }

    const token = this.#readToken();
    if (token === '') {
      this.pos++;
      return undefined;
    }
    if (token === 'true') return true;
    if (token === 'false') return false;
    if (token === 'null') return null;

    if (/^[+-]?[\d.]+$/.test(token)) {
      const value = Number.parseFloat(token);
      const number = Number.isNaN(value) ? 0 : value;
      // `N G R` is an indirect reference; look ahead for it before committing
      // to a plain number.
      const save = this.pos;
      this.skipSpace();
      const genStart = this.pos;
      const gen = this.#readToken();
      if (/^\d+$/.test(gen)) {
        this.skipSpace();
        const kw = this.#readToken();
        if (kw === 'R') return { kind: 'ref', num: number, gen: Number.parseInt(gen, 10) };
        this.pos = genStart;
      }
      this.pos = save;
      return number;
    }

    // An operator or keyword; the content-stream reader handles those.
    return { kind: 'name', name: `#op:${token}` };
  }

  #readToken(): string {
    const start = this.pos;
    while (this.pos < this.data.length && isRegular(this.data[this.pos]!)) this.pos++;
    return latin1(this.data.subarray(start, this.pos));
  }

  #parseName(): PdfName {
    this.pos++; // past '/'
    let name = '';
    while (this.pos < this.data.length && isRegular(this.data[this.pos]!)) {
      const byte = this.data[this.pos]!;
      if (byte === 0x23 && this.pos + 2 < this.data.length) {
        const hex = latin1(this.data.subarray(this.pos + 1, this.pos + 3));
        const code = Number.parseInt(hex, 16);
        if (!Number.isNaN(code)) {
          name += String.fromCharCode(code);
          this.pos += 3;
          continue;
        }
      }
      name += String.fromCharCode(byte);
      this.pos++;
    }
    return { kind: 'name', name };
  }

  /** `(...)` with balanced parentheses, backslash escapes, and octal codes. */
  #parseLiteralString(): PdfString {
    this.pos++; // past '('
    const out: number[] = [];
    let depth = 1;

    while (this.pos < this.data.length) {
      const byte = this.data[this.pos++]!;

      if (byte === 0x5c) {
        const next = this.data[this.pos++];
        if (next === undefined) break;
        switch (next) {
          case 0x6e: out.push(0x0a); break; // \n
          case 0x72: out.push(0x0d); break; // \r
          case 0x74: out.push(0x09); break; // \t
          case 0x62: out.push(0x08); break; // \b
          case 0x66: out.push(0x0c); break; // \f
          case 0x0a: break;                  // line continuation
          case 0x0d: if (this.data[this.pos] === 0x0a) this.pos++; break;
          default:
            if (next >= 0x30 && next <= 0x37) {
              let octal = next - 0x30;
              for (let i = 0; i < 2; i++) {
                const digit = this.data[this.pos];
                if (digit === undefined || digit < 0x30 || digit > 0x37) break;
                octal = octal * 8 + (digit - 0x30);
                this.pos++;
              }
              out.push(octal & 0xff);
            } else {
              out.push(next);
            }
        }
        continue;
      }

      if (byte === 0x28) depth++;
      if (byte === 0x29) {
        depth--;
        if (depth === 0) break;
      }
      out.push(byte);
    }
    return { kind: 'string', bytes: Uint8Array.from(out) };
  }

  #parseHexString(): PdfString {
    this.pos++; // past '<'
    const digits: string[] = [];
    while (this.pos < this.data.length && this.data[this.pos] !== 0x3e) {
      const ch = String.fromCharCode(this.data[this.pos++]!);
      if (/[0-9a-fA-F]/.test(ch)) digits.push(ch);
    }
    this.pos++; // past '>'
    if (digits.length % 2 === 1) digits.push('0'); // trailing nibble pads with zero
    const out = new Uint8Array(digits.length / 2);
    for (let i = 0; i < out.length; i++) {
      out[i] = Number.parseInt(digits[i * 2]! + digits[i * 2 + 1]!, 16);
    }
    return { kind: 'string', bytes: out };
  }

  #parseArray(depth: number): PdfArray {
    this.pos++; // past '['
    const out: PdfArray = [];
    for (;;) {
      this.skipSpace();
      if (this.pos >= this.data.length) break;
      if (this.data[this.pos] === 0x5d) { this.pos++; break; }
      const value = this.parseValue(depth + 1);
      if (value === undefined) break;
      out.push(value);
    }
    return out;
  }

  #parseDict(depth: number): PdfDict | PdfStream {
    this.pos += 2; // past '<<'
    const map = new Map<string, PdfValue>();

    for (;;) {
      this.skipSpace();
      if (this.pos >= this.data.length) break;
      if (this.data[this.pos] === 0x3e && this.data[this.pos + 1] === 0x3e) { this.pos += 2; break; }
      if (this.data[this.pos] !== 0x2f) {
        // Not a key; skip whatever this is rather than looping forever.
        if (this.parseValue(depth + 1) === undefined) break;
        continue;
      }
      const key = this.#parseName();
      const value = this.parseValue(depth + 1);
      if (value === undefined) break;
      map.set(key.name, value);
    }

    const dict: PdfDict = { kind: 'dict', map };

    // A dictionary followed by `stream` introduces stream data.
    const save = this.pos;
    this.skipSpace();
    if (latin1(this.data.subarray(this.pos, this.pos + 6)) === 'stream') {
      this.pos += 6;
      if (this.data[this.pos] === 0x0d) this.pos++;
      if (this.data[this.pos] === 0x0a) this.pos++;
      const start = this.pos;

      const declared = dict.map.get('Length');
      let end = -1;
      if (typeof declared === 'number' && start + declared <= this.data.length) {
        // Trust the declared length only if `endstream` actually follows it.
        const after = latin1(this.data.subarray(start + declared, start + declared + 20));
        if (/^\s*endstream/.test(after)) end = start + declared;
      }
      if (end === -1) {
        // A wrong or indirect /Length is common; find the terminator instead.
        end = indexOfBytes(this.data, 'endstream', start);
        if (end === -1) end = this.data.length;
        // Trim the EOL that precedes `endstream`.
        if (this.data[end - 1] === 0x0a) end--;
        if (this.data[end - 1] === 0x0d) end--;
      }

      const raw = this.data.subarray(start, end);
      this.pos = indexOfBytes(this.data, 'endstream', end);
      this.pos = this.pos === -1 ? this.data.length : this.pos + 9;
      return { kind: 'stream', dict, raw };
    }
    this.pos = save;
    return dict;
  }
}

/** Byte-wise `indexOf` for an ASCII needle. */
export function indexOfBytes(haystack: Uint8Array, needle: string, from = 0): number {
  const first = needle.charCodeAt(0);
  const limit = haystack.length - needle.length;
  outer: for (let i = Math.max(0, from); i <= limit; i++) {
    if (haystack[i] !== first) continue;
    for (let k = 1; k < needle.length; k++) {
      if (haystack[i + k] !== needle.charCodeAt(k)) continue outer;
    }
    return i;
  }
  return -1;
}

/** One indirect object found in the file. */
export interface PdfObject {
  readonly num: number;
  readonly gen: number;
  readonly offset: number;
  readonly value: PdfValue;
  /**
   * True when a later definition of the same object number supersedes this one.
   *
   * A superseded object is a previous revision still present in the bytes. Text
   * that a tool "removed" by writing a new version of the object is still here,
   * and is exactly what a determined reader extracts.
   */
  readonly superseded: boolean;
}

/** Every object in a file, current and superseded. */
export class PdfObjectStore {
  readonly objects: readonly PdfObject[];
  readonly #current: ReadonlyMap<number, PdfObject>;
  readonly data: Uint8Array;

  constructor(data: Uint8Array) {
    this.data = data;
    const found: Array<{ num: number; gen: number; offset: number; bodyAt: number }> = [];

    // Scan for `N G obj`. The regex runs over a Latin-1 view so the offsets map
    // one-to-one onto byte positions.
    const text = latin1(data);
    const pattern = /(?:^|[\s>\]])(\d{1,10})\s+(\d{1,5})\s+obj\b/g;
    let match: RegExpExecArray | null;
    while ((match = pattern.exec(text)) !== null) {
      const offset = match.index + (match[0].length - match[0].trimStart().length);
      found.push({
        num: Number.parseInt(match[1]!, 10),
        gen: Number.parseInt(match[2]!, 10),
        offset,
        bodyAt: match.index + match[0].length,
      });
    }

    const parsed: PdfObject[] = [];
    const lastIndexByNum = new Map<number, number>();
    for (const entry of found) lastIndexByNum.set(entry.num, entry.offset);

    for (const entry of found) {
      let value: PdfValue = null;
      try {
        const lexer = new PdfLexer(data, entry.bodyAt);
        value = lexer.parseValue() ?? null;
      } catch {
        // A single malformed object must not stop the scan; the rest of the
        // file is still worth examining.
        value = null;
      }
      parsed.push({
        num: entry.num,
        gen: entry.gen,
        offset: entry.offset,
        value,
        superseded: lastIndexByNum.get(entry.num) !== entry.offset,
      });
    }

    const current = new Map<number, PdfObject>();
    for (const object of parsed) if (!object.superseded) current.set(object.num, object);

    this.objects = parsed;
    this.#current = current;
  }

  /** Follow references until a direct value is reached. */
  resolve(value: PdfValue | undefined, depth = 0): PdfValue | undefined {
    if (value === undefined || depth > 32) return value;
    if (!isRef(value)) return value;
    const target = this.#current.get(value.num);
    return target === undefined ? null : this.resolve(target.value, depth + 1);
  }

  /** Resolve a dictionary entry in one step. */
  get(dict: PdfDict | undefined, key: string): PdfValue | undefined {
    if (dict === undefined) return undefined;
    return this.resolve(dict.map.get(key));
  }

  /** Objects that a later revision replaced. */
  get supersededObjects(): readonly PdfObject[] {
    return this.objects.filter((o) => o.superseded);
  }

  /**
   * Decode a stream's bytes, applying its filter chain.
   *
   * Unsupported filters return the raw bytes rather than throwing: an image in
   * a codec this engine does not decode is still an object whose *dictionary*
   * may disclose something, and refusing the whole document over it would be
   * the wrong trade.
   */
  decodeStream(stream: PdfStream): { bytes: Uint8Array; decoded: boolean; filter: string } {
    const filterValue = this.get(stream.dict, 'Filter');
    const filters = filterValue === undefined || filterValue === null
      ? []
      : isArray(filterValue)
        ? filterValue.filter(isName).map((f) => f.name)
        : isName(filterValue) ? [filterValue.name] : [];

    let bytes = stream.raw;
    for (const filter of filters) {
      try {
        if (filter === 'FlateDecode' || filter === 'Fl') bytes = inflate(bytes);
        else if (filter === 'ASCIIHexDecode' || filter === 'AHx') bytes = asciiHexDecode(bytes);
        else if (filter === 'ASCII85Decode' || filter === 'A85') bytes = ascii85Decode(bytes);
        else return { bytes, decoded: false, filter };
      } catch {
        return { bytes, decoded: false, filter };
      }
    }

    // Predictors are used by xref streams and by some image data. Undoing the
    // PNG predictor is required or the bytes read as noise.
    const parms = this.get(stream.dict, 'DecodeParms');
    const parmDict = isArray(parms) ? parms.map((p) => this.resolve(p)).find(isDict) : isDict(parms) ? parms : undefined;
    if (parmDict !== undefined) {
      const predictor = this.get(parmDict, 'Predictor');
      if (typeof predictor === 'number' && predictor >= 10) {
        const columns = this.get(parmDict, 'Columns');
        const colors = this.get(parmDict, 'Colors');
        const bpc = this.get(parmDict, 'BitsPerComponent');
        bytes = undoPngPredictor(
          bytes,
          typeof columns === 'number' ? columns : 1,
          typeof colors === 'number' ? colors : 1,
          typeof bpc === 'number' ? bpc : 8,
        );
      }
    }

    return { bytes, decoded: true, filter: filters.join('+') || 'none' };
  }
}

function asciiHexDecode(data: Uint8Array): Uint8Array {
  const digits: string[] = [];
  for (let i = 0; i < data.length; i++) {
    const ch = String.fromCharCode(data[i]!);
    if (ch === '>') break;
    if (/[0-9a-fA-F]/.test(ch)) digits.push(ch);
  }
  if (digits.length % 2 === 1) digits.push('0');
  const out = new Uint8Array(digits.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = Number.parseInt(digits[i * 2]! + digits[i * 2 + 1]!, 16);
  return out;
}

function ascii85Decode(data: Uint8Array): Uint8Array {
  const out: number[] = [];
  let tuple = 0;
  let count = 0;
  for (let i = 0; i < data.length; i++) {
    const byte = data[i]!;
    if (byte === 0x7e) break; // '~' begins the EOD marker
    if (isWhite(byte)) continue;
    if (byte === 0x7a && count === 0) { out.push(0, 0, 0, 0); continue; } // 'z'
    if (byte < 0x21 || byte > 0x75) continue;
    tuple = tuple * 85 + (byte - 0x21);
    if (++count === 5) {
      out.push((tuple >>> 24) & 255, (tuple >>> 16) & 255, (tuple >>> 8) & 255, tuple & 255);
      tuple = 0;
      count = 0;
    }
  }
  if (count > 0) {
    for (let i = count; i < 5; i++) tuple = tuple * 85 + 84;
    const bytes = [(tuple >>> 24) & 255, (tuple >>> 16) & 255, (tuple >>> 8) & 255, tuple & 255];
    out.push(...bytes.slice(0, count - 1));
  }
  return Uint8Array.from(out);
}

/** Reverse the PNG row filters that a /Predictor >= 10 stream applies. */
function undoPngPredictor(data: Uint8Array, columns: number, colors: number, bits: number): Uint8Array {
  const bpp = Math.max(1, Math.ceil((colors * bits) / 8));
  const rowLength = Math.ceil((columns * colors * bits) / 8);
  const stride = rowLength + 1;
  if (stride <= 1 || data.length < stride) return data;

  const rows = Math.floor(data.length / stride);
  const out = new Uint8Array(rows * rowLength);
  let previous = new Uint8Array(rowLength);

  for (let r = 0; r < rows; r++) {
    const type = data[r * stride]!;
    const row = data.subarray(r * stride + 1, r * stride + 1 + rowLength);
    const current = new Uint8Array(rowLength);
    for (let i = 0; i < rowLength; i++) {
      const raw = row[i] ?? 0;
      const left = i >= bpp ? current[i - bpp]! : 0;
      const up = previous[i]!;
      const upLeft = i >= bpp ? previous[i - bpp]! : 0;
      switch (type) {
        case 0: current[i] = raw; break;
        case 1: current[i] = (raw + left) & 255; break;
        case 2: current[i] = (raw + up) & 255; break;
        case 3: current[i] = (raw + ((left + up) >> 1)) & 255; break;
        case 4: {
          const p = left + up - upLeft;
          const pa = Math.abs(p - left);
          const pb = Math.abs(p - up);
          const pc = Math.abs(p - upLeft);
          current[i] = (raw + (pa <= pb && pa <= pc ? left : pb <= pc ? up : upLeft)) & 255;
          break;
        }
        default: current[i] = raw;
      }
    }
    out.set(current, r * rowLength);
    previous = current;
  }
  return out;
}

/** Decode a PDF text string, honouring the UTF-16BE byte-order mark. */
export function decodeTextString(bytes: Uint8Array): string {
  if (bytes.length >= 2 && bytes[0] === 0xfe && bytes[1] === 0xff) {
    let out = '';
    for (let i = 2; i + 1 < bytes.length; i += 2) {
      out += String.fromCharCode((bytes[i]! << 8) | bytes[i + 1]!);
    }
    return out;
  }
  return latin1(bytes);
}

/** Assert that the input begins with a PDF header. */
export function assertPdf(data: Uint8Array): void {
  if (indexOfBytes(data.subarray(0, 1024), '%PDF-') === -1) {
    throw new ClassifiedError('E_PARSE', 'not a PDF: no %PDF- header in the first kilobyte', {});
  }
}
