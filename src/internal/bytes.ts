/**
 * Byte and encoding primitives.
 *
 * The engine must run identically in browsers, Node, Deno, Bun, and Workers, so
 * nothing here may touch `Buffer`, `TextEncoder`, `atob`, or any other host
 * global. Everything is implemented over `Uint8Array` and plain arithmetic.
 */

/** Encode a JavaScript string as UTF-8 bytes. Lone surrogates become U+FFFD. */
export function utf8Encode(input: string): Uint8Array {
  const out: number[] = [];
  for (let i = 0; i < input.length; i++) {
    let cp = input.charCodeAt(i);
    if (cp >= 0xd800 && cp <= 0xdbff) {
      const next = i + 1 < input.length ? input.charCodeAt(i + 1) : 0;
      if (next >= 0xdc00 && next <= 0xdfff) {
        cp = (cp - 0xd800) * 0x400 + (next - 0xdc00) + 0x10000;
        i++;
      } else {
        cp = 0xfffd;
      }
    } else if (cp >= 0xdc00 && cp <= 0xdfff) {
      cp = 0xfffd;
    }

    if (cp < 0x80) {
      out.push(cp);
    } else if (cp < 0x800) {
      out.push(0xc0 | (cp >> 6), 0x80 | (cp & 0x3f));
    } else if (cp < 0x10000) {
      out.push(0xe0 | (cp >> 12), 0x80 | ((cp >> 6) & 0x3f), 0x80 | (cp & 0x3f));
    } else {
      out.push(
        0xf0 | (cp >> 18),
        0x80 | ((cp >> 12) & 0x3f),
        0x80 | ((cp >> 6) & 0x3f),
        0x80 | (cp & 0x3f),
      );
    }
  }
  return Uint8Array.from(out);
}

/** Decode UTF-8 bytes to a string. Malformed sequences become U+FFFD. */
export function utf8Decode(bytes: Uint8Array): string {
  let out = '';
  let i = 0;
  while (i < bytes.length) {
    const b0 = bytes[i]!;
    let cp: number;
    let size: number;
    if (b0 < 0x80) {
      cp = b0;
      size = 1;
    } else if ((b0 & 0xe0) === 0xc0) {
      cp = b0 & 0x1f;
      size = 2;
    } else if ((b0 & 0xf0) === 0xe0) {
      cp = b0 & 0x0f;
      size = 3;
    } else if ((b0 & 0xf8) === 0xf0) {
      cp = b0 & 0x07;
      size = 4;
    } else {
      out += '�';
      i++;
      continue;
    }
    if (i + size > bytes.length) {
      out += '�';
      break;
    }
    let ok = true;
    for (let k = 1; k < size; k++) {
      const bk = bytes[i + k]!;
      if ((bk & 0xc0) !== 0x80) {
        ok = false;
        break;
      }
      cp = (cp << 6) | (bk & 0x3f);
    }
    if (!ok) {
      out += '�';
      i++;
      continue;
    }
    i += size;
    if (cp > 0x10ffff || (cp >= 0xd800 && cp <= 0xdfff)) {
      out += '�';
    } else if (cp < 0x10000) {
      out += String.fromCharCode(cp);
    } else {
      cp -= 0x10000;
      out += String.fromCharCode(0xd800 + (cp >> 10), 0xdc00 + (cp & 0x3ff));
    }
  }
  return out;
}

const HEX = '0123456789abcdef';

/** Lowercase hex encoding. */
export function toHex(bytes: Uint8Array): string {
  let out = '';
  for (let i = 0; i < bytes.length; i++) {
    const b = bytes[i]!;
    out += HEX[b >> 4]! + HEX[b & 0x0f]!;
  }
  return out;
}

/** Parse lowercase or uppercase hex. Throws on odd length or non-hex input. */
export function fromHex(hex: string): Uint8Array {
  if (hex.length % 2 !== 0) throw new RangeError('hex string must have even length');
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) {
    const byte = Number.parseInt(hex.slice(i * 2, i * 2 + 2), 16);
    if (Number.isNaN(byte)) throw new RangeError(`invalid hex at offset ${i * 2}`);
    out[i] = byte;
  }
  return out;
}

const B32 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

/**
 * Crockford-free RFC 4648 base32 without padding. Used for pseudonym tokens,
 * where the alphabet must survive case-insensitive systems and be readable
 * aloud, which base64 is not.
 */
export function toBase32(bytes: Uint8Array, length?: number): string {
  let out = '';
  let bits = 0;
  let value = 0;
  for (let i = 0; i < bytes.length; i++) {
    value = (value << 8) | bytes[i]!;
    bits += 8;
    while (bits >= 5) {
      out += B32[(value >>> (bits - 5)) & 31]!;
      bits -= 5;
    }
    if (length !== undefined && out.length >= length) break;
  }
  if (bits > 0 && (length === undefined || out.length < length)) {
    out += B32[(value << (5 - bits)) & 31]!;
  }
  return length === undefined ? out : out.slice(0, length);
}

/** Concatenate byte arrays into a single buffer. */
export function concatBytes(...parts: readonly Uint8Array[]): Uint8Array {
  let total = 0;
  for (const p of parts) total += p.length;
  const out = new Uint8Array(total);
  let offset = 0;
  for (const p of parts) {
    out.set(p, offset);
    offset += p.length;
  }
  return out;
}

/**
 * Length-independent equality check.
 *
 * Manifest signature comparison must not leak the position of the first
 * differing byte through timing, so this always walks the full longer input.
 */
export function timingSafeEqual(a: Uint8Array, b: Uint8Array): boolean {
  const len = Math.max(a.length, b.length);
  let diff = a.length ^ b.length;
  for (let i = 0; i < len; i++) {
    diff |= (a[i] ?? 0) ^ (b[i] ?? 0);
  }
  return diff === 0;
}
