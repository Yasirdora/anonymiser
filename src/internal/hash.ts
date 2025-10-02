/**
 * SHA-256 and HMAC-SHA-256.
 *
 * These are implemented here rather than delegated to WebCrypto for three
 * reasons: WebCrypto's digest API is async, which would force every manifest
 * and pseudonym call site to become a promise; it is absent from some sandboxed
 * and non-secure-context environments the engine targets; and a synchronous,
 * inspectable implementation keeps the provenance chain reproducible with no
 * host variability. The cost is a few microseconds per document.
 *
 * Not constant-time against a local attacker measuring cache behaviour. That is
 * out of scope: the engine hashes content the caller already holds in plaintext.
 */

import { concatBytes, utf8Encode } from './bytes.js';

const K = /* @__PURE__ */ Uint32Array.from([
  0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
  0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
  0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
  0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
  0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
  0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
  0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
  0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
]);

const BLOCK_SIZE = 64;

/** Streaming SHA-256. Reused by HMAC and by the provenance hash chain. */
export class Sha256 {
  readonly #state = Uint32Array.from([
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
  ]);
  readonly #block = new Uint8Array(BLOCK_SIZE);
  readonly #w = new Uint32Array(64);
  #blockLen = 0;
  #totalLen = 0;
  #done = false;

  update(data: Uint8Array): this {
    if (this.#done) throw new Error('Sha256: update() after digest()');
    this.#totalLen += data.length;
    let offset = 0;
    if (this.#blockLen > 0) {
      const need = BLOCK_SIZE - this.#blockLen;
      const take = Math.min(need, data.length);
      this.#block.set(data.subarray(0, take), this.#blockLen);
      this.#blockLen += take;
      offset = take;
      if (this.#blockLen === BLOCK_SIZE) {
        this.#compress(this.#block, 0);
        this.#blockLen = 0;
      }
    }
    while (offset + BLOCK_SIZE <= data.length) {
      this.#compress(data, offset);
      offset += BLOCK_SIZE;
    }
    if (offset < data.length) {
      this.#block.set(data.subarray(offset), 0);
      this.#blockLen = data.length - offset;
    }
    return this;
  }

  digest(): Uint8Array {
    if (this.#done) throw new Error('Sha256: digest() called twice');
    this.#done = true;

    const bitLen = this.#totalLen * 8;
    const padLen = this.#blockLen < 56 ? 56 - this.#blockLen : 120 - this.#blockLen;
    const tail = new Uint8Array(padLen + 8);
    tail[0] = 0x80;
    // Lengths are written as a 64-bit big-endian count. Splitting into two
    // 32-bit halves keeps this exact past 2^32 bits without BigInt.
    const hi = Math.floor(bitLen / 0x100000000);
    const lo = bitLen >>> 0;
    const view = tail.length - 8;
    tail[view] = (hi >>> 24) & 0xff;
    tail[view + 1] = (hi >>> 16) & 0xff;
    tail[view + 2] = (hi >>> 8) & 0xff;
    tail[view + 3] = hi & 0xff;
    tail[view + 4] = (lo >>> 24) & 0xff;
    tail[view + 5] = (lo >>> 16) & 0xff;
    tail[view + 6] = (lo >>> 8) & 0xff;
    tail[view + 7] = lo & 0xff;

    // Feed the padding through the same path as real data.
    const merged = concatBytes(this.#block.subarray(0, this.#blockLen), tail);
    for (let offset = 0; offset + BLOCK_SIZE <= merged.length; offset += BLOCK_SIZE) {
      this.#compress(merged, offset);
    }

    const out = new Uint8Array(32);
    for (let i = 0; i < 8; i++) {
      const v = this.#state[i]!;
      out[i * 4] = (v >>> 24) & 0xff;
      out[i * 4 + 1] = (v >>> 16) & 0xff;
      out[i * 4 + 2] = (v >>> 8) & 0xff;
      out[i * 4 + 3] = v & 0xff;
    }
    return out;
  }

  #compress(buf: Uint8Array, offset: number): void {
    const w = this.#w;
    for (let i = 0; i < 16; i++) {
      const j = offset + i * 4;
      w[i] = ((buf[j]! << 24) | (buf[j + 1]! << 16) | (buf[j + 2]! << 8) | buf[j + 3]!) >>> 0;
    }
    for (let i = 16; i < 64; i++) {
      const x = w[i - 15]!;
      const y = w[i - 2]!;
      const s0 = (((x >>> 7) | (x << 25)) ^ ((x >>> 18) | (x << 14)) ^ (x >>> 3)) >>> 0;
      const s1 = (((y >>> 17) | (y << 15)) ^ ((y >>> 19) | (y << 13)) ^ (y >>> 10)) >>> 0;
      w[i] = (w[i - 16]! + s0 + w[i - 7]! + s1) >>> 0;
    }

    const s = this.#state;
    let a = s[0]!, b = s[1]!, c = s[2]!, d = s[3]!;
    let e = s[4]!, f = s[5]!, g = s[6]!, h = s[7]!;

    for (let i = 0; i < 64; i++) {
      const S1 = (((e >>> 6) | (e << 26)) ^ ((e >>> 11) | (e << 21)) ^ ((e >>> 25) | (e << 7))) >>> 0;
      const ch = ((e & f) ^ (~e & g)) >>> 0;
      const t1 = (h + S1 + ch + K[i]! + w[i]!) >>> 0;
      const S0 = (((a >>> 2) | (a << 30)) ^ ((a >>> 13) | (a << 19)) ^ ((a >>> 22) | (a << 10))) >>> 0;
      const maj = ((a & b) ^ (a & c) ^ (b & c)) >>> 0;
      const t2 = (S0 + maj) >>> 0;
      h = g; g = f; f = e;
      e = (d + t1) >>> 0;
      d = c; c = b; b = a;
      a = (t1 + t2) >>> 0;
    }

    s[0] = (s[0]! + a) >>> 0;
    s[1] = (s[1]! + b) >>> 0;
    s[2] = (s[2]! + c) >>> 0;
    s[3] = (s[3]! + d) >>> 0;
    s[4] = (s[4]! + e) >>> 0;
    s[5] = (s[5]! + f) >>> 0;
    s[6] = (s[6]! + g) >>> 0;
    s[7] = (s[7]! + h) >>> 0;
  }
}

/** One-shot SHA-256 over bytes. */
export function sha256(data: Uint8Array): Uint8Array {
  return new Sha256().update(data).digest();
}

/** One-shot SHA-256 over a UTF-8 string. */
export function sha256Text(text: string): Uint8Array {
  return sha256(utf8Encode(text));
}

/** HMAC-SHA-256, per RFC 2104. */
export function hmacSha256(key: Uint8Array, message: Uint8Array): Uint8Array {
  let k = key;
  if (k.length > BLOCK_SIZE) k = sha256(k);

  const inner = new Uint8Array(BLOCK_SIZE);
  const outer = new Uint8Array(BLOCK_SIZE);
  inner.set(k);
  outer.set(k);
  for (let i = 0; i < BLOCK_SIZE; i++) {
    const b = inner[i]!;
    inner[i] = b ^ 0x36;
    outer[i] = b ^ 0x5c;
  }

  const innerDigest = new Sha256().update(inner).update(message).digest();
  return new Sha256().update(outer).update(innerDigest).digest();
}
