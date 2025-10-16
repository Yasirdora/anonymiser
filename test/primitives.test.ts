import assert from 'node:assert/strict';
import { describe, it } from 'node:test';

import { fromHex, toBase32, toHex, utf8Decode, utf8Encode, timingSafeEqual } from '../src/internal/bytes.js';
import { hmacSha256, sha256, sha256Text } from '../src/internal/hash.js';
import { complement, mergeIntervals } from '../src/internal/interval.js';
import { canonicalJson } from '../src/provenance/manifest.js';

describe('SHA-256', () => {
  it('matches the FIPS 180-4 vectors', () => {
    assert.equal(
      toHex(sha256Text('')),
      'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
    );
    assert.equal(
      toHex(sha256Text('abc')),
      'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad',
    );
    assert.equal(
      toHex(sha256Text('abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq')),
      '248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1',
    );
  });

  it('handles inputs spanning many blocks', () => {
    // The million-a vector exercises the length encoding and block chaining.
    assert.equal(
      toHex(sha256Text('a'.repeat(1_000_000))),
      'cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0',
    );
  });

  it('is unaffected by how input is chunked', () => {
    const whole = sha256Text('the quick brown fox jumps over the lazy dog');
    const parts = utf8Encode('the quick brown fox jumps over the lazy dog');
    const split = sha256(parts);
    assert.deepEqual(whole, split);
  });
});

describe('HMAC-SHA-256', () => {
  it('matches RFC 4231 test case 1', () => {
    const key = new Uint8Array(20).fill(0x0b);
    const message = utf8Encode('Hi There');
    assert.equal(
      toHex(hmacSha256(key, message)),
      'b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7',
    );
  });

  it('matches RFC 4231 test case 2', () => {
    assert.equal(
      toHex(hmacSha256(utf8Encode('Jefe'), utf8Encode('what do ya want for nothing?'))),
      '5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843',
    );
  });

  it('hashes keys longer than the block size', () => {
    const key = new Uint8Array(131).fill(0xaa);
    const digest = hmacSha256(key, utf8Encode('Test Using Larger Than Block-Size Key - Hash Key First'));
    assert.equal(
      toHex(digest),
      '60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54',
    );
  });
});

describe('encodings', () => {
  it('round-trips UTF-8 including astral characters', () => {
    for (const value of ['', 'ascii', 'café', '日本語', '👩‍💻 family', 'mixed 漢字 and emoji 🔒']) {
      assert.equal(utf8Decode(utf8Encode(value)), value);
    }
  });

  it('replaces lone surrogates rather than throwing', () => {
    const lone = String.fromCharCode(0xd800);
    assert.equal(utf8Decode(utf8Encode(lone)), '�');
  });

  it('round-trips hex', () => {
    const bytes = Uint8Array.from([0, 1, 15, 16, 127, 128, 255]);
    assert.deepEqual(fromHex(toHex(bytes)), bytes);
  });

  it('produces base32 of the requested length', () => {
    const digest = sha256Text('seed');
    assert.equal(toBase32(digest, 6).length, 6);
    assert.match(toBase32(digest, 6), /^[A-Z2-7]{6}$/);
  });

  it('compares equal-length and unequal-length inputs correctly', () => {
    assert.equal(timingSafeEqual(fromHex('00ff'), fromHex('00ff')), true);
    assert.equal(timingSafeEqual(fromHex('00ff'), fromHex('00fe')), false);
    assert.equal(timingSafeEqual(fromHex('00ff'), fromHex('00ffaa')), false);
  });
});

describe('interval algebra', () => {
  it('merges overlapping and adjacent spans', () => {
    const merged = mergeIntervals([
      { start: 0, end: 3 },
      { start: 3, end: 5 },
      { start: 10, end: 12 },
      { start: 1, end: 2 },
    ]);
    assert.deepEqual(
      merged.map((m) => [m.start, m.end]),
      [
        [0, 5],
        [10, 12],
      ],
    );
  });

  it('returns the gaps around removed spans', () => {
    assert.deepEqual(complement(10, [{ start: 2, end: 4 }, { start: 7, end: 8 }]), [
      { start: 0, end: 2 },
      { start: 4, end: 7 },
      { start: 8, end: 10 },
    ]);
  });

  it('clamps spans that run past the end', () => {
    assert.deepEqual(complement(5, [{ start: 3, end: 99 }]), [{ start: 0, end: 3 }]);
  });
});

describe('canonical JSON', () => {
  it('is independent of key insertion order', () => {
    assert.equal(canonicalJson({ b: 1, a: 2 }), canonicalJson({ a: 2, b: 1 }));
  });

  it('drops undefined values so optional fields do not change the digest', () => {
    assert.equal(canonicalJson({ a: 1, b: undefined }), '{"a":1}');
  });

  it('preserves array order, which is significant', () => {
    assert.notEqual(canonicalJson([1, 2]), canonicalJson([2, 1]));
  });
});
