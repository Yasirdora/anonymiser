import assert from 'node:assert/strict';
import { describe, it } from 'node:test';

import {
  detectFormat,
  imageAdapter,
  jpegDimensions,
  pngDimensions,
  readExif,
  scanContainer,
  scrubImageMetadata,
  gpsToDecimal,
} from '../src/adapters/image/index.js';
import { detect } from '../src/detect/engine.js';
import { standardDetectors } from '../src/detect/index.js';
import { ClassifiedError } from '../src/errors.js';
import { hatchRegion, pixelateRegion, scrambleRegion } from '../src/redact/apply.js';

/** CRC-32, needed to build valid PNG chunks by hand. */
function crc32(bytes: Uint8Array): number {
  let crc = 0xffffffff;
  for (const byte of bytes) {
    crc ^= byte;
    for (let i = 0; i < 8; i++) {
      crc = crc & 1 ? (crc >>> 1) ^ 0xedb88320 : crc >>> 1;
    }
  }
  return (crc ^ 0xffffffff) >>> 0;
}

function pngChunk(type: string, data: Uint8Array): number[] {
  const typeBytes = [...type].map((c) => c.charCodeAt(0));
  const body = Uint8Array.from([...typeBytes, ...data]);
  const crc = crc32(body);
  return [
    (data.length >>> 24) & 0xff, (data.length >>> 16) & 0xff,
    (data.length >>> 8) & 0xff, data.length & 0xff,
    ...body,
    (crc >>> 24) & 0xff, (crc >>> 16) & 0xff, (crc >>> 8) & 0xff, crc & 0xff,
  ];
}

function ascii(text: string): number[] {
  return [...text].map((c) => c.charCodeAt(0));
}

/** A 1x1 PNG carrying an authorship comment. */
function buildPng(): Uint8Array {
  const ihdr = Uint8Array.from([
    0, 0, 0, 1, // width
    0, 0, 0, 1, // height
    8, 6, 0, 0, 0, // bit depth, colour type, compression, filter, interlace
  ]);
  const text = Uint8Array.from(ascii('Author\0Dana Reyes'));
  const idat = Uint8Array.from([0x78, 0x9c, 0x62, 0x00, 0x00, 0x00, 0x02, 0x00, 0x01]);

  return Uint8Array.from([
    0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a,
    ...pngChunk('IHDR', ihdr),
    ...pngChunk('tEXt', text),
    ...pngChunk('IDAT', idat),
    ...pngChunk('IEND', new Uint8Array(0)),
  ]);
}

/**
 * A JPEG carrying an EXIF block with a Make tag and GPS coordinates.
 *
 * Built by hand so the test exercises the real byte layout rather than a
 * library's idea of it.
 */
function buildJpegWithExif(): Uint8Array {
  const entries: number[][] = [];
  const values: number[] = [];
  const VALUES_BASE = 8 + 2 + 2 * 12 + 4; // TIFF header + IFD0 with two entries

  // IFD0 entry: Make (0x010f), ASCII.
  const make = ascii('AcmeCam\0');
  const makeOffset = VALUES_BASE + values.length;
  values.push(...make);
  entries.push([
    0x01, 0x0f, 0x00, 0x02,
    0, 0, 0, make.length,
    (makeOffset >>> 24) & 0xff, (makeOffset >>> 16) & 0xff, (makeOffset >>> 8) & 0xff, makeOffset & 0xff,
  ]);

  // GPS IFD pointer (0x8825). The GPS directory follows the IFD0 values.
  const gpsOffset = VALUES_BASE + values.length;
  const gpsEntries: number[][] = [];
  const gpsValues: number[] = [];
  const GPS_VALUES_BASE = gpsOffset + 2 + 4 * 12 + 4;

  const rational = (n: number, d: number): number[] => [
    (n >>> 24) & 0xff, (n >>> 16) & 0xff, (n >>> 8) & 0xff, n & 0xff,
    (d >>> 24) & 0xff, (d >>> 16) & 0xff, (d >>> 8) & 0xff, d & 0xff,
  ];

  // GPSLatitudeRef = 'N'
  gpsEntries.push([0x00, 0x01, 0x00, 0x02, 0, 0, 0, 2, 0x4e, 0x00, 0x00, 0x00]);
  // GPSLatitude = 51 30 30 (three rationals)
  const latOffset = GPS_VALUES_BASE + gpsValues.length;
  gpsValues.push(...rational(51, 1), ...rational(30, 1), ...rational(30, 1));
  gpsEntries.push([
    0x00, 0x02, 0x00, 0x05, 0, 0, 0, 3,
    (latOffset >>> 24) & 0xff, (latOffset >>> 16) & 0xff, (latOffset >>> 8) & 0xff, latOffset & 0xff,
  ]);
  // GPSLongitudeRef = 'W'
  gpsEntries.push([0x00, 0x03, 0x00, 0x02, 0, 0, 0, 2, 0x57, 0x00, 0x00, 0x00]);
  // GPSLongitude = 0 7 30
  const lonOffset = GPS_VALUES_BASE + gpsValues.length;
  gpsValues.push(...rational(0, 1), ...rational(7, 1), ...rational(30, 1));
  gpsEntries.push([
    0x00, 0x04, 0x00, 0x05, 0, 0, 0, 3,
    (lonOffset >>> 24) & 0xff, (lonOffset >>> 16) & 0xff, (lonOffset >>> 8) & 0xff, lonOffset & 0xff,
  ]);

  entries.push([
    0x88, 0x25, 0x00, 0x04, 0, 0, 0, 1,
    (gpsOffset >>> 24) & 0xff, (gpsOffset >>> 16) & 0xff, (gpsOffset >>> 8) & 0xff, gpsOffset & 0xff,
  ]);

  const tiff = [
    0x4d, 0x4d, 0x00, 0x2a, 0x00, 0x00, 0x00, 0x08, // big-endian, IFD0 at 8
    0x00, entries.length,
    ...entries.flat(),
    0x00, 0x00, 0x00, 0x00, // no next IFD
    ...values,
    0x00, gpsEntries.length,
    ...gpsEntries.flat(),
    0x00, 0x00, 0x00, 0x00,
    ...gpsValues,
  ];

  const app1Payload = [...ascii('Exif\0\0'), ...tiff];
  const app1Length = app1Payload.length + 2;

  return Uint8Array.from([
    0xff, 0xd8, // SOI
    0xff, 0xe1, (app1Length >> 8) & 0xff, app1Length & 0xff, ...app1Payload,
    // A minimal baseline SOF0 so dimensions can be read.
    0xff, 0xc0, 0x00, 0x11, 0x08, 0x00, 0x40, 0x00, 0x60, 0x03,
    0x01, 0x11, 0x00, 0x02, 0x11, 0x01, 0x03, 0x11, 0x01,
    0xff, 0xda, 0x00, 0x08, 0x01, 0x01, 0x00, 0x00, 0x3f, 0x00,
    0xff, 0xd9, // EOI
  ]);
}

describe('container detection', () => {
  it('identifies PNG and JPEG by signature', () => {
    assert.equal(detectFormat(buildPng()), 'png');
    assert.equal(detectFormat(buildJpegWithExif()), 'jpeg');
    assert.equal(detectFormat(Uint8Array.from([1, 2, 3, 4])), 'unknown');
  });

  it('reads dimensions without decoding pixels', () => {
    assert.deepEqual(pngDimensions(buildPng()), { width: 1, height: 1 });
    assert.deepEqual(jpegDimensions(buildJpegWithExif()), { width: 96, height: 64 });
  });
});

describe('PNG metadata', () => {
  it('finds a textual chunk', () => {
    const scan = scanContainer(buildPng());
    const text = scan.blocks.find((b) => b.kind === 'tEXt');
    assert.ok(text, 'the tEXt chunk must be found');
    assert.match(text.text ?? '', /Dana Reyes/);
  });

  it('removes the chunk and leaves the image data byte-identical', () => {
    const original = buildPng();
    const { bytes } = scrubImageMetadata(original);

    assert.ok(bytes.length < original.length);
    assert.equal(detectFormat(bytes), 'png', 'the result must still be a PNG');
    assert.equal(scanContainer(bytes).blocks.length, 0, 'nothing removable may remain');

    const asString = [...bytes].map((b) => String.fromCharCode(b)).join('');
    assert.ok(!asString.includes('Dana Reyes'));
    // IHDR, IDAT, and IEND survive untouched.
    assert.ok(asString.includes('IHDR') && asString.includes('IDAT') && asString.includes('IEND'));
  });
});

describe('EXIF', () => {
  it('reads IFD0 and GPS tags', () => {
    const jpeg = buildJpegWithExif();
    const scan = scanContainer(jpeg);
    const exif = scan.blocks.find((b) => b.kind === 'APP1/Exif');
    assert.ok(exif, 'the EXIF block must be found');

    const names = (exif.fields ?? []).map((f) => f.name);
    assert.ok(names.includes('Make'));
    assert.ok(names.includes('GPSLatitude'));
    assert.ok(names.includes('GPSLongitudeRef'));
  });

  it('converts coordinates to signed decimal degrees', () => {
    assert.equal(gpsToDecimal('51, 30, 30', 'N')?.toFixed(4), '51.5083');
    assert.equal(gpsToDecimal('0, 7, 30', 'W')?.toFixed(4), '-0.1250');
    assert.equal(gpsToDecimal('33, 52, 4', 'S')! < 0, true, 'southern latitudes are negative');
  });

  it('survives malformed input without throwing', () => {
    assert.deepEqual(readExif(new Uint8Array(0)), []);
    assert.deepEqual(readExif(Uint8Array.from([0xff, 0xff, 0xff, 0xff])), []);
    // A directory pointing past the end of the buffer.
    assert.deepEqual(readExif(Uint8Array.from([0x49, 0x49, 0x2a, 0x00, 0xff, 0xff, 0xff, 0xff])), []);
  });

  it('strips EXIF from the JPEG while leaving it a JPEG', () => {
    const jpeg = buildJpegWithExif();
    const { bytes } = scrubImageMetadata(jpeg);
    assert.equal(detectFormat(bytes), 'jpeg');
    assert.equal(scanContainer(bytes).blocks.length, 0);
    assert.deepEqual(jpegDimensions(bytes), { width: 96, height: 64 }, 'the frame must survive');
  });
});

describe('the image adapter', () => {
  const pixels = new Uint8ClampedArray(8 * 8 * 4).fill(180);

  it('rejects a pixel buffer that does not match the dimensions', () => {
    assert.throws(
      () => imageAdapter.parse({ width: 8, height: 8, pixels: new Uint8ClampedArray(4) }),
      /RGBA needs/,
    );
  });

  it('exposes EXIF as metadata nodes the detectors can see', () => {
    const model = imageAdapter.parse({
      width: 96,
      height: 64,
      pixels: new Uint8ClampedArray(96 * 64 * 4),
      container: buildJpegWithExif(),
    });
    const keys = model.nodes.filter((n) => n.kind === 'metadata').map((n) => n.attrs?.['key']);
    assert.ok(keys.includes('Make'));
    assert.ok(keys.includes('GPSPosition'), 'decoded coordinates must be exposed');
  });

  it('classifies a photograph\'s GPS coordinates like any other location', () => {
    const model = imageAdapter.parse({
      width: 96,
      height: 64,
      pixels: new Uint8ClampedArray(96 * 64 * 4),
      container: buildJpegWithExif(),
    });
    const result = detect(model, standardDetectors());
    assert.ok(
      result.findings.some((f) => f.type === 'geo.coordinates'),
      'coordinates in EXIF are the same disclosure as coordinates in the body',
    );
  });

  it('exposes OCR text for classification', () => {
    const model = imageAdapter.parse({
      width: 8,
      height: 8,
      pixels,
      ocr: [
        { id: 'b1', text: 'SSN: 123-45-6789', rect: { x: 1, y: 1, width: 6, height: 2 } },
      ],
    });
    const result = detect(model, standardDetectors());
    assert.ok(result.findings.some((f) => f.type === 'gov.ssn'));
  });

  it('destroys the pixels under a redaction and does not mutate the input', () => {
    const source = { width: 8, height: 8, pixels: new Uint8ClampedArray(pixels) };
    const model = imageAdapter.parse(source);
    const output = imageAdapter.apply(model, [
      {
        id: 'op',
        location: { kind: 'region', node: 'image', rect: { x: 2, y: 2, width: 4, height: 4 } },
        strategy: 'blackout',
        reason: { code: 'test', authority: 'test' },
        findingIds: [],
      },
    ]);

    const centre = (4 * 8 + 4) * 4;
    assert.deepEqual([...output.pixels.slice(centre, centre + 4)], [0, 0, 0, 255]);
    assert.equal(source.pixels[centre], 180, 'the source buffer must be untouched');
    assert.equal(output.container, undefined, 'the original JPEG/PNG must not ship next to a blackout');
  });

  it('does not return the original container after a pixel redaction even when metadata is also stripped', () => {
    const png = Uint8Array.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]);
    const pixels = new Uint8ClampedArray(8 * 8 * 4).fill(180);
    const model = imageAdapter.parse({ width: 8, height: 8, pixels, container: png });
    const output = imageAdapter.apply(model, [
      {
        id: 'op',
        location: { kind: 'region', node: 'image', rect: { x: 0, y: 0, width: 8, height: 8 } },
        strategy: 'blackout',
        reason: { code: 'test', authority: 'test' },
        findingIds: [],
      },
      {
        id: 'meta',
        location: { kind: 'node', node: 'image' },
        strategy: 'remove',
        reason: { code: 'test', authority: 'test' },
        findingIds: [],
      },
    ]);
    assert.equal(output.container, undefined);
  });

  it('refuses to apply a non-destructive strategy to a region', () => {
    const model = imageAdapter.parse({ width: 8, height: 8, pixels });
    assert.throws(
      () =>
        imageAdapter.apply(model, [
          {
            id: 'op',
            location: { kind: 'region', node: 'image', rect: { x: 0, y: 0, width: 2, height: 2 } },
            strategy: 'blur',
            reason: { code: 'test', authority: 'test' },
            findingIds: [],
          },
        ]),
      /only "blackout"/,
    );
  });
});

describe('the mosaic', () => {
  const source = () => {
    // A four-pixel checkerboard block: the average is mid-grey, so a mosaic
    // over it is detectable without depending on any particular photograph.
    const pixels = new Uint8ClampedArray(8 * 8 * 4);
    for (let y = 0; y < 8; y++) {
      for (let x = 0; x < 8; x++) {
        const i = (y * 8 + x) * 4;
        const on = (x + y) % 2 === 0 ? 255 : 0;
        pixels[i] = on; pixels[i + 1] = on; pixels[i + 2] = on; pixels[i + 3] = 255;
      }
    }
    return pixels;
  };

  it('replaces each block with its average', () => {
    const pixels = source();
    pixelateRegion(pixels, 8, 8, { x: 0, y: 0, width: 8, height: 8 }, 4);
    // Every pixel in a block of an even checkerboard averages to 127 or 128.
    for (let i = 0; i < pixels.length; i += 4) {
      assert.ok(pixels[i]! >= 127 && pixels[i]! <= 128, `pixel ${i / 4} is ${pixels[i]}`);
    }
  });

  it('is refused by the adapter unless the operation acknowledges it', () => {
    const model = imageAdapter.parse({ width: 8, height: 8, pixels: source() });
    const op = {
      id: 'p1',
      location: { kind: 'region' as const, node: 'image', rect: { x: 0, y: 0, width: 8, height: 8 } },
      strategy: 'pixelate' as const,
      reason: { code: 'test', authority: 'test' },
      findingIds: [],
    };
    assert.throws(
      () => imageAdapter.apply(model, [op]),
      (error: unknown) => {
        assert.ok(error instanceof ClassifiedError);
        assert.equal(error.code, 'E_COSMETIC_REFUSED');
        return true;
      },
    );
    assert.doesNotThrow(() => imageAdapter.apply(model, [{ ...op, acknowledgedRecoverable: true }]));
  });

  it('leaves a blackout defensible and does not need the acknowledgement', () => {
    const model = imageAdapter.parse({ width: 8, height: 8, pixels: source() });
    const out = imageAdapter.apply(model, [{
      id: 'b1',
      location: { kind: 'region', node: 'image', rect: { x: 0, y: 0, width: 8, height: 8 } },
      strategy: 'blackout',
      reason: { code: 'test', authority: 'test' },
      findingIds: [],
    }]);
    assert.ok([...out.pixels].every((v, i) => (i % 4 === 3 ? v === 255 : v === 0)));
  });
});

describe('destructive alternatives to a black bar', () => {
  /** A gradient, so any surviving structure would be obvious. */
  const gradient = () => {
    const pixels = new Uint8ClampedArray(16 * 16 * 4);
    for (let y = 0; y < 16; y++) {
      for (let x = 0; x < 16; x++) {
        const i = (y * 16 + x) * 4;
        pixels[i] = x * 16; pixels[i + 1] = y * 16; pixels[i + 2] = 128; pixels[i + 3] = 255;
      }
    }
    return pixels;
  };

  it('scrambles to noise that does not depend on what it replaced', () => {
    const a = gradient();
    const b = new Uint8ClampedArray(16 * 16 * 4).fill(200);
    const region = { x: 0, y: 0, width: 16, height: 16 };
    scrambleRegion(a, 16, 16, region, 'op1');
    scrambleRegion(b, 16, 16, region, 'op1');
    // Two different sources under the same seed produce identical output, which
    // is the property that matters: the result is a function of the seed alone.
    assert.deepEqual([...a], [...b]);
  });

  it('produces the same noise on every run, so a release stays reproducible', () => {
    const first = gradient();
    const second = gradient();
    scrambleRegion(first, 16, 16, { x: 0, y: 0, width: 16, height: 16 }, 'op7');
    scrambleRegion(second, 16, 16, { x: 0, y: 0, width: 16, height: 16 }, 'op7');
    assert.deepEqual([...first], [...second]);
    // A different operation gets different noise.
    const third = gradient();
    scrambleRegion(third, 16, 16, { x: 0, y: 0, width: 16, height: 16 }, 'op8');
    assert.notDeepEqual([...first], [...third]);
  });

  it('hatches without leaving any of the original behind', () => {
    const pixels = gradient();
    hatchRegion(pixels, 16, 16, { x: 0, y: 0, width: 16, height: 16 });
    // Only the two hatch tones, and every channel equal -- nothing of the
    // gradient's per-channel structure survives.
    for (let i = 0; i < pixels.length; i += 4) {
      assert.ok(pixels[i] === 34 || pixels[i] === 12, `unexpected tone ${pixels[i]}`);
      assert.equal(pixels[i], pixels[i + 1]);
      assert.equal(pixels[i], pixels[i + 2]);
    }
  });

  it('leaves pixels outside the region untouched', () => {
    const pixels = gradient();
    const before = [...pixels];
    scrambleRegion(pixels, 16, 16, { x: 4, y: 4, width: 4, height: 4 }, 'op1');
    // Row 0 is entirely outside the region.
    assert.deepEqual([...pixels.slice(0, 16 * 4)], before.slice(0, 16 * 4));
  });

  it('applies both through the adapter without an acknowledgement', () => {
    const model = imageAdapter.parse({ width: 16, height: 16, pixels: gradient() });
    for (const strategy of ['scramble', 'hatch'] as const) {
      assert.doesNotThrow(() => imageAdapter.apply(model, [{
        id: `op-${strategy}`,
        location: { kind: 'region', node: 'image', rect: { x: 0, y: 0, width: 16, height: 16 } },
        strategy,
        reason: { code: 'test', authority: 'test' },
        findingIds: [],
      }]), strategy);
    }
  });
});
