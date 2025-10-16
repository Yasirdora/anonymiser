import assert from 'node:assert/strict';
import { deflateRawSync, deflateSync } from 'node:zlib';
import { describe, it } from 'node:test';

import { extractImages, looksLikeAPage, pdfAdapter, writeImagePdf } from '../src/adapters/pdf/index.js';
import { inflate, inflateRaw } from '../src/adapters/pdf/inflate.js';
import { parseContentStream, looksLikeRedactionBar } from '../src/adapters/pdf/content.js';
import { PdfObjectStore, latin1 } from '../src/adapters/pdf/objects.js';
import { classify } from '../src/classify/engine.js';
import { compilePolicy } from '../src/classify/lattice.js';
import { privacyPolicy } from '../src/classify/packs/index.js';
import { detect } from '../src/detect/engine.js';
import { standardDetectors } from '../src/detect/index.js';
import { utf8Encode } from '../src/internal/bytes.js';
import { analyze, redactDocument } from '../src/pipeline.js';

const policy = compilePolicy(privacyPolicy);
const SALT = utf8Encode('pdf-test-salt-of-sufficient-length');

const bytes = (text: string): Uint8Array => Uint8Array.from(text, (c) => c.charCodeAt(0) & 0xff);

/**
 * A PDF built the way careless tools build them: a black rectangle painted over
 * text that was never removed. This is the shape of the Manafort filing failure
 * and it is what the adapter has to catch.
 */
function fakeRedactedPdf(options: { compress?: boolean } = {}): Uint8Array {
  const content = [
    'BT /F1 14 Tf 72 700 Td (Witness statement) Tj ET',
    'BT /F1 11 Tf 72 660 Td (The informant SSN is 123-45-6789 and lives at SW1A 2AA.) Tj ET',
    'BT /F1 11 Tf 72 640 Td (Contact: dana.reyes@example.com) Tj ET',
    'q 0 g 70 654 470 16 re f Q',
  ].join('\n');

  const raw = Buffer.from(content, 'latin1');
  const stream = options.compress === false ? raw : deflateSync(raw);
  const filter = options.compress === false ? '' : ' /Filter /FlateDecode';

  const parts: Buffer[] = [Buffer.from('%PDF-1.7\n')];
  parts.push(Buffer.from('1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n'));
  parts.push(Buffer.from('2 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 1 >>\nendobj\n'));
  parts.push(Buffer.from(
    '3 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents 4 0 R ' +
    '/Resources << /Font << /F1 5 0 R >> >> /Annots [6 0 R] >>\nendobj\n'));
  parts.push(Buffer.concat([
    Buffer.from(`4 0 obj\n<< /Length ${stream.length}${filter} >>\nstream\n`),
    stream,
    Buffer.from('\nendstream\nendobj\n'),
  ]));
  parts.push(Buffer.from('5 0 obj\n<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>\nendobj\n'));
  parts.push(Buffer.from('6 0 obj\n<< /Type /Annot /Subtype /Text /Contents (reviewer note: do not release the address) >>\nendobj\n'));
  parts.push(Buffer.from('7 0 obj\n<< /Title (Witness Statement 4471) /Author (M. Okonkwo) /Producer (CaseTrack 7.2) >>\nendobj\n'));
  parts.push(Buffer.from('trailer\n<< /Size 8 /Root 1 0 R /Info 7 0 R >>\n%%EOF\n'));
  return new Uint8Array(Buffer.concat(parts));
}

/** The same file with an incremental update that supersedes the content stream. */
function incrementallyUpdatedPdf(): Uint8Array {
  const original = Buffer.from(fakeRedactedPdf({ compress: false }));
  const replacement = 'BT /F1 11 Tf 72 660 Td (The informant is protected.) Tj ET';
  const update = Buffer.from(
    `4 0 obj\n<< /Length ${replacement.length} >>\nstream\n${replacement}\nendstream\nendobj\n` +
    'trailer\n<< /Size 8 /Root 1 0 R /Prev 0 >>\n%%EOF\n');
  return new Uint8Array(Buffer.concat([original, update]));
}

describe('DEFLATE', () => {
  it('round-trips zlib and raw streams against the reference encoder', () => {
    for (const source of ['', 'hello', 'ABC'.repeat(4000), 'BT (x) Tj ET '.repeat(500)]) {
      const buffer = Buffer.from(source);
      assert.deepEqual(Buffer.from(inflate(new Uint8Array(deflateSync(buffer)))), buffer);
      assert.deepEqual(Buffer.from(inflateRaw(new Uint8Array(deflateRawSync(buffer)))), buffer);
    }
  });

  it('handles stored (uncompressed) blocks', () => {
    const buffer = Buffer.from('stored block content');
    const compressed = deflateSync(buffer, { level: 0 });
    assert.deepEqual(Buffer.from(inflate(new Uint8Array(compressed))), buffer);
  });

  it('reports a truncated stream rather than returning partial data silently', () => {
    const compressed = new Uint8Array(deflateSync(Buffer.from('x'.repeat(5000))));
    assert.throws(() => inflate(compressed.subarray(0, 12)), /E_PARSE|ended mid-symbol|invalid/);
  });

  it('refuses a decompression bomb rather than growing without bound', () => {
    const huge = deflateSync(Buffer.alloc(65 * 1024 * 1024));
    assert.throws(() => inflate(new Uint8Array(huge)), /decompression bomb|exceeded/);
  });
});

describe('PDF object syntax', () => {
  it('parses dictionaries, arrays, names, strings, and references', () => {
    const store = new PdfObjectStore(bytes(
      '%PDF-1.7\n1 0 obj\n<< /Type /Page /Count 3 /Kids [2 0 R 3 0 R] ' +
      '/Title (Hello \\(World\\)) /Hex <48656C6C6F> /Flag true /Nil null >>\nendobj\n'));
    const object = store.objects[0]!;
    assert.equal(object.num, 1);
    const dict = object.value as { map: Map<string, unknown> };
    assert.equal((dict.map.get('Count') as number), 3);
    assert.equal((dict.map.get('Kids') as unknown[]).length, 2);
    assert.equal(latin1((dict.map.get('Title') as { bytes: Uint8Array }).bytes), 'Hello (World)');
    assert.equal(latin1((dict.map.get('Hex') as { bytes: Uint8Array }).bytes), 'Hello');
    assert.equal(dict.map.get('Flag'), true);
    assert.equal(dict.map.get('Nil'), null);
  });

  it('finds objects even when the cross-reference table is absent', () => {
    // Every fixture here is written without an xref, which is also how many
    // real damaged files arrive.
    const store = new PdfObjectStore(fakeRedactedPdf());
    assert.ok(store.objects.length >= 7);
  });

  it('recovers a stream whose declared Length is wrong', () => {
    const store = new PdfObjectStore(bytes(
      '%PDF-1.7\n1 0 obj\n<< /Length 99999 >>\nstream\nHELLO STREAM\nendstream\nendobj\n'));
    const stream = store.objects[0]!.value as { raw: Uint8Array };
    assert.equal(latin1(stream.raw), 'HELLO STREAM');
  });
});

describe('content streams', () => {
  it('extracts text with positions', () => {
    const { texts } = parseContentStream(bytes('BT /F1 12 Tf 72 700 Td (Hello) Tj ET'));
    assert.equal(texts.length, 1);
    assert.equal(texts[0]!.text, 'Hello');
    assert.equal(Math.round(texts[0]!.rect.x), 72);
    assert.ok(texts[0]!.argStart >= 0, 'the byte range of the argument must be recorded');
  });

  it('joins a kerned TJ array into one run', () => {
    // A number split across kerning adjustments must still read as one number,
    // or no pattern rule will ever match it.
    const { texts } = parseContentStream(bytes('BT /F1 12 Tf [(123-45) -20 (-6789)] TJ ET'));
    assert.equal(texts.length, 1);
    assert.equal(texts[0]!.text, '123-45-6789');
  });

  it('identifies a dark opaque fill as a redaction bar', () => {
    const { rects } = parseContentStream(bytes('q 0 g 70 654 470 16 re f Q'));
    assert.equal(rects.length, 1);
    assert.equal(looksLikeRedactionBar(rects[0]!), true);
  });

  it('does not mistake a pale fill for a redaction bar', () => {
    const { rects } = parseContentStream(bytes('q 1 1 0.9 rg 70 654 470 16 re f Q'));
    assert.equal(looksLikeRedactionBar(rects[0]!), false);
  });
});

describe('the PDF adapter', () => {
  it('rejects input that is not a PDF', () => {
    assert.throws(() => pdfAdapter.parse(bytes('just some text')), /not a PDF/);
  });

  it('refuses an encrypted PDF rather than half-processing it', () => {
    const encrypted = bytes(
      '%PDF-1.7\n1 0 obj\n<< /Type /Catalog >>\nendobj\n' +
        'trailer\n<< /Size 2 /Root 1 0 R /Encrypt 2 0 R >>\nstartxref\n0\n%%EOF\n',
    );
    assert.throws(() => pdfAdapter.parse(encrypted), /encrypted/);
  });

  it('does not treat the word Encrypt in page text as encryption', () => {
    const content = 'BT /F1 12 Tf 72 700 Td (see /Encrypt in the spec) Tj ET';
    const pdf = bytes(
      '%PDF-1.7\n' +
        '1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n' +
        '2 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 1 >>\nendobj\n' +
        '3 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents 4 0 R >>\nendobj\n' +
        `4 0 obj\n<< /Length ${content.length} >>\nstream\n${content}\nendstream\nendobj\n` +
        'trailer\n<< /Size 5 /Root 1 0 R >>\n%%EOF\n',
    );
    assert.doesNotThrow(() => pdfAdapter.parse(pdf));
  });

  it('extracts text, metadata, annotations, and filled rectangles', () => {
    const model = pdfAdapter.parse(fakeRedactedPdf());
    const kinds = model.nodes.reduce<Record<string, number>>((acc, n) => {
      acc[n.kind] = (acc[n.kind] ?? 0) + 1;
      return acc;
    }, {});
    assert.equal(kinds['text'], 3);
    assert.equal(kinds['vector'], 1);
    assert.equal(kinds['annotation'], 1);
    assert.ok((kinds['metadata'] ?? 0) >= 3);
    assert.equal(model.pages.length, 1);
    assert.equal(model.origin, 'bottom-left');
  });

  it('catches the black box over live text', () => {
    const model = pdfAdapter.parse(fakeRedactedPdf());
    const result = detect(model, standardDetectors());
    const cosmetic = result.findings.filter((f) => f.type === 'risk.cosmetic-redaction');
    assert.equal(cosmetic.length, 1, 'the fake redaction must be reported');
    assert.match(cosmetic[0]!.value, /123-45-6789/);
  });

  it('finds text left behind in a superseded revision', () => {
    const model = pdfAdapter.parse(incrementallyUpdatedPdf());
    const revision = model.nodes.find((n) => n.attrs?.['revision'] !== undefined);
    assert.ok(revision, 'the superseded content stream must be reported');
    assert.match(revision.text ?? '', /123-45-6789/);

    const result = detect(model, standardDetectors());
    assert.ok(result.findings.some((f) => f.type === 'risk.revision-history'));
  });

  it('classifies a PDF the same way it classifies anything else', () => {
    const model = pdfAdapter.parse(fakeRedactedPdf());
    const detection = detect(model, standardDetectors());
    const classification = classify(model, detection, policy);
    assert.notEqual(classification.banner.level, 'open');
    assert.ok(classification.bannerMarking.length > 0);
  });

  it('removes the text from the bytes, not just from the view', () => {
    const result = redactDocument(fakeRedactedPdf(), {
      adapter: pdfAdapter, policy,
      plan: { minConfidence: 0.6 },
      manifestSalt: SALT,
    });

    assert.equal(result.verification.passed, true);
    assert.equal(result.defensible, true);

    const raw = latin1(result.output);
    for (const secret of ['123-45-6789', 'dana.reyes@example.com', 'SW1A 2AA', 'M. Okonkwo', 'do not release']) {
      assert.ok(!raw.includes(secret), `${secret} must not survive in the output bytes`);
    }
  });

  it('produces an output that re-parses clean', () => {
    const result = redactDocument(fakeRedactedPdf(), {
      adapter: pdfAdapter, policy, plan: { minConfidence: 0.6 }, manifestSalt: SALT,
    });
    const after = analyze(result.output, { adapter: pdfAdapter, policy });
    assert.equal(after.detection.findings.length, 0, 'a re-scan of the output must find nothing');
  });

  it('writes one flattened revision, so nothing survives in a prior one', () => {
    const result = redactDocument(incrementallyUpdatedPdf(), {
      adapter: pdfAdapter, policy, plan: { minConfidence: 0.6 }, manifestSalt: SALT,
      returnUnverified: true,
    });
    const store = new PdfObjectStore(result.output);
    assert.equal(store.supersededObjects.length, 0, 'the output must contain no superseded objects');
  });

  it('records every PDF removal in the manifest with an authority', () => {
    const result = redactDocument(fakeRedactedPdf(), {
      adapter: pdfAdapter, policy, plan: { minConfidence: 0.6 }, manifestSalt: SALT,
    });
    assert.ok(result.manifest);
    assert.ok(result.manifest.entries.length > 0);
    for (const entry of result.manifest.entries) assert.ok(entry.authority.length > 0);
    assert.ok(!JSON.stringify(result.manifest).includes('123-45-6789'));
  });
});

describe('writing a PDF of images', () => {
  /** The smallest thing that is unmistakably a JPEG to a PDF reader. */
  const jpeg = (marker: number) =>
    Uint8Array.from([0xff, 0xd8, 0xff, 0xe0, 0x00, 0x10, marker, 0x00, 0xff, 0xd9]);

  const decode = (bytes: Uint8Array) => {
    let out = '';
    for (const byte of bytes) out += String.fromCharCode(byte);
    return out;
  };

  it('writes one page per image, in order', () => {
    const pdf = writeImagePdf([
      { jpeg: jpeg(1), width: 1200, height: 896 },
      { jpeg: jpeg(2), width: 800, height: 600 },
    ]);
    const text = decode(pdf);
    assert.match(text, /^%PDF-1\.7/);
    assert.match(text, /%%EOF\n$/);
    assert.equal((text.match(/\/Type \/Page[^s]/g) ?? []).length, 2);
    assert.match(text, /\/Count 2/);
  });

  it('embeds the JPEG bytes verbatim rather than re-encoding', () => {
    const source = jpeg(0x2a);
    const pdf = writeImagePdf([{ jpeg: source, width: 10, height: 10 }]);
    // The exact byte sequence has to survive: a re-encode would be a second
    // generation of loss over an image that has already been redacted once.
    const needle = decode(source);
    assert.ok(decode(pdf).includes(needle));
    assert.match(decode(pdf), /\/Filter \/DCTDecode/);
  });

  it('sizes the page in points, not pixels', () => {
    const pdf = decode(writeImagePdf([{ jpeg: jpeg(1), width: 96, height: 192, dpi: 96 }]));
    // 96 pixels at 96 per inch is one inch, which is 72 points.
    assert.match(pdf, /\/MediaBox \[0 0 72 144\]/);
  });

  it('embeds uncompressed RGB without a DCT filter', () => {
    const rgb = new Uint8Array(2 * 2 * 3);
    rgb.set([255, 0, 0, 0, 255, 0, 0, 0, 255, 0, 0, 0]);
    const pdf = writeImagePdf([{ rgb, width: 2, height: 2, dpi: 150 }]);
    const text = decode(pdf);
    assert.ok(!text.includes('/DCTDecode'), 'a redacted page must not be JPEG-encoded');
    assert.match(text, /\/ColorSpace \/DeviceRGB/);
    // 2px at 150 dpi is 2 * 72 / 150 = 0.96 pt.
    assert.match(text, /\/MediaBox \[0 0 0.96 0.96\]/);
    assert.ok(text.includes(decode(rgb)));
  });

  it('refuses a page with neither JPEG nor RGB, and a buffer of the wrong length', () => {
    assert.throws(
      () => writeImagePdf([{ jpeg: Uint8Array.from([0x89, 0x50, 0x4e, 0x47]), width: 1, height: 1 }]),
      /needs uncompressed RGB/,
    );
    assert.throws(
      () => writeImagePdf([{ rgb: new Uint8Array(2), width: 2, height: 2 }]),
      /needs uncompressed RGB/,
    );
  });

  it('produces the same bytes twice, so a release can be reproduced', () => {
    const pages = [{ jpeg: jpeg(3), width: 100, height: 50 }];
    assert.deepEqual([...writeImagePdf(pages)], [...writeImagePdf(pages)]);
  });

  it('writes a cross-reference offset that lands on its own table', () => {
    const pdf = writeImagePdf([{ jpeg: jpeg(1), width: 10, height: 10 }]);
    const text = decode(pdf);
    const start = Number(/startxref\n(\d+)/.exec(text)?.[1]);
    assert.ok(Number.isFinite(start));
    assert.equal(text.slice(start, start + 4), 'xref');
  });

  it('refuses an empty page list', () => {
    assert.throws(() => writeImagePdf([]), /at least one page/);
  });
});

describe('overlay bars land on the page they belong to', () => {
  function twoPagePdf(): Uint8Array {
    const page1 = 'BT /F1 12 Tf 72 700 Td (Page one body) Tj ET';
    const page2 = 'BT /F1 12 Tf 72 700 Td (Page two body) Tj ET';
    const parts = [
      '%PDF-1.7\n',
      '1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n',
      '2 0 obj\n<< /Type /Pages /Kids [3 0 R 4 0 R] /Count 2 >>\nendobj\n',
      '3 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents 5 0 R >>\nendobj\n',
      '4 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents 6 0 R >>\nendobj\n',
      `5 0 obj\n<< /Length ${page1.length} >>\nstream\n${page1}\nendstream\nendobj\n`,
      `6 0 obj\n<< /Length ${page2.length} >>\nstream\n${page2}\nendstream\nendobj\n`,
      'trailer\n<< /Size 7 /Root 1 0 R >>\n%%EOF\n',
    ];
    return bytes(parts.join(''));
  }

  it('paints a region bar into the target page stream, not the first stream in the file', () => {
    const model = pdfAdapter.parse(twoPagePdf());
    const pageTwo = model.nodes.find((n) => n.kind === 'text' && n.page === 1);
    assert.ok(pageTwo?.bbox);
    const output = pdfAdapter.apply(model, [
      {
        id: 'bar',
        location: { kind: 'region', node: pageTwo.id, rect: pageTwo.bbox },
        strategy: 'blackout',
        reason: { code: 'test', authority: 'test' },
        findingIds: [],
      },
    ]);
    const text = latin1(output);
    // Page two's original text object is 6; the bar operators must sit in that
    // stream. Page one (object 5) must not have grown a fill.
    const obj5 = /5 0 obj[\s\S]*?endobj/.exec(text)?.[0] ?? '';
    const obj6 = /6 0 obj[\s\S]*?endobj/.exec(text)?.[0] ?? '';
    assert.ok(obj6.includes(' re f'), 'the bar belongs on page two');
    assert.ok(!obj5.includes(' re f'), 'page one must not receive page two\'s bar');
  });
});

describe('values found inside PDF metadata', () => {
  /**
   * A PDF whose Info dictionary carries something a rule matches.
   *
   * The Info dictionary is not a content stream, so a text-located finding on
   * it has no byte offsets to splice. The adapter used to refuse the entire
   * document — and the studio reported the refusal as though a value had
   * survived, which is the opposite of what had happened.
   */
  const withTitle = (title: string) => {
    const content = 'BT /F1 12 Tf 72 700 Td (Body text) Tj ET';
    const objects = [
      '<< /Type /Catalog /Pages 2 0 R >>',
      '<< /Type /Pages /Count 1 /Kids [3 0 R] >>',
      '<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents 4 0 R >>',
      `<< /Length ${content.length} >>\nstream\n${content}\nendstream`,
      `<< /Title (${title}) >>`,
    ];
    let out = '%PDF-1.4\n';
    const offsets: number[] = [];
    objects.forEach((object, i) => {
      offsets.push(out.length);
      out += `${i + 1} 0 obj\n${object}\nendobj\n`;
    });
    const xref = out.length;
    out += `xref\n0 ${objects.length + 1}\n0000000000 65535 f \n`;
    for (const offset of offsets) out += `${String(offset).padStart(10, '0')} 00000 n \n`;
    out += `trailer\n<< /Size ${objects.length + 1} /Root 1 0 R /Info 5 0 R >>\nstartxref\n${xref}\n%%EOF\n`;
    return Uint8Array.from([...out].map((c) => c.charCodeAt(0)));
  };

  it('drops the whole entry instead of refusing the document', () => {
    const bytes = withTitle('Case file for Marcus Vance dated 2024-10-26');
    const result = redactDocument(bytes, { adapter: pdfAdapter, policy: compilePolicy(privacyPolicy) });

    assert.equal(result.verification.passed, true);
    const text = new TextDecoder('latin1').decode(result.output);
    assert.doesNotMatch(text, /Marcus Vance/, 'the name is gone from the title');
    assert.doesNotMatch(text, /2024-10-26/, 'and so is the date');
    // Removing the entry rather than emptying it: a title reading
    // "Case file for [REDACTED]" still says a name was worth hiding.
    assert.doesNotMatch(text, /Case file for/);
  });

  it('leaves a clean title alone', () => {
    const bytes = withTitle('Quarterly summary');
    const result = redactDocument(bytes, { adapter: pdfAdapter, policy: compilePolicy(privacyPolicy) });
    assert.match(new TextDecoder('latin1').decode(result.output), /Quarterly summary/);
  });
});

describe('finding the pictures in a PDF', () => {
  /** Three pages, each one image: what a scan looks like. */
  const scan = () =>
    writeImagePdf([
      { jpeg: Uint8Array.from([0xff, 0xd8, 0xff, 0xe0, 0x00, 0x10, 1, 0, 0xff, 0xd9]), width: 1200, height: 896 },
      { jpeg: Uint8Array.from([0xff, 0xd8, 0xff, 0xe0, 0x00, 0x10, 2, 0, 0xff, 0xd9]), width: 800, height: 600 },
      { jpeg: Uint8Array.from([0xff, 0xd8, 0xff, 0xe0, 0x00, 0x10, 3, 0, 0xff, 0xd9]), width: 640, height: 480 },
    ]);

  it('finds one image per page, with its size and page', () => {
    const images = extractImages(scan());
    assert.equal(images.length, 3);
    assert.deepEqual(images.map((i) => i.page), [0, 1, 2]);
    assert.deepEqual(images.map((i) => `${i.width}x${i.height}`), ['1200x896', '800x600', '640x480']);
  });

  it('hands back JPEG bytes a browser can decode as they stand', () => {
    // The whole reason this needs no PDF renderer: the stream *is* the file.
    for (const image of extractImages(scan())) {
      assert.equal(image.filter, 'DCTDecode');
      assert.equal(image.decodable, true);
      assert.equal(image.bytes[0], 0xff);
      assert.equal(image.bytes[1], 0xd8);
    }
  });

  it('marks an image it cannot decode rather than dropping it', () => {
    // A page whose imagery is silently missing is worse than one that says so:
    // the reviewer would believe they had seen the whole document.
    const withFlateImage = [
      '%PDF-1.4',
      '1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj',
      '2 0 obj\n<< /Type /Pages /Count 1 /Kids [3 0 R] >>\nendobj',
      '3 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 10 10] ' +
        '/Resources << /XObject << /Im0 4 0 R >> >> >>\nendobj',
      '4 0 obj\n<< /Type /XObject /Subtype /Image /Width 4 /Height 4 ' +
        '/ColorSpace /DeviceGray /BitsPerComponent 8 /Filter /FlateDecode /Length 4 >>\n' +
        'stream\nabcd\nendstream\nendobj',
      'trailer\n<< /Size 5 /Root 1 0 R >>',
      '%%EOF',
    ].join('\n');
    const images = extractImages(Uint8Array.from([...withFlateImage].map((c) => c.charCodeAt(0))));

    assert.equal(images.length, 1);
    assert.equal(images[0]?.filter, 'FlateDecode');
    assert.equal(images[0]?.decodable, false, 'reported, not skipped');
    assert.equal(images[0]?.page, 0);
  });

  it('finds nothing in a PDF that has no pictures', () => {
    const textOnly = [
      '%PDF-1.4',
      '1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj',
      '2 0 obj\n<< /Type /Pages /Count 1 /Kids [3 0 R] >>\nendobj',
      '3 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 10 10] >>\nendobj',
      'trailer\n<< /Size 4 /Root 1 0 R >>',
      '%%EOF',
    ].join('\n');
    assert.equal(extractImages(Uint8Array.from([...textOnly].map((c) => c.charCodeAt(0)))).length, 0);
  });
});

describe('telling a page from a picture on a page', () => {
  const image = (width: number, height: number) => ({
    object: 1, page: 0, width, height, filter: 'DCTDecode',
    bytes: new Uint8Array(0), decodable: true,
  });

  it('recognises a scanned page', () => {
    // Both measured from a real two-page identity document.
    assert.equal(looksLikeAPage(image(1560, 2496)), true);
    assert.equal(looksLikeAPage(image(1656, 2656)), true);
  });

  it('rejects the logos on a form', () => {
    // Measured from a real six-page benefits application.
    assert.equal(looksLikeAPage(image(192, 192)), false);
    assert.equal(looksLikeAPage(image(685, 144)), false);
  });

  it('rejects a wide header strip even when it is large', () => {
    // 3.2 megapixels, and still not a page: 3.23:1 is a masthead.
    assert.equal(looksLikeAPage(image(3228, 1000)), false);
  });

  it('accepts landscape pages', () => {
    assert.equal(looksLikeAPage(image(2480, 1754)), true, 'A4 landscape at 210dpi');
  });
});
