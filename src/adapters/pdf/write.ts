/**
 * Writing a PDF, one page per image.
 *
 * A release is a set of pages, and handing back a folder of loose PNGs makes
 * the recipient reassemble it -- in an order nobody recorded, with nothing tying
 * page four to the batch it came from. One file is what gets filed, emailed and
 * entered into a docket.
 *
 * Redacted pages are stored as uncompressed DeviceRGB. JPEG around a burned bar
 * mixes unredacted pixels into the bar's DCT blocks; that is the same class of
 * failure as drawing a rectangle over live text. Uncompressed RGB is large and
 * is the only encoding this writer will apply to pixels that have been
 * overwritten. A JPEG is accepted only when the caller already holds one and
 * embeds it verbatim -- never as a re-encode of a redacted buffer.
 *
 * What it deliberately does not do is append. Incremental updates are how a
 * redacted PDF leaks -- the superseded objects stay in the file and any reader
 * that walks the earlier revision finds them -- so every document this writes is
 * a single generation with one cross-reference table and no prior state to
 * recover.
 */

import { ClassifiedError } from '../../errors.js';

/** One page: either lossless RGB (the release path) or a verbatim JPEG. */
export interface PdfImagePage {
  /**
   * Uncompressed RGB, length `width * height * 3`, row-major.
   *
   * This is the professional release encoding: no DCT, no ringing around bars.
   */
  readonly rgb?: Uint8Array;
  /**
   * JPEG bytes, embedded verbatim as a `DCTDecode` stream.
   *
   * Only for callers that already have a JPEG and are not encoding a redacted
   * buffer. A redacted page must use `rgb`.
   */
  readonly jpeg?: Uint8Array;
  readonly width: number;
  readonly height: number;
  /**
   * Pixels per inch used to size the page in PDF points.
   *
   * Defaults to 150, the resolution this project's renderer uses for review.
   * 96 is accepted for fixtures that document the 96px = 1in identity.
   */
  readonly dpi?: number;
  /** Shown in the reader's outline, when the writer is given one. */
  readonly title?: string;
}

export interface PdfWriteOptions {
  /** Written to the document information dictionary. */
  readonly title?: string;
  readonly producer?: string;
  /**
   * Creation date, as a PDF date string.
   *
   * Omit for a byte-reproducible file. A timestamp is the only thing in this
   * writer that varies between two runs over the same input, and reproducibility
   * is worth more than a date the filesystem already records.
   */
  readonly created?: string;
}

/** Default review resolution, matching the studio renderer. */
export const DEFAULT_PAGE_DPI = 150;

export function writeImagePdf(
  pages: readonly PdfImagePage[],
  options: PdfWriteOptions = {},
): Uint8Array {
  if (pages.length === 0) {
    throw new ClassifiedError('E_USAGE', 'a PDF needs at least one page', { pages: 0 });
  }
  for (const [index, page] of pages.entries()) {
    const encoding = encodingOf(page);
    if (encoding === 'invalid') {
      throw new ClassifiedError(
        'E_USAGE',
        `page ${index + 1} needs uncompressed RGB (width × height × 3 bytes) or a JPEG; mixing neither and both is refused`,
        { page: index + 1 },
      );
    }
  }

  const chunks: Uint8Array[] = [];
  const offsets: number[] = [];
  let length = 0;

  const push = (bytes: Uint8Array): void => {
    chunks.push(bytes);
    length += bytes.length;
  };
  const text = (value: string): void => push(latin1(value));

  /** Record where an object starts, so the cross-reference table can find it. */
  const begin = (id: number): void => {
    offsets[id] = length;
    text(`${id} 0 obj\n`);
  };
  const end = (): void => text('endobj\n');

  // Object numbering, fixed up front so references can be written before the
  // objects they point at exist.
  const CATALOG = 1;
  const PAGES = 2;
  const INFO = 3;
  const firstPageId = 4;
  const idsFor = (index: number) => ({
    page: firstPageId + index * 3,
    content: firstPageId + index * 3 + 1,
    image: firstPageId + index * 3 + 2,
  });

  text('%PDF-1.7\n');
  // A comment of high bytes, which is what tells a transfer agent the file is
  // binary and must not be newline-translated.
  push(Uint8Array.from([0x25, 0xe2, 0xe3, 0xcf, 0xd3, 0x0a]));

  begin(CATALOG);
  text(`<< /Type /Catalog /Pages ${PAGES} 0 R >>\n`);
  end();

  begin(PAGES);
  const kids = pages.map((_, i) => `${idsFor(i).page} 0 R`).join(' ');
  text(`<< /Type /Pages /Count ${pages.length} /Kids [${kids}] >>\n`);
  end();

  begin(INFO);
  const info = [
    options.title === undefined ? '' : `/Title (${escapeText(options.title)})`,
    `/Producer (${escapeText(options.producer ?? 'classified')})`,
    options.created === undefined ? '' : `/CreationDate (${escapeText(options.created)})`,
  ].filter((part) => part !== '').join(' ');
  text(`<< ${info} >>\n`);
  end();

  for (const [index, page] of pages.entries()) {
    const { page: pageId, content: contentId, image: imageId } = idsFor(index);
    const dpi = page.dpi ?? DEFAULT_PAGE_DPI;
    const widthPt = round(page.width * (72 / dpi));
    const heightPt = round(page.height * (72 / dpi));

    begin(pageId);
    text(
      `<< /Type /Page /Parent ${PAGES} 0 R /MediaBox [0 0 ${widthPt} ${heightPt}] ` +
        `/Resources << /XObject << /Im0 ${imageId} 0 R >> >> /Contents ${contentId} 0 R >>\n`,
    );
    end();

    // The image is scaled to the page by the transformation matrix, so the
    // stream itself is the same three tokens whatever size the page is.
    const stream = `q ${widthPt} 0 0 ${heightPt} 0 0 cm /Im0 Do Q\n`;
    begin(contentId);
    text(`<< /Length ${stream.length} >>\nstream\n${stream}endstream\n`);
    end();

    const kind = encodingOf(page);
    begin(imageId);
    if (kind === 'rgb') {
      const rgb = page.rgb!;
      text(
        `<< /Type /XObject /Subtype /Image /Width ${page.width} /Height ${page.height} ` +
          `/ColorSpace /DeviceRGB /BitsPerComponent 8 /Length ${rgb.length} >>\nstream\n`,
      );
      push(rgb);
      text('\nendstream\n');
    } else {
      const jpeg = page.jpeg!;
      text(
        `<< /Type /XObject /Subtype /Image /Width ${page.width} /Height ${page.height} ` +
          `/ColorSpace /DeviceRGB /BitsPerComponent 8 /Filter /DCTDecode ` +
          `/Length ${jpeg.length} >>\nstream\n`,
      );
      push(jpeg);
      text('\nendstream\n');
    }
    end();
  }

  const xrefAt = length;
  const highest = firstPageId + pages.length * 3;
  text(`xref\n0 ${highest}\n`);
  text('0000000000 65535 f \n');
  for (let id = 1; id < highest; id++) {
    const offset = offsets[id] ?? 0;
    text(`${String(offset).padStart(10, '0')} 00000 n \n`);
  }
  text(
    `trailer\n<< /Size ${highest} /Root ${CATALOG} 0 R /Info ${INFO} 0 R >>\n` +
      `startxref\n${xrefAt}\n%%EOF\n`,
  );

  const out = new Uint8Array(length);
  let at = 0;
  for (const chunk of chunks) {
    out.set(chunk, at);
    at += chunk.length;
  }
  return out;
}

function encodingOf(page: PdfImagePage): 'rgb' | 'jpeg' | 'invalid' {
  const hasRgb = page.rgb !== undefined;
  const hasJpeg = page.jpeg !== undefined;
  if (hasRgb === hasJpeg) return 'invalid';
  if (hasRgb) {
    const expected = page.width * page.height * 3;
    return page.rgb!.length === expected ? 'rgb' : 'invalid';
  }
  return isJpeg(page.jpeg!) ? 'jpeg' : 'invalid';
}

function isJpeg(bytes: Uint8Array): boolean {
  return bytes.length > 3 && bytes[0] === 0xff && bytes[1] === 0xd8 && bytes[2] === 0xff;
}

/** PDF numbers have no exponent form, and readers differ on precision. */
function round(value: number): string {
  return (Math.round(value * 100) / 100).toString();
}

/** Escape the three characters that end a PDF literal string early. */
function escapeText(value: string): string {
  return value.replace(/[\\()]/g, (match) => `\\${match}`);
}

/**
 * PDF syntax is bytes, not characters.
 *
 * Everything this writer emits outside a stream is ASCII; anything above it in a
 * title would otherwise be written as UTF-8 and read as Latin-1, which turns a
 * name into mojibake in the reader's title bar.
 */
function latin1(value: string): Uint8Array {
  const out = new Uint8Array(value.length);
  for (let i = 0; i < value.length; i++) out[i] = value.charCodeAt(i) & 0xff;
  return out;
}
