/**
 * Finding the pictures in a PDF.
 *
 * A scanned document is a PDF whose every page is one image, and until now this
 * engine could not see them at all. It read the text layer, found nothing --
 * because there is none -- and presented the reviewer with a blank page. They
 * saw nothing to redact, concluded there was nothing to redact, and released the
 * scan. That is the exact failure the whole tool exists to prevent, sitting in
 * the most common government document format there is.
 *
 * Fixing it does not need a PDF renderer. The page image in a scan is stored as
 * an image XObject, and for the overwhelmingly common `/DCTDecode` filter the
 * stream's bytes **are** a JPEG -- the same bytes a browser would get from a
 * dropped `.jpg`. So this locates the images and hands them over; the host
 * decodes them exactly as it decodes any other picture, and everything already
 * built for images applies unchanged.
 *
 * Rendering a *born-digital* page faithfully -- fonts, paths, graphics state --
 * is a different problem and genuinely does need a renderer. It is also a
 * smaller problem, because a born-digital page has a real text layer, and
 * removing text from it deletes the value rather than covering it.
 */

import { isArray, isDict, isName, isRef, isStream, PdfObjectStore, type PdfDict, type PdfValue } from './objects.js';

/** One picture found inside a PDF. */
export interface PdfImage {
  /** The object number, so a caller can tie it back to the file. */
  readonly object: number;
  /** Zero-based page it appears on, or `null` when that cannot be resolved. */
  readonly page: number | null;
  readonly width: number;
  readonly height: number;
  /** The stream's filter, verbatim, e.g. `DCTDecode`. */
  readonly filter: string;
  /**
   * The encoded bytes, exactly as stored.
   *
   * For `DCTDecode` this is a complete JPEG and can go straight to an image
   * decoder. For anything else it is the raw stream and the caller must know
   * what to do with it, which is why {@link decodable} exists.
   */
  readonly bytes: Uint8Array;
  /**
   * Whether a browser can decode {@link bytes} without further work.
   *
   * True only for JPEG. A reviewer must never be shown a page with some of its
   * imagery silently missing, so a caller that cannot decode an image has to say
   * so rather than skip it.
   */
  readonly decodable: boolean;
}

const dictGet = (dict: PdfDict, key: string): PdfValue | undefined => dict.map.get(key);

const nameOf = (value: PdfValue | undefined): string | null =>
  isName(value) ? value.name : null;

const numberOf = (value: PdfValue | undefined): number | null =>
  typeof value === 'number' ? value : null;

/**
 * The filter that actually applies, when a stream lists several.
 *
 * A chain like `[/FlateDecode /DCTDecode]` ends in the image codec, so the last
 * entry is the one that describes the pixels.
 */
function filterOf(dict: PdfDict): string | null {
  const filter = dictGet(dict, 'Filter');
  if (filter === undefined) return null;
  const direct = nameOf(filter);
  if (direct !== null) return direct;
  if (isArray(filter)) {
    for (let i = filter.length - 1; i >= 0; i--) {
      const name = nameOf(filter[i]);
      if (name !== null) return name;
    }
  }
  return null;
}

/**
 * Every image XObject in the file, in document order.
 *
 * Pages are resolved where the page's own resources name the object, which
 * covers the ordinary case. An image reached through an inherited resource
 * dictionary or a nested form XObject comes back with `page: null` rather than a
 * guess -- a picture attributed to the wrong page would send a reviewer looking
 * for something that is not there.
 */
export function extractImages(bytes: Uint8Array): readonly PdfImage[] {
  const store = new PdfObjectStore(bytes);
  const pageOfObject = mapObjectsToPages(store);

  const out: PdfImage[] = [];
  for (const object of store.objects) {
    if (object.superseded) continue;
    const value = object.value;
    if (!isStream(value)) continue;

    const dict = value.dict;
    if (nameOf(dictGet(dict, 'Subtype')) !== 'Image') continue;

    const width = numberOf(dictGet(dict, 'Width'));
    const height = numberOf(dictGet(dict, 'Height'));
    if (width === null || height === null || width <= 0 || height <= 0) continue;

    const filter = filterOf(dict) ?? 'none';
    out.push({
      object: object.num,
      page: pageOfObject.get(object.num) ?? null,
      width,
      height,
      filter,
      bytes: value.raw,
      // A JPEG stream is a JPEG file. Everything else needs unpacking that
      // belongs to whoever knows the colour space, not to this function.
      decodable: filter === 'DCTDecode' && value.raw[0] === 0xff && value.raw[1] === 0xd8,
    });
  }
  return out;
}

/** Which page each XObject is named by, from the pages' resource dictionaries. */
function mapObjectsToPages(store: PdfObjectStore): Map<number, number> {
  const mapping = new Map<number, number>();
  let pageIndex = 0;

  for (const object of store.objects) {
    if (object.superseded) continue;
    const value = object.value;
    if (!isDict(value)) continue;
    if (nameOf(dictGet(value, 'Type')) !== 'Page') continue;

    const current = pageIndex++;
    const resources = store.resolve(dictGet(value, 'Resources'));
    if (!isDict(resources)) continue;
    const xobjects = store.resolve(dictGet(resources, 'XObject'));
    if (!isDict(xobjects)) continue;

    for (const entry of xobjects.map.values()) {
      // First page wins: an image shared between pages is still one image, and
      // showing it once where it first appears is better than twice.
      if (isRef(entry) && !mapping.has(entry.num)) mapping.set(entry.num, current);
    }
  }
  return mapping;
}

/**
 * Whether an image is a page, or something sitting on one.
 *
 * A scanned page is several megapixels and roughly page-shaped. A logo is a few
 * hundredths of a megapixel; a masthead is wide and shallow. Measured against
 * real documents: page scans came in at 3.9 and 4.4 MP with aspect ratios near
 * 0.63, while the logos on a six-page benefits form were 0.03 to 0.10 MP, and a
 * header strip was 3.2 MP but 3.23:1 -- so size alone does not separate them and
 * shape settles it.
 *
 * The consequence of getting this wrong in each direction is unequal, which is
 * why the thresholds are where they are. Calling a logo a page opens a document
 * as a handful of tiny pictures and the reviewer sees immediately that something
 * is off. Calling a page a logo sends a scan down the text path, where it looks
 * like an empty document -- and an empty document reads as a clean one.
 */
export function looksLikeAPage(image: PdfImage): boolean {
  const megapixels = (image.width * image.height) / 1e6;
  const aspect = image.width / image.height;
  return megapixels >= 1 && aspect >= 0.4 && aspect <= 2;
}
