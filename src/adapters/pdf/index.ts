/**
 * The PDF adapter.
 *
 * What it does, stated plainly, because a redaction tool that overstates its
 * reach is worse than one that does less:
 *
 * - **Reads** page text with positions, filled rectangles, annotations,
 *   embedded files, document metadata, and every object superseded by an
 *   incremental update.
 * - **Finds** the signature failure: an opaque dark rectangle sitting over text
 *   that is still extractable. This is what leaked the Manafort filings and a
 *   long line of FOIA releases, and it is the single most useful thing this
 *   adapter does, because it works on documents *other* tools produced.
 * - **Removes** text by rewriting the show operators that draw it, burns a bar
 *   in its place, strips document metadata, drops annotations and embedded
 *   files, and rewrites the file with a single flattened revision so nothing
 *   survives in a prior one.
 *
 * What it does not do: unpack object streams, map CID/ToUnicode fonts, walk
 * Form XObjects, re-encode images, or preserve encryption. An encrypted PDF is
 * refused rather than half-processed. Studio's release path rasterizes pages
 * and writes a new image PDF for that reason; this adapter is the forensic
 * detector (fake bars, incremental leftovers) and a rewriter for simple
 * Type1/WinAnsi files. Text bounding boxes use an average glyph width rather
 * than font metrics, so a burned bar is slightly generous -- deliberately,
 * since an oversized bar is cosmetic and an undersized one is a disclosure.
 */

export { writeImagePdf, DEFAULT_PAGE_DPI, type PdfImagePage, type PdfWriteOptions } from './write.js';
export { extractImages, looksLikeAPage, type PdfImage } from './images.js';

import { toHex } from '../../internal/bytes.js';
import { sha256 } from '../../internal/hash.js';
import { ClassifiedError } from '../../errors.js';
import type { AdapterCapabilities, DocumentAdapter, ParseOptions } from '../../adapter.js';
import type { ContentNode, DocumentModel } from '../../model/document.js';
import type { Rect } from '../../model/geometry.js';
import type { RedactionOperation } from '../../redact/plan.js';
import { parseContentStream, looksLikeRedactionBar, type Matrix } from './content.js';
import {
  assertPdf, decodeTextString, indexOfBytes, isArray, isDict, isName, isRef, isStream, isString,
  latin1, PdfLexer, PdfObjectStore, type PdfDict, type PdfValue,
} from './objects.js';

export * from './inflate.js';
export * from './objects.js';
export * from './content.js';

/** A PDF as this adapter sees it: just the bytes. */
export type PdfSource = Uint8Array;

const CAPABILITIES: AdapterCapabilities = {
  strategies: ['remove', 'replace', 'blackout'],
  removesMetadata: true,
  removesAttachments: true,
  // Output is written as one flattened revision, so prior versions of objects
  // do not survive into it.
  removesRevisionHistory: true,
  verifiable: true,
};

/** Metadata keys worth surfacing from the Info dictionary. */
const INFO_KEYS = ['Title', 'Author', 'Subject', 'Keywords', 'Creator', 'Producer', 'CreationDate', 'ModDate'];

export const pdfAdapter: DocumentAdapter<PdfSource, Uint8Array> = {
  id: 'pdf',
  version: '0.1.0',
  mediaTypes: ['application/pdf'],
  capabilities: CAPABILITIES,

  parse(source: PdfSource, options: ParseOptions = {}): DocumentModel {
    assertPdf(source);
    const store = new PdfObjectStore(source);

    if (isEncrypted(store)) {
      throw new ClassifiedError(
        'E_PARSE',
        'this PDF is encrypted; decrypt it before redacting, since a partially-processed encrypted file would look redacted without being so',
        {},
      );
    }

    const nodes: ContentNode[] = [];
    const pages: Rect[] = [];

    // --- document metadata -------------------------------------------------
    const trailerInfo = findInfoDict(store);
    if (trailerInfo !== undefined) {
      for (const key of INFO_KEYS) {
        const value = store.get(trailerInfo, key);
        if (isString(value)) {
          const text = decodeTextString(value.bytes).trim();
          if (text !== '') {
            nodes.push({ id: `info:${key}`, kind: 'metadata', text, attrs: { key, source: 'Info' } });
          }
        }
      }
    }
    for (const object of store.objects) {
      if (object.superseded || !isStream(object.value)) continue;
      const type = store.get(object.value.dict, 'Type');
      if (isName(type) && type.name === 'Metadata') {
        const { bytes } = store.decodeStream(object.value);
        const xmp = latin1(bytes);
        for (const [key, text] of extractXmpFields(xmp)) {
          nodes.push({ id: `xmp:${key}`, kind: 'metadata', text, attrs: { key, source: 'XMP' } });
        }
      }
    }

    // --- pages, text, and painted rectangles -------------------------------
    const pageObjects = collectPages(store);
    for (const [pageIndex, page] of pageObjects.entries()) {
      const box = mediaBox(store, page);
      pages.push(box);
      nodes.push({
        id: `page${pageIndex}`,
        kind: 'container',
        role: 'page',
        page: pageIndex,
        bbox: box,
      });

      for (const [streamIndex, stream] of pageContentStreams(store, page).entries()) {
        const { bytes } = store.decodeStream(stream.value);
        // The media box origin is not always (0, 0); shift into page space.
        const base: Matrix = [1, 0, 0, 1, -box.x, -box.y];
        const { texts, rects } = parseContentStream(bytes, base);

        for (const [i, run] of texts.entries()) {
          if (run.text.trim() === '') continue;
          nodes.push({
            id: `p${pageIndex}s${streamIndex}t${i}`,
            kind: 'text',
            parent: `page${pageIndex}`,
            page: pageIndex,
            role: 'paragraph',
            text: run.text,
            bbox: run.rect,
            attrs: {
              object: String(stream.num),
              stream: String(streamIndex),
              argStart: String(run.argStart),
              argEnd: String(run.argEnd),
              operator: run.operator,
            },
          });
        }

        for (const [i, rect] of rects.entries()) {
          if (!rect.filled) continue;
          nodes.push({
            id: `p${pageIndex}s${streamIndex}r${i}`,
            kind: 'vector',
            parent: `page${pageIndex}`,
            page: pageIndex,
            bbox: rect.rect,
            attrs: {
              filled: 'true',
              opacity: String(rect.alpha),
              luminance: rect.luminance.toFixed(3),
              // The structural detector treats a dark, opaque box over live text
              // as a cosmetic redaction; this flag is what tells it which is which.
              redactionBar: String(looksLikeRedactionBar(rect)),
            },
          });
        }
      }

      // --- annotations ----------------------------------------------------
      const annots = store.get(page, 'Annots');
      if (isArray(annots)) {
        for (const [i, entry] of annots.entries()) {
          const annot = store.resolve(entry);
          if (!isDict(annot)) continue;
          const contents = store.get(annot, 'Contents');
          const text = isString(contents) ? decodeTextString(contents.bytes).trim() : '';
          if (text === '') continue;
          const subtype = store.get(annot, 'Subtype');
          nodes.push({
            id: `p${pageIndex}a${i}`,
            kind: 'annotation',
            parent: `page${pageIndex}`,
            page: pageIndex,
            text,
            attrs: {
              subtype: isName(subtype) ? subtype.name : 'unknown',
              // Recorded so removal can drop the object itself rather than just
              // blanking its text -- a blanked annotation is still an object in
              // the file with a revision history of its own.
              ...(isRef(entry) ? { object: String(entry.num) } : {}),
            },
          });
        }
      }
    }

    // --- embedded files ----------------------------------------------------
    for (const object of store.objects) {
      if (object.superseded || !isDict(object.value)) continue;
      const type = store.get(object.value, 'Type');
      if (!isName(type) || type.name !== 'Filespec') continue;
      const name = store.get(object.value, 'F') ?? store.get(object.value, 'UF');
      nodes.push({
        id: `file:${object.num}`,
        kind: 'attachment',
        attrs: {
          name: isString(name) ? decodeTextString(name.bytes) : `object ${object.num}`,
          object: String(object.num),
        },
      });
    }

    // --- prior revisions ---------------------------------------------------
    // Text still present in a superseded object is text a previous "redaction"
    // failed to remove. It renders nowhere and extracts perfectly.
    for (const object of store.supersededObjects) {
      if (!isStream(object.value)) continue;
      let recovered = '';
      try {
        const { bytes, decoded } = store.decodeStream(object.value);
        if (!decoded) continue;
        recovered = parseContentStream(bytes).texts.map((t) => t.text).join(' ').trim();
      } catch {
        continue;
      }
      if (recovered.length < 4) continue;
      nodes.push({
        id: `revision:${object.num}:${object.offset}`,
        kind: 'text',
        text: recovered,
        role: 'unknown',
        attrs: { revision: `object ${object.num} superseded at byte ${object.offset}` },
      });
    }

    const digest = toHex(sha256(source));
    return {
      id: options.documentId ?? `pdf_${digest.slice(0, 16)}`,
      mediaType: 'application/pdf',
      adapterId: 'pdf',
      // PDF user space grows upward from the bottom-left of the media box.
      origin: 'bottom-left',
      pages,
      nodes,
      sourceDigest: digest,
      raw: source,
    };
  },

  /**
   * Write a redacted PDF.
   *
   * Text is removed by blanking the show operator's argument inside its content
   * stream, so the glyphs are gone from the byte stream rather than covered.
   * A bar is then painted where they were, which is presentation only -- by that
   * point there is nothing underneath it.
   */
  apply(model: DocumentModel, operations: readonly RedactionOperation[]): Uint8Array {
    if (model.raw === undefined) {
      throw new ClassifiedError('E_USAGE', 'the PDF adapter needs the original bytes on the model', {});
    }
    const store = new PdfObjectStore(model.raw);
    const byId = new Map(model.nodes.map((n) => [n.id, n]));

    // Group text edits by the content-stream object they live in.
    const edits = new Map<number, Array<{ start: number; end: number; replacement: string }>>();
    const bars: Array<{ page: number; rect: Rect }> = [];
    const droppedNodes = new Set<string>();
    const droppedObjects = new Set<number>();

    for (const operation of operations) {
      const node = byId.get(operation.location.node);
      if (node === undefined) continue;

      if (operation.location.kind === 'region') {
        bars.push({ page: node.page ?? 0, rect: operation.location.rect });
        continue;
      }
      /**
       * A value found *inside* a metadata string, rather than in the page.
       *
       * The Info dictionary is not a content stream, so there are no byte
       * offsets to splice and the adapter used to refuse the whole document --
       * which meant any PDF whose title happened to contain a date could not be
       * saved at all, reported as though something had leaked.
       *
       * Dropping the whole entry is also the better redaction. Rewriting the
       * title to `Report on [REDACTED]` leaves a title that says a date was
       * worth hiding; removing the entry leaves a document with no title, which
       * is what a released record should look like.
       */
      if (
        operation.location.kind === 'text' &&
        (node.kind === 'metadata' || node.kind === 'annotation' || node.kind === 'attachment')
      ) {
        droppedNodes.add(node.id);
        const owner = Number(node.attrs?.['object'] ?? NaN);
        if (Number.isFinite(owner)) droppedObjects.add(owner);
        continue;
      }

      if (operation.location.kind === 'node' && (node.kind === 'metadata' || node.kind === 'annotation' || node.kind === 'attachment')) {
        droppedNodes.add(node.id);
        const objectNumber = Number(node.attrs?.['object'] ?? NaN);
        if (Number.isFinite(objectNumber)) droppedObjects.add(objectNumber);
        continue;
      }

      // Text recovered from a superseded object needs no edit: the output is
      // written as a single flattened revision, so the object that held it is
      // simply never written. Treating this as a content-stream edit would look
      // for byte offsets that do not exist in the current revision.
      if (node.attrs?.['revision'] !== undefined) {
        droppedNodes.add(node.id);
        continue;
      }

      const objectNum = Number(node.attrs?.['object'] ?? NaN);
      const argStart = Number(node.attrs?.['argStart'] ?? -1);
      const argEnd = Number(node.attrs?.['argEnd'] ?? -1);
      if (!Number.isFinite(objectNum) || argStart < 0 || argEnd <= argStart) {
        throw new ClassifiedError(
          'E_UNSUPPORTED',
          `cannot locate the content-stream bytes for node ${node.id}; refusing to report a redaction that was not performed`,
          { node: node.id },
        );
      }

      const bucket = edits.get(objectNum) ?? [];
      // The whole show operation is replaced by an empty string literal, which
      // keeps the operator well-formed while drawing nothing.
      bucket.push({ start: argStart, end: argEnd, replacement: '()' });
      edits.set(objectNum, bucket);
      if (node.bbox !== undefined) bars.push({ page: node.page ?? 0, rect: node.bbox });
    }

    return writePdf(store, model, edits, bars, droppedNodes, droppedObjects);
  },

  reparse(output: Uint8Array): DocumentModel {
    return pdfAdapter.parse(output);
  },
};

/* ------------------------------------------------------------------ helpers */

function isEncrypted(store: PdfObjectStore): boolean {
  // Encrypt lives in the trailer dictionary. Scanning the whole file for the
  // bytes `/Encrypt` refuses any document that discusses encryption, and misses
  // a trailer whose name is hex-escaped. The last `trailer` in the last 64 KiB
  // is the current generation.
  const data = store.data;
  const from = Math.max(0, data.length - 65536);
  let last = -1;
  let cursor = from;
  for (;;) {
    const at = indexOfBytes(data, 'trailer', cursor);
    if (at === -1) break;
    last = at;
    cursor = at + 7;
  }
  if (last === -1) return false;
  const lexer = new PdfLexer(data, last + 7);
  const value = lexer.parseValue();
  return isDict(value) && value.map.has('Encrypt');
}

function findInfoDict(store: PdfObjectStore): PdfDict | undefined {
  // The trailer is not always parseable; the Info dictionary is recognisable on
  // its own by the keys it carries.
  for (const object of store.objects) {
    if (object.superseded || !isDict(object.value)) continue;
    const keys = [...object.value.map.keys()];
    if (keys.some((k) => INFO_KEYS.includes(k)) && !object.value.map.has('Type')) {
      return object.value;
    }
  }
  return undefined;
}

function collectPages(store: PdfObjectStore): PdfDict[] {
  const pages: PdfDict[] = [];
  for (const object of store.objects) {
    if (object.superseded || !isDict(object.value)) continue;
    const type = store.get(object.value, 'Type');
    if (isName(type) && type.name === 'Page') pages.push(object.value);
  }
  return pages;
}

function mediaBox(store: PdfObjectStore, page: PdfDict): Rect {
  const box = store.get(page, 'MediaBox');
  if (isArray(box) && box.length >= 4) {
    const n = box.map((v) => (typeof store.resolve(v) === 'number' ? (store.resolve(v) as number) : 0));
    const [x0, y0, x1, y1] = n as [number, number, number, number];
    return { x: Math.min(x0, x1), y: Math.min(y0, y1), width: Math.abs(x1 - x0), height: Math.abs(y1 - y0) };
  }
  return { x: 0, y: 0, width: 612, height: 792 }; // US Letter, the usual default
}

/** Object number of each page's content stream(s) → page index. */
function contentStreamPageIndex(store: PdfObjectStore): Map<number, number> {
  const map = new Map<number, number>();
  for (const [pageIndex, page] of collectPages(store).entries()) {
    for (const stream of pageContentStreams(store, page)) {
      if (stream.num >= 0) map.set(stream.num, pageIndex);
    }
  }
  return map;
}

function pageContentStreams(
  store: PdfObjectStore,
  page: PdfDict,
): Array<{ num: number; value: ReturnType<typeof asStream> }> {
  const out: Array<{ num: number; value: ReturnType<typeof asStream> }> = [];
  const contents = page.map.get('Contents');
  const entries: PdfValue[] = [];

  const resolved = store.resolve(contents);
  if (isArray(resolved)) entries.push(...resolved);
  else if (contents !== undefined) entries.push(contents);

  for (const entry of entries) {
    const num = typeof entry === 'object' && entry !== null && 'num' in entry
      ? (entry as { num: number }).num
      : -1;
    const value = store.resolve(entry);
    if (isStream(value)) out.push({ num, value });
  }
  return out;
}

function asStream(value: PdfValue) {
  return value as Extract<PdfValue, { kind: 'stream' }>;
}

function extractXmpFields(xmp: string): Array<[string, string]> {
  const out: Array<[string, string]> = [];
  const patterns: Array<[string, RegExp]> = [
    ['dc:creator', /<dc:creator>[\s\S]*?<rdf:li[^>]*>([^<]{1,200})<\/rdf:li>/],
    ['dc:title', /<dc:title>[\s\S]*?<rdf:li[^>]*>([^<]{1,200})<\/rdf:li>/],
    ['xmp:CreatorTool', /<xmp:CreatorTool>([^<]{1,200})<\/xmp:CreatorTool>/],
    ['pdf:Producer', /<pdf:Producer>([^<]{1,200})<\/pdf:Producer>/],
    ['xmpMM:DocumentID', /<xmpMM:DocumentID>([^<]{1,200})<\/xmpMM:DocumentID>/],
  ];
  for (const [key, pattern] of patterns) {
    const match = pattern.exec(xmp);
    if (match?.[1]) out.push([key, match[1].trim()]);
  }
  return out;
}

/**
 * Serialise a redacted PDF.
 *
 * Every surviving object is written once, in order, followed by a fresh xref
 * table and trailer. Writing a complete file rather than appending an
 * incremental update is the point: an incremental update would leave the
 * original objects in the bytes, which is the very failure this adapter detects
 * in other people's documents.
 */
function writePdf(
  store: PdfObjectStore,
  model: DocumentModel,
  edits: ReadonlyMap<number, Array<{ start: number; end: number; replacement: string }>>,
  bars: ReadonlyArray<{ page: number; rect: Rect }>,
  droppedNodes: ReadonlySet<string>,
  droppedObjects: ReadonlySet<number>,
): Uint8Array {
  const parts: Uint8Array[] = [];
  const offsets = new Map<number, number>();
  let length = 0;

  const push = (text: string | Uint8Array): void => {
    const bytes = typeof text === 'string' ? Uint8Array.from(text, (c) => c.charCodeAt(0) & 0xff) : text;
    parts.push(bytes);
    length += bytes.length;
  };

  push('%PDF-1.7\n%\xE2\xE3\xCF\xD3\n');

  const droppedKeys = new Set<string>();
  for (const id of droppedNodes) {
    const node = model.nodes.find((n) => n.id === id);
    const key = node?.attrs?.['key'];
    if (key !== undefined) droppedKeys.add(key);
  }

  // Bars are grouped per page so each page's overlay stream is written once.
  const barsByPage = new Map<number, Rect[]>();
  for (const bar of bars) {
    const bucket = barsByPage.get(bar.page) ?? [];
    bucket.push(bar.rect);
    barsByPage.set(bar.page, bucket);
  }

  const streamPages = contentStreamPageIndex(store);
  let maxObjectNumber = 0;

  for (const object of store.objects) {
    if (object.superseded) continue; // prior revisions are simply not written
    maxObjectNumber = Math.max(maxObjectNumber, object.num);

    // Objects the plan removed are simply not written. Blanking their contents
    // would leave the object in the file; omitting it removes it from the bytes.
    if (droppedObjects.has(object.num)) continue;

    const value = object.value;

    if (isStream(value)) {
      const type = store.get(value.dict, 'Type');
      const subtype = store.get(value.dict, 'Subtype');
      // XMP and embedded files are the channels a flattened rewrite is for.
      // Copying them forward would keep author, GPS, and attached spreadsheets
      // in a file whose page looks redacted.
      if (isName(type) && type.name === 'Metadata') continue;
      if (isName(subtype) && subtype.name === 'EmbeddedFile') continue;
    }
    if (isDict(value)) {
      const type = store.get(value, 'Type');
      if (isName(type) && type.name === 'Filespec') continue;
    }

    offsets.set(object.num, length);
    push(`${object.num} ${object.gen} obj\n`);

    if (isStream(value)) {
      const streamEdits = edits.get(object.num);
      const pageIdx = streamPages.get(object.num);
      const overlay = pageIdx !== undefined ? barsByPage.get(pageIdx) : undefined;

      if (streamEdits !== undefined || overlay !== undefined) {
        const { bytes, decoded } = store.decodeStream(value);
        if (!decoded) {
          throw new ClassifiedError(
            'E_UNSUPPORTED',
            `content stream in object ${object.num} uses a filter this build cannot decode, so its text cannot be removed`,
            { object: object.num },
          );
        }
        let content = latin1(bytes);
        for (const edit of [...(streamEdits ?? [])].sort((a, b) => b.start - a.start)) {
          content = content.slice(0, edit.start) + edit.replacement + content.slice(edit.end);
        }
        if (overlay !== undefined) {
          const paint = overlay
            .map((r) => `${fmt(r.x)} ${fmt(r.y)} ${fmt(r.width)} ${fmt(r.height)} re f`)
            .join('\n');
          content += `\nq 0 g 1 0 0 1 0 0 cm\n${paint}\nQ\n`;
        }
        // Written uncompressed: the result stays inspectable, and anyone can
        // confirm with a text editor that the words are actually gone.
        push(`<< /Length ${content.length} >>\nstream\n`);
        push(content);
        push('\nendstream\nendobj\n');
        continue;
      }

      push(serialiseDict(value.dict, droppedKeys, droppedObjects, value.raw.length));
      push('stream\n');
      push(value.raw);
      push('\nendstream\nendobj\n');
      continue;
    }

    push(serialiseValue(value, droppedKeys, droppedObjects));
    push('\nendobj\n');
  }
  void maxObjectNumber;

  // --- xref and trailer ----------------------------------------------------
  const xrefAt = length;
  const numbers = [...offsets.keys()].sort((a, b) => a - b);
  const highest = (numbers[numbers.length - 1] ?? 0) + 1;

  let xref = `xref\n0 ${highest}\n0000000000 65535 f \n`;
  for (let n = 1; n < highest; n++) {
    const offset = offsets.get(n);
    xref += offset === undefined
      ? '0000000000 65535 f \n'
      : `${String(offset).padStart(10, '0')} 00000 n \n`;
  }
  push(xref);

  const rootRef = findCatalogRef(store);
  push(`trailer\n<< /Size ${highest}${rootRef !== undefined ? ` /Root ${rootRef} 0 R` : ''} >>\nstartxref\n${xrefAt}\n%%EOF\n`);

  const out = new Uint8Array(length);
  let at = 0;
  for (const part of parts) {
    out.set(part, at);
    at += part.length;
  }
  return out;
}

function findCatalogRef(store: PdfObjectStore): number | undefined {
  for (const object of store.objects) {
    if (object.superseded || !isDict(object.value)) continue;
    const type = store.get(object.value, 'Type');
    if (isName(type) && type.name === 'Catalog') return object.num;
  }
  return undefined;
}

function fmt(value: number): string {
  return Number.isFinite(value) ? value.toFixed(2) : '0';
}

function serialiseDict(
  dict: PdfDict,
  droppedKeys: ReadonlySet<string>,
  droppedObjects: ReadonlySet<number>,
  streamLength: number,
): string {
  const entries: string[] = [];
  for (const [key, value] of dict.map) {
    if (droppedKeys.has(key)) continue;
    if (key === 'Length') continue;
    entries.push(`/${key} ${serialiseValue(value, droppedKeys, droppedObjects)}`);
  }
  entries.push(`/Length ${streamLength}`);
  return `<< ${entries.join(' ')} >>\n`;
}

function serialiseValue(
  value: PdfValue,
  droppedKeys: ReadonlySet<string>,
  droppedObjects: ReadonlySet<number>,
  depth = 0,
): string {
  if (depth > 32) return 'null';
  if (value === null) return 'null';
  if (typeof value === 'boolean') return value ? 'true' : 'false';
  if (typeof value === 'number') return Number.isInteger(value) ? String(value) : value.toFixed(4);
  if (isName(value)) return `/${value.name}`;
  if (isString(value)) return `(${escapePdfString(latin1(value.bytes))})`;
  if (Array.isArray(value)) {
    // References to removed objects are filtered out rather than written as
    // null, so an /Annots array shrinks instead of holding a hole.
    const kept = value.filter((v) => !(isRef(v) && droppedObjects.has(v.num)));
    return `[ ${kept.map((v) => serialiseValue(v, droppedKeys, droppedObjects, depth + 1)).join(' ')} ]`;
  }
  if (isStream(value)) return serialiseDict(value.dict, droppedKeys, droppedObjects, value.raw.length);
  if (isDict(value)) {
    const entries: string[] = [];
    for (const [key, entry] of value.map) {
      if (droppedKeys.has(key)) continue;
      if (isRef(entry) && droppedObjects.has(entry.num)) continue;
      entries.push(`/${key} ${serialiseValue(entry, droppedKeys, droppedObjects, depth + 1)}`);
    }
    return `<< ${entries.join(' ')} >>`;
  }
  return `${(value as { num: number }).num} ${(value as { gen: number }).gen} R`;
}

function escapePdfString(text: string): string {
  return text.replace(/[\\()]/g, (c) => `\\${c}`).replace(/[\r\n]/g, ' ');
}
