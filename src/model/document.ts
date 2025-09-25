/**
 * The intermediate document model.
 *
 * Everything downstream -- detection, classification, redaction, verification --
 * operates on this structure and never on a file format. A format is supported
 * by writing an adapter that produces a `DocumentModel` and can apply operations
 * back to the original bytes; nothing else in the engine changes.
 *
 * The model is intentionally flat. A tree of nodes with parent pointers is
 * cheaper to address, diff, and verify than nested children, and redaction
 * targets are always leaves.
 */

import type { Origin, Rect } from './geometry.js';

/** Opaque, adapter-assigned node identifier. Stable across parse/reparse. */
export type NodeId = string;

/** What a node holds. Drives which redaction strategies are legal for it. */
export type ContentKind =
  /** A run of extractable text. The primary redaction target. */
  | 'text'
  /** Raster image data. Redacted by destroying pixels, never by overlay. */
  | 'raster'
  /** Vector drawing operations. */
  | 'vector'
  /** A document or object metadata field (EXIF tag, XMP property, PDF Info). */
  | 'metadata'
  /** Comment, markup, or form field. A classic leak channel. */
  | 'annotation'
  /** Embedded file or attachment. */
  | 'attachment'
  /** Grouping node with no content of its own (page, section, table). */
  | 'container';

/**
 * Semantic role, when the adapter can determine one.
 *
 * Roles matter for marking: classification policies mark titles differently
 * from body paragraphs, and a banner must not be derived from a node that is
 * itself a banner.
 */
export type NodeRole =
  | 'page'
  | 'section'
  | 'heading'
  | 'title'
  | 'paragraph'
  | 'list-item'
  | 'table-cell'
  | 'caption'
  | 'header'
  | 'footer'
  | 'footnote'
  | 'banner-marking'
  | 'portion-marking'
  | 'signature'
  | 'unknown';

/** Reference to raster pixels held outside the node. */
export interface RasterRef {
  readonly width: number;
  readonly height: number;
  /** RGBA, 8 bits per channel, row-major, length `width * height * 4`. */
  readonly pixels: Uint8ClampedArray;
}

/** A single addressable piece of the document. */
export interface ContentNode {
  readonly id: NodeId;
  readonly kind: ContentKind;
  /** Parent container, or `undefined` for roots. */
  readonly parent?: NodeId;
  /** Zero-based page or sheet index, when the format is paginated. */
  readonly page?: number;
  /** Position in layout units. Absent when the format has no layout. */
  readonly bbox?: Rect;
  /** Text content for `text`, `metadata`, and `annotation` nodes. */
  readonly text?: string;
  /** Pixels for `raster` nodes. */
  readonly raster?: RasterRef;
  /** Semantic role, when known. */
  readonly role?: NodeRole;
  /**
   * Per-character layout boxes, index-aligned with `text`.
   *
   * When an adapter can supply these, redaction of a character range produces
   * an exact box. Without them the engine falls back to the whole node's bbox,
   * which over-redacts rather than under-redacts.
   */
  readonly glyphs?: readonly Rect[];
  /** Format-specific attributes, preserved verbatim through the pipeline. */
  readonly attrs?: Readonly<Record<string, string>>;
}

/** A parsed document ready for analysis. */
export interface DocumentModel {
  /** Stable identifier for this document within a session. */
  readonly id: string;
  /** IANA media type of the source, e.g. `application/pdf`. */
  readonly mediaType: string;
  /** Identifier of the adapter that produced this model. */
  readonly adapterId: string;
  /** Coordinate convention for every `bbox` and `glyphs` entry. */
  readonly origin: Origin;
  /** Page bounds in layout units, indexed by page number. */
  readonly pages: readonly Rect[];
  /** All nodes, in document order. */
  readonly nodes: readonly ContentNode[];
  /**
   * Digest of the exact source bytes this model was parsed from.
   *
   * The provenance manifest binds to this, so a manifest can never be
   * transplanted onto a different input.
   */
  readonly sourceDigest: string;
  /**
   * The original container bytes, when the adapter needs them to write output.
   *
   * Formats where redaction is byte surgery rather than a re-serialisation --
   * excising a JPEG segment, dropping a PDF object -- must reach the original
   * bytes from `apply`, which otherwise sees only the model. Adapters that
   * fully reconstruct their output from nodes leave this undefined.
   *
   * Treat it as sensitive: it is the unredacted source.
   */
  readonly raw?: Uint8Array;
}

/**
 * Addresses a target for detection findings and redaction operations.
 *
 * The three forms are not interchangeable. Text spans support surgical removal
 * with reflow; regions destroy pixels; whole nodes are dropped entirely. An
 * operation's legality is checked against the kind of location it names.
 */
export type Location = TextLocation | RegionLocation | NodeLocation;

/** A half-open character range `[start, end)` within a node's `text`. */
export interface TextLocation {
  readonly kind: 'text';
  readonly node: NodeId;
  readonly start: number;
  readonly end: number;
}

/** A rectangular area within a raster or laid-out node. */
export interface RegionLocation {
  readonly kind: 'region';
  readonly node: NodeId;
  readonly rect: Rect;
}

/** An entire node: a metadata field, an annotation, an attachment. */
export interface NodeLocation {
  readonly kind: 'node';
  readonly node: NodeId;
}

/** Index for O(1) node lookup and safe traversal of a model. */
export class DocumentIndex {
  readonly #byId: ReadonlyMap<NodeId, ContentNode>;
  readonly #childrenOf: ReadonlyMap<NodeId, readonly ContentNode[]>;
  readonly model: DocumentModel;

  constructor(model: DocumentModel) {
    this.model = model;
    const byId = new Map<NodeId, ContentNode>();
    const children = new Map<NodeId, ContentNode[]>();
    for (const node of model.nodes) {
      if (byId.has(node.id)) {
        throw new Error(`DocumentIndex: duplicate node id ${JSON.stringify(node.id)}`);
      }
      byId.set(node.id, node);
      if (node.parent !== undefined) {
        const bucket = children.get(node.parent);
        if (bucket) bucket.push(node);
        else children.set(node.parent, [node]);
      }
    }
    this.#byId = byId;
    this.#childrenOf = children;
  }

  get(id: NodeId): ContentNode | undefined {
    return this.#byId.get(id);
  }

  /** Look up a node, throwing with context when it is missing. */
  require(id: NodeId): ContentNode {
    const node = this.#byId.get(id);
    if (node === undefined) {
      throw new Error(`DocumentIndex: no node with id ${JSON.stringify(id)}`);
    }
    return node;
  }

  children(id: NodeId): readonly ContentNode[] {
    return this.#childrenOf.get(id) ?? [];
  }

  /** Walk from a node up to its root, nearest ancestor first. */
  ancestors(id: NodeId): ContentNode[] {
    const out: ContentNode[] = [];
    const seen = new Set<NodeId>([id]);
    let current = this.#byId.get(id);
    while (current?.parent !== undefined) {
      if (seen.has(current.parent)) break; // defend against adapter-introduced cycles
      seen.add(current.parent);
      const parent = this.#byId.get(current.parent);
      if (parent === undefined) break;
      out.push(parent);
      current = parent;
    }
    return out;
  }

  /** All nodes of the given kinds, in document order. */
  *ofKind(...kinds: readonly ContentKind[]): Generator<ContentNode> {
    const wanted = new Set(kinds);
    for (const node of this.model.nodes) {
      if (wanted.has(node.kind)) yield node;
    }
  }

  /** Resolve the text a location refers to, or `undefined` if it has none. */
  textAt(location: Location): string | undefined {
    const node = this.#byId.get(location.node);
    if (node?.text === undefined) return undefined;
    if (location.kind === 'text') return node.text.slice(location.start, location.end);
    if (location.kind === 'node') return node.text;
    return undefined;
  }

  /**
   * The tightest rectangle covering a location.
   *
   * For a text span with glyph boxes this is the union of the covered glyphs;
   * without them it degrades to the whole node's box, which over-redacts. The
   * fallback is deliberate: an oversized bar is a cosmetic problem, an
   * undersized one is a disclosure.
   */
  rectFor(location: Location): Rect | undefined {
    const node = this.#byId.get(location.node);
    if (node === undefined) return undefined;
    if (location.kind === 'region') return location.rect;
    if (location.kind === 'text' && node.glyphs !== undefined) {
      const covered = node.glyphs.slice(location.start, location.end);
      if (covered.length > 0) return unionOf(covered);
    }
    return node.bbox;
  }
}

function unionOf(rects: readonly Rect[]): Rect {
  let minX = Infinity;
  let minY = Infinity;
  let maxX = -Infinity;
  let maxY = -Infinity;
  for (const r of rects) {
    minX = Math.min(minX, r.x);
    minY = Math.min(minY, r.y);
    maxX = Math.max(maxX, r.x + r.width);
    maxY = Math.max(maxY, r.y + r.height);
  }
  return { x: minX, y: minY, width: maxX - minX, height: maxY - minY };
}

/** Stable string form of a location, used as a map key and in manifests. */
export function locationKey(location: Location): string {
  switch (location.kind) {
    case 'text':
      return `${location.node}:t:${location.start}-${location.end}`;
    case 'region': {
      const { x, y, width, height } = location.rect;
      return `${location.node}:r:${x},${y},${width},${height}`;
    }
    case 'node':
      return `${location.node}:n`;
  }
}
