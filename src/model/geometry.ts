/**
 * Axis-aligned geometry in the document's own layout units.
 *
 * The engine never assumes pixels. A PDF adapter reports points with the origin
 * at bottom-left; a raster adapter reports device pixels top-down. Each model
 * declares its `origin` so redaction boxes land where the caller expects.
 */

/** An axis-aligned rectangle. Width and height are non-negative. */
export interface Rect {
  readonly x: number;
  readonly y: number;
  readonly width: number;
  readonly height: number;
}

/** Which corner `(0, 0)` refers to, and which way `y` grows. */
export type Origin = 'top-left' | 'bottom-left';

/** Construct a rect from two corner points, in any order. */
export function rectFromPoints(x0: number, y0: number, x1: number, y1: number): Rect {
  return {
    x: Math.min(x0, x1),
    y: Math.min(y0, y1),
    width: Math.abs(x1 - x0),
    height: Math.abs(y1 - y0),
  };
}

export function rectRight(r: Rect): number {
  return r.x + r.width;
}

export function rectBottom(r: Rect): number {
  return r.y + r.height;
}

export function rectArea(r: Rect): number {
  return r.width * r.height;
}

/** True when the rectangles share any area. Edge contact alone is not overlap. */
export function rectIntersects(a: Rect, b: Rect): boolean {
  return (
    a.x < rectRight(b) && b.x < rectRight(a) && a.y < rectBottom(b) && b.y < rectBottom(a)
  );
}

/** The shared area of two rectangles, or `null` when they do not overlap. */
export function rectIntersection(a: Rect, b: Rect): Rect | null {
  const x = Math.max(a.x, b.x);
  const y = Math.max(a.y, b.y);
  const width = Math.min(rectRight(a), rectRight(b)) - x;
  const height = Math.min(rectBottom(a), rectBottom(b)) - y;
  if (width <= 0 || height <= 0) return null;
  return { x, y, width, height };
}

/** The smallest rectangle containing all inputs, or `null` for an empty list. */
export function rectUnion(rects: readonly Rect[]): Rect | null {
  if (rects.length === 0) return null;
  let minX = Infinity;
  let minY = Infinity;
  let maxX = -Infinity;
  let maxY = -Infinity;
  for (const r of rects) {
    minX = Math.min(minX, r.x);
    minY = Math.min(minY, r.y);
    maxX = Math.max(maxX, rectRight(r));
    maxY = Math.max(maxY, rectBottom(r));
  }
  return { x: minX, y: minY, width: maxX - minX, height: maxY - minY };
}

/**
 * Grow a rectangle on every side.
 *
 * Redaction boxes are padded before they are burned in. Glyph bounding boxes
 * routinely under-report ascenders, descenders, and antialiasing fringe, and a
 * box that clips a descender leaves a legible sliver of the character below the
 * bar -- enough for a reader to recover the word.
 */
export function inflateRect(r: Rect, padding: number): Rect {
  return {
    x: r.x - padding,
    y: r.y - padding,
    width: Math.max(0, r.width + padding * 2),
    height: Math.max(0, r.height + padding * 2),
  };
}

/** Clamp a rectangle to lie within `bounds`, returning `null` if fully outside. */
export function clampRect(r: Rect, bounds: Rect): Rect | null {
  return rectIntersection(r, bounds);
}

/** Round a rect outward to whole units, so a burn-in never leaves a partial pixel. */
export function snapRectOutward(r: Rect): Rect {
  const x = Math.floor(r.x);
  const y = Math.floor(r.y);
  return {
    x,
    y,
    width: Math.ceil(rectRight(r)) - x,
    height: Math.ceil(rectBottom(r)) - y,
  };
}
