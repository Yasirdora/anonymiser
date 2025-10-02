/**
 * Half-open interval algebra over `[start, end)`.
 *
 * Findings from independent detectors overlap constantly -- an email address is
 * also matched by a generic identifier rule, a passport number sits inside a
 * matched line of an MRZ block. Redaction correctness depends on resolving those
 * overlaps deterministically before anything is written.
 */

export interface Interval {
  readonly start: number;
  readonly end: number;
}

/** True when the two intervals share at least one position. */
export function overlaps(a: Interval, b: Interval): boolean {
  return a.start < b.end && b.start < a.end;
}

/** True when `outer` fully contains `inner`. */
export function contains(outer: Interval, inner: Interval): boolean {
  return outer.start <= inner.start && outer.end >= inner.end;
}

/** Number of positions the two intervals share. */
export function intersectionLength(a: Interval, b: Interval): number {
  return Math.max(0, Math.min(a.end, b.end) - Math.max(a.start, b.start));
}

/**
 * Merge overlapping and adjacent intervals into a minimal covering set.
 *
 * Adjacent intervals are merged too (`[0,3)` and `[3,5)` become `[0,5)`), since
 * leaving a zero-width seam between two redactions produces the visual artifact
 * of two boxes where there should be one.
 */
export function mergeIntervals<T extends Interval>(
  intervals: readonly T[],
): Array<{ start: number; end: number; members: T[] }> {
  if (intervals.length === 0) return [];
  const sorted = [...intervals].sort((a, b) => a.start - b.start || a.end - b.end);
  const out: Array<{ start: number; end: number; members: T[] }> = [];

  for (const item of sorted) {
    const last = out[out.length - 1];
    if (last !== undefined && item.start <= last.end) {
      last.end = Math.max(last.end, item.end);
      last.members.push(item);
    } else {
      out.push({ start: item.start, end: item.end, members: [item] });
    }
  }
  return out;
}

/**
 * Subtract a set of intervals from `[0, length)`, returning the gaps.
 * Used to reassemble the surviving text around removed spans.
 */
export function complement(length: number, removed: readonly Interval[]): Interval[] {
  const merged = mergeIntervals(removed);
  const gaps: Interval[] = [];
  let cursor = 0;
  for (const block of merged) {
    const start = Math.max(0, Math.min(block.start, length));
    const end = Math.max(0, Math.min(block.end, length));
    if (start > cursor) gaps.push({ start: cursor, end: start });
    cursor = Math.max(cursor, end);
  }
  if (cursor < length) gaps.push({ start: cursor, end: length });
  return gaps;
}
