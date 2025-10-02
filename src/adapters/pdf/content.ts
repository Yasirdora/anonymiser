/**
 * Content stream interpretation.
 *
 * A PDF page is a program: a sequence of operators that move a cursor, set a
 * font, show glyphs, and fill shapes. Reading it means running that program far
 * enough to know *where* each piece of text landed and *what* was drawn on top
 * of it.
 *
 * Two outputs matter. The text runs, with their byte ranges in the stream, are
 * what redaction rewrites. The filled rectangles are what the structural
 * detector compares against those runs to find the black box sitting over live
 * text -- the failure that leaked the Manafort filings and a long line of FOIA
 * releases, and the reason this adapter exists.
 */

import type { Rect } from '../../model/geometry.js';
import { latin1, PdfLexer, isName, isString, isArray, type PdfValue } from './objects.js';

/** A 2-D affine transform, in PDF's `[a b c d e f]` order. */
export type Matrix = readonly [number, number, number, number, number, number];

const IDENTITY: Matrix = [1, 0, 0, 1, 0, 0];

/** `m × n`, applying `m` first. */
export function multiply(m: Matrix, n: Matrix): Matrix {
  return [
    m[0] * n[0] + m[1] * n[2],
    m[0] * n[1] + m[1] * n[3],
    m[2] * n[0] + m[3] * n[2],
    m[2] * n[1] + m[3] * n[3],
    m[4] * n[0] + m[5] * n[2] + n[4],
    m[4] * n[1] + m[5] * n[3] + n[5],
  ];
}

function apply(m: Matrix, x: number, y: number): { x: number; y: number } {
  return { x: m[0] * x + m[2] * y + m[4], y: m[1] * x + m[3] * y + m[5] };
}

/** A run of text shown by one operator. */
export interface ContentText {
  readonly text: string;
  /** Position in PDF user space, origin bottom-left. */
  readonly rect: Rect;
  /** The show operator that produced it. */
  readonly operator: 'Tj' | 'TJ' | "'" | '"';
  /**
   * Byte range of the operator's argument within the decoded stream.
   *
   * Redaction rewrites exactly this range, which is what makes removal surgical:
   * nothing else in the stream shifts, so the page still renders and every other
   * operator keeps working.
   */
  readonly argStart: number;
  readonly argEnd: number;
  readonly fontSize: number;
}

/** A rectangle painted by the page. */
export interface ContentRect {
  readonly rect: Rect;
  /** True when the path was filled rather than merely stroked. */
  readonly filled: boolean;
  /** Constant alpha in force when it was painted. */
  readonly alpha: number;
  /** Approximate luminance of the fill colour, 0 (black) to 1 (white). */
  readonly luminance: number;
}

/** Everything one content stream drew. */
export interface ContentResult {
  readonly texts: readonly ContentText[];
  readonly rects: readonly ContentRect[];
}

interface GraphicsState {
  ctm: Matrix;
  alpha: number;
  fillLuminance: number;
  fontSize: number;
}

/**
 * Glyph width as a fraction of font size, used when no font metrics are loaded.
 *
 * Real widths live in the font program, and parsing embedded CFF and TrueType
 * tables to get them is a large amount of work for a bounding box that only has
 * to be *big enough*. 0.5 em is close to the average for the text faces used in
 * documents, and the box is padded before anything is burned in, so the error
 * lands on the safe side: a slightly wide bar rather than a clipped one.
 */
const AVERAGE_GLYPH_WIDTH = 0.5;

/**
 * Interpret one content stream.
 *
 * A tolerant interpreter, not a renderer: unknown operators are skipped rather
 * than treated as errors, because a stream this engine cannot fully model is
 * still a stream whose text must be found.
 */
export function parseContentStream(bytes: Uint8Array, base: Matrix = IDENTITY): ContentResult {
  const texts: ContentText[] = [];
  const rects: ContentRect[] = [];

  const stack: GraphicsState[] = [];
  let state: GraphicsState = { ctm: base, alpha: 1, fillLuminance: 0, fontSize: 12 };

  let textMatrix: Matrix = IDENTITY;
  let lineMatrix: Matrix = IDENTITY;
  let leading = 0;

  // Operands accumulate until an operator consumes them, with the byte range of
  // each recorded so a show operator can report where its argument sat.
  let operands: PdfValue[] = [];
  let spans: Array<{ start: number; end: number }> = [];
  let pendingPath: Rect[] = [];

  const lexer = new PdfLexer(bytes, 0);

  const showText = (
    text: string,
    operator: ContentText['operator'],
    span: { start: number; end: number } | undefined,
  ): void => {
    if (text.length === 0) return;
    const render = multiply(textMatrix, state.ctm);
    const origin = apply(render, 0, 0);
    const scale = Math.hypot(render[0], render[1]) || 1;
    const width = text.length * AVERAGE_GLYPH_WIDTH * state.fontSize * scale;
    const height = state.fontSize * scale;

    texts.push({
      text,
      // The text origin sits on the baseline; the box extends above it, with a
      // small allowance below for descenders.
      rect: { x: origin.x, y: origin.y - height * 0.22, width, height: height * 1.12 },
      operator,
      argStart: span?.start ?? -1,
      argEnd: span?.end ?? -1,
      fontSize: state.fontSize,
    });

    // Advance the text matrix so the next run on the same line is placed after
    // this one rather than on top of it.
    textMatrix = multiply([1, 0, 0, 1, width / (scale || 1), 0], textMatrix);
  };

  for (;;) {
    lexer.skipSpace();
    if (lexer.pos >= bytes.length) break;
    const start = lexer.pos;
    const value = lexer.parseValue();
    if (value === undefined) {
      if (lexer.pos <= start) lexer.pos = start + 1;
      continue;
    }

    // Operators come back from the lexer tagged with `#op:`.
    if (isName(value) && value.name.startsWith('#op:')) {
      const op = value.name.slice(4);
      const numbers = operands.filter((o): o is number => typeof o === 'number');

      switch (op) {
        case 'q':
          stack.push({ ...state });
          break;
        case 'Q':
          state = stack.pop() ?? state;
          break;
        case 'cm':
          if (numbers.length >= 6) {
            state.ctm = multiply(numbers.slice(-6) as unknown as Matrix, state.ctm);
          }
          break;

        case 'BT':
          textMatrix = IDENTITY;
          lineMatrix = IDENTITY;
          break;
        case 'ET':
          break;
        case 'Tf':
          if (numbers.length >= 1) state.fontSize = numbers[numbers.length - 1]!;
          break;
        case 'TL':
          if (numbers.length >= 1) leading = numbers[numbers.length - 1]!;
          break;
        case 'Td':
          if (numbers.length >= 2) {
            lineMatrix = multiply([1, 0, 0, 1, numbers[numbers.length - 2]!, numbers[numbers.length - 1]!], lineMatrix);
            textMatrix = lineMatrix;
          }
          break;
        case 'TD':
          if (numbers.length >= 2) {
            leading = -numbers[numbers.length - 1]!;
            lineMatrix = multiply([1, 0, 0, 1, numbers[numbers.length - 2]!, numbers[numbers.length - 1]!], lineMatrix);
            textMatrix = lineMatrix;
          }
          break;
        case 'Tm':
          if (numbers.length >= 6) {
            lineMatrix = numbers.slice(-6) as unknown as Matrix;
            textMatrix = lineMatrix;
          }
          break;
        case 'T*':
          lineMatrix = multiply([1, 0, 0, 1, 0, -leading], lineMatrix);
          textMatrix = lineMatrix;
          break;

        case 'Tj':
        case "'":
        case '"': {
          if (op !== 'Tj') {
            lineMatrix = multiply([1, 0, 0, 1, 0, -leading], lineMatrix);
            textMatrix = lineMatrix;
          }
          const last = operands[operands.length - 1];
          if (isString(last)) {
            showText(latin1(last.bytes), op, spans[operands.length - 1]);
          }
          break;
        }
        case 'TJ': {
          const array = operands[operands.length - 1];
          const span = spans[operands.length - 1];
          if (isArray(array)) {
            // A TJ array interleaves strings with kerning adjustments. The
            // pieces are joined so the run reads as one phrase: an SSN split
            // across three kerned fragments must still match as an SSN.
            const joined = array.filter(isString).map((s) => latin1(s.bytes)).join('');
            showText(joined, 'TJ', span);
          }
          break;
        }

        case 're':
          if (numbers.length >= 4) {
            const [x, y, w, h] = numbers.slice(-4) as [number, number, number, number];
            const a = apply(state.ctm, x, y);
            const b = apply(state.ctm, x + w, y + h);
            pendingPath.push({
              x: Math.min(a.x, b.x), y: Math.min(a.y, b.y),
              width: Math.abs(b.x - a.x), height: Math.abs(b.y - a.y),
            });
          }
          break;

        case 'f': case 'F': case 'f*': case 'b': case 'b*': case 'B': case 'B*':
          for (const rect of pendingPath) {
            rects.push({ rect, filled: true, alpha: state.alpha, luminance: state.fillLuminance });
          }
          pendingPath = [];
          break;
        case 'S': case 's': case 'n':
          pendingPath = [];
          break;

        case 'g': case 'G':
          if (numbers.length >= 1) state.fillLuminance = clamp01(numbers[numbers.length - 1]!);
          break;
        case 'rg': case 'RG':
          if (numbers.length >= 3) {
            const [r, gg, b] = numbers.slice(-3) as [number, number, number];
            state.fillLuminance = clamp01(0.2126 * r + 0.7152 * gg + 0.0722 * b);
          }
          break;
        case 'k': case 'K':
          if (numbers.length >= 4) {
            const [c, m, y, kk] = numbers.slice(-4) as [number, number, number, number];
            state.fillLuminance = clamp01((1 - c) * (1 - kk) * 0.3 + (1 - m) * (1 - kk) * 0.6 + (1 - y) * (1 - kk) * 0.1);
          }
          break;
        case 'sc': case 'scn':
          if (numbers.length >= 1) {
            state.fillLuminance = clamp01(numbers.reduce((s, n) => s + n, 0) / numbers.length);
          }
          break;
        default:
          break;
      }

      operands = [];
      spans = [];
      continue;
    }

    operands.push(value);
    spans.push({ start, end: lexer.pos });
    // A malformed stream can pile up operands without ever reaching an
    // operator; cap it so one bad page cannot exhaust memory.
    if (operands.length > 512) {
      operands = operands.slice(-64);
      spans = spans.slice(-64);
    }
  }

  return { texts, rects };
}

function clamp01(value: number): number {
  return value < 0 ? 0 : value > 1 ? 1 : value;
}

/**
 * Whether a painted rectangle reads as a redaction bar.
 *
 * Dark and near-opaque. This is the shape that, sitting over extractable text,
 * means the document looks redacted and is not.
 */
export function looksLikeRedactionBar(rect: ContentRect): boolean {
  return rect.filled && rect.alpha >= 0.85 && rect.luminance <= 0.35;
}
