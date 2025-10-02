/**
 * The plain-text adapter.
 *
 * Handles strings, and structured documents carrying metadata, annotations, and
 * attachments alongside their body text. Useful in its own right for logs,
 * transcripts, CSV extracts, and Markdown, and it is the reference
 * implementation of the adapter contract: an adapter for a richer format has
 * more parsing to do but nothing structurally different.
 */

import { toHex } from '../../internal/bytes.js';
import { sha256Text } from '../../internal/hash.js';
import { ClassifiedError } from '../../errors.js';
import type { AdapterCapabilities, DocumentAdapter, ParseOptions } from '../../adapter.js';
import type { ContentNode, DocumentModel, NodeId } from '../../model/document.js';
import { applyTextOperations, groupOperationsByNode } from '../../redact/apply.js';
import type { RedactionOperation } from '../../redact/plan.js';

/** A document as this adapter sees it. */
export interface TextDocument {
  readonly text: string;
  /** Document metadata: author, title, tool, and anything else the source carried. */
  readonly metadata?: Readonly<Record<string, string>>;
  /** Comments and review notes held outside the body. */
  readonly annotations?: readonly TextAnnotation[];
  /** Embedded files. Their text is scanned; their bytes are passed through. */
  readonly attachments?: readonly TextAttachment[];
}

export interface TextAnnotation {
  readonly id: string;
  readonly text: string;
  readonly author?: string;
}

export interface TextAttachment {
  readonly name: string;
  /** Extracted text, when the caller could produce it. */
  readonly text?: string;
}

/** What the caller may pass to `parse`. */
export type TextSource = string | TextDocument;

const CAPABILITIES: AdapterCapabilities = {
  strategies: ['remove', 'replace', 'mask', 'pseudonymize', 'synthesize'],
  removesMetadata: true,
  removesAttachments: true,
  // Plain text carries no revision history, so there is none to fail to remove.
  removesRevisionHistory: true,
  verifiable: true,
};

/**
 * Split the body into paragraphs on blank lines.
 *
 * Paragraphs are the portion unit: they are what a reader perceives as a block,
 * what a classification marking attaches to, and what a reviewer accepts or
 * rejects as a whole.
 */
function stripBom(text: string): string {
  return text.charCodeAt(0) === 0xfeff ? text.slice(1) : text;
}

function splitParagraphs(text: string): Array<{ start: number; end: number; text: string }> {
  const out: Array<{ start: number; end: number; text: string }> = [];
  const separator = /\n[ \t]*\n/g;
  let cursor = 0;
  let match: RegExpExecArray | null;

  while ((match = separator.exec(text)) !== null) {
    const end = match.index;
    if (end > cursor) out.push({ start: cursor, end, text: text.slice(cursor, end) });
    cursor = separator.lastIndex;
  }
  if (cursor < text.length) out.push({ start: cursor, end: text.length, text: text.slice(cursor) });
  if (out.length === 0 && text.length > 0) out.push({ start: 0, end: text.length, text });
  return out;
}

/** The plain-text adapter. */
export const textAdapter: DocumentAdapter<TextSource, TextDocument> = {
  id: 'text',
  version: '1.0.0',
  mediaTypes: ['text/plain', 'text/markdown', 'text/csv', 'application/json'],
  capabilities: CAPABILITIES,

  parse(source: TextSource, options: ParseOptions = {}): DocumentModel {
    const incoming: TextDocument = typeof source === 'string' ? { text: source } : source;
    const document: TextDocument = { ...incoming, text: stripBom(incoming.text) };
    const nodes: ContentNode[] = [];

    const rootId = 'root';
    nodes.push({ id: rootId, kind: 'container', role: 'section' });

    for (const [index, paragraph] of splitParagraphs(document.text).entries()) {
      nodes.push({
        id: `p${index}`,
        kind: 'text',
        parent: rootId,
        role: 'paragraph',
        text: paragraph.text,
        // The source offset is retained so an operation on a paragraph can be
        // mapped back to a position in the original string.
        attrs: { sourceStart: String(paragraph.start), sourceEnd: String(paragraph.end) },
      });
    }

    for (const [key, value] of Object.entries(document.metadata ?? {})) {
      nodes.push({
        id: `meta:${key}`,
        kind: 'metadata',
        parent: rootId,
        text: value,
        attrs: { key },
      });
    }

    for (const annotation of document.annotations ?? []) {
      nodes.push({
        id: `note:${annotation.id}`,
        kind: 'annotation',
        parent: rootId,
        text: annotation.text,
        attrs: annotation.author === undefined ? {} : { author: annotation.author },
      });
    }

    for (const attachment of document.attachments ?? []) {
      nodes.push({
        id: `file:${attachment.name}`,
        kind: 'attachment',
        parent: rootId,
        ...(attachment.text !== undefined ? { text: attachment.text } : {}),
        attrs: { name: attachment.name },
      });
    }

    const sourceDigest = toHex(sha256Text(serialize(document)));
    return {
      id: options.documentId ?? `doc_${sourceDigest.slice(0, 16)}`,
      mediaType: 'text/plain',
      adapterId: 'text',
      origin: 'top-left',
      pages: [],
      nodes,
      sourceDigest,
    };
  },

  apply(model: DocumentModel, operations: readonly RedactionOperation[]): TextDocument {
    const byNode = groupOperationsByNode(operations);
    const removedNodes = new Set<NodeId>();
    const replacedNodes = new Map<NodeId, string>();

    for (const [nodeId, ops] of byNode) {
      for (const op of ops) {
        if (op.location.kind !== 'node') continue;
        if (op.strategy === 'remove') removedNodes.add(nodeId);
        // Every other whole-node strategy substitutes the node's entire value.
        // Ignoring these would leave the original in place, which is precisely
        // the failure the verifier exists to catch.
        else replacedNodes.set(nodeId, op.replacement ?? '');
      }
    }

    const valueOf = (node: { id: NodeId; text?: string }, ops: readonly RedactionOperation[]): string => {
      const whole = replacedNodes.get(node.id);
      if (whole !== undefined) return whole;
      const text = node.text ?? '';
      const spans = ops.filter((op) => op.location.kind === 'text');
      return spans.length === 0 ? text : applyTextOperations(text, spans).text;
    };

    const paragraphs: string[] = [];
    const metadata: Record<string, string> = {};
    const annotations: TextAnnotation[] = [];
    const attachments: TextAttachment[] = [];

    for (const node of model.nodes) {
      if (removedNodes.has(node.id)) continue;
      const ops = byNode.get(node.id) ?? [];

      switch (node.kind) {
        case 'text':
          paragraphs.push(valueOf(node, ops));
          break;
        case 'metadata': {
          const key = node.attrs?.['key'];
          if (key === undefined) break;
          metadata[key] = valueOf(node, ops);
          break;
        }
        case 'annotation':
          annotations.push({
            id: node.id.replace(/^note:/, ''),
            text: valueOf(node, ops),
            ...(node.attrs?.['author'] !== undefined ? { author: node.attrs['author'] } : {}),
          });
          break;
        case 'attachment': {
          const name = node.attrs?.['name'];
          if (name === undefined) break;
          attachments.push({
            name,
            ...(node.text !== undefined ? { text: valueOf(node, ops) } : {}),
          });
          break;
        }
        default:
          break;
      }
    }

    return {
      text: paragraphs.join('\n\n'),
      ...(Object.keys(metadata).length > 0 ? { metadata } : {}),
      ...(annotations.length > 0 ? { annotations } : {}),
      ...(attachments.length > 0 ? { attachments } : {}),
    };
  },

  reparse(output: TextDocument): DocumentModel {
    return textAdapter.parse(output);
  },
};

/**
 * Stable serialisation for digesting.
 *
 * Keys are sorted so that two structurally identical documents digest
 * identically regardless of how the caller built the object; the plan binds to
 * this digest and would otherwise reject a document for a difference in
 * property order.
 */
function serialize(document: TextDocument): string {
  const metadata = Object.entries(document.metadata ?? {}).sort(([a], [b]) =>
    a < b ? -1 : a > b ? 1 : 0,
  );
  const parts = [
    document.text,
    ...metadata.map(([k, v]) => `${k}=${v}`),
    ...(document.annotations ?? []).map((a) => `note:${a.id}:${a.text}`),
    ...(document.attachments ?? []).map((f) => `file:${f.name}:${f.text ?? ''}`),
  ];
  return parts.join(' ');
}

/** Convenience wrapper that reports a clear error for a non-string input. */
export function asTextDocument(value: unknown): TextDocument {
  if (typeof value === 'string') return { text: value };
  if (typeof value === 'object' && value !== null && 'text' in value) return value as TextDocument;
  throw new ClassifiedError('E_PARSE', 'expected a string or a TextDocument', {
    received: typeof value,
  });
}
