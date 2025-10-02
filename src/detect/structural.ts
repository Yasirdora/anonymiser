/**
 * Structural risk detection.
 *
 * Pattern detectors find sensitive *values*. This one finds sensitive
 * *arrangements*: the metadata block nobody looks at, the tracked change that
 * still holds the original sentence, the black rectangle sitting on top of live
 * text. Every documented redaction disaster of the last decade belongs to this
 * category rather than to the first, and no library in the ecosystem looks for
 * them.
 */

import { toBase32 } from '../internal/bytes.js';
import { sha256Text } from '../internal/hash.js';
import type { ContentNode } from '../model/document.js';
import { rectIntersects } from '../model/geometry.js';
import {
  Confidence,
  type DetectionContext,
  type Detector,
  type EntityType,
  type Evidence,
  type Finding,
} from './types.js';

/**
 * Metadata keys that carry identity or provenance.
 *
 * The value of a metadata field is often perfectly ordinary; the risk is that
 * it exists at all in a document about to be published. `Author` is the single
 * most common source of accidental attribution in released documents.
 */
const IDENTIFYING_METADATA = new Set([
  'author', 'creator', 'producer', 'lastmodifiedby', 'last_modified_by', 'company',
  'manager', 'owner', 'username', 'user', 'creatortool', 'device', 'make', 'model',
  'serialnumber', 'bodyserialnumber', 'lensserialnumber', 'ownername', 'artist',
  'copyright', 'hostcomputer', 'software', 'documentid', 'instanceid', 'originaldocumentid',
]);

/** Metadata keys that disclose location. */
const LOCATION_METADATA = new Set([
  'gpslatitude', 'gpslongitude', 'gpsaltitude', 'gpsposition', 'gpsdatestamp',
  'location', 'sublocation', 'city', 'state', 'country', 'gpsareainformation',
]);

function classifyMetadataKey(key: string): { type: EntityType; note: string } | undefined {
  const normalized = key.toLowerCase().replace(/[^a-z]/g, '');
  if (LOCATION_METADATA.has(normalized)) {
    return { type: 'geo.coordinates', note: 'metadata field recording where the file was created' };
  }
  if (IDENTIFYING_METADATA.has(normalized)) {
    return { type: 'risk.metadata', note: 'metadata field identifying the author, device, or originating system' };
  }
  return undefined;
}

function structuralFinding(
  ruleId: string,
  type: EntityType,
  node: ContentNode,
  value: string,
  confidence: number,
  evidence: readonly Evidence[],
): Finding {
  return {
    id: `f_${toBase32(sha256Text(`${ruleId} ${node.id} ${value}`), 16).toLowerCase()}`,
    ruleId,
    type,
    location: { kind: 'node', node: node.id },
    value,
    confidence,
    evidence: [...evidence],
  };
}

/**
 * Detects risky document structure.
 *
 * Runs at stage 1 so it can see pattern findings: an annotation that contains a
 * detected SSN is a different severity from one that contains a spelling note,
 * and the overlay check needs to know which regions were already flagged.
 */
export function structuralDetector(): Detector {
  return {
    id: 'structural',
    version: '1.0.0',
    emits: [
      'risk.metadata',
      'risk.revision-history',
      'risk.attachment',
      'risk.hidden-content',
      'risk.cosmetic-redaction',
      'geo.coordinates',
    ],
    stage: 1,
    detect(context: DetectionContext): readonly Finding[] {
      const findings: Finding[] = [];

      /**
       * Whether an earlier detector already made this exact claim about this
       * node.
       *
       * A GPS metadata field is reported here as a location risk *and* by the
       * geo pattern rules as a coordinate, which is the same disclosure counted
       * twice: two findings, two redaction operations, two manifest entries for
       * one value. The pattern finding is the better of the two -- it has the
       * exact span and the precision evidence -- so this one steps aside.
       *
       * Only an identical type defers. An `Author` field holding a detected
       * person name is two genuinely different claims: that a name is present,
       * and that the document is attributed to someone.
       */
      const alreadyClaimed = (nodeId: string, type: EntityType): boolean =>
        context.priorFindings.some((f) => f.location.node === nodeId && f.type === type);

      for (const node of context.index.ofKind('metadata')) {
        const key = node.attrs?.['key'] ?? node.role ?? '';
        const classified = classifyMetadataKey(key);
        if (classified === undefined || node.text === undefined || node.text.trim() === '') continue;
        if (alreadyClaimed(node.id, classified.type)) continue;
        findings.push(
          structuralFinding(
            'structural:metadata',
            classified.type,
            node,
            node.text,
            Confidence.VERIFIED,
            [{ signal: 'structure:metadata-key', note: `${classified.note} (${key})`, weight: Confidence.VERIFIED }],
          ),
        );
      }

      for (const node of context.index.ofKind('attachment')) {
        findings.push(
          structuralFinding(
            'structural:attachment',
            'risk.attachment',
            node,
            node.attrs?.['name'] ?? node.id,
            Confidence.STRONG,
            [{
              signal: 'structure:embedded-file',
              note: 'an embedded file, whose contents are not covered by redactions applied to the visible page',
              weight: Confidence.STRONG,
            }],
          ),
        );
      }

      for (const node of context.index.ofKind('annotation')) {
        if (node.text === undefined || node.text.trim() === '') continue;
        findings.push(
          structuralFinding(
            'structural:annotation',
            'risk.hidden-content',
            node,
            node.text,
            Confidence.LIKELY,
            [{
              signal: 'structure:annotation',
              note: 'a comment or form field, which readers do not see on the page but every extraction tool does',
              weight: Confidence.LIKELY,
            }],
          ),
        );
      }

      if (context.model.nodes.some((n) => n.attrs?.['revision'] !== undefined)) {
        const marker = context.model.nodes.find((n) => n.attrs?.['revision'] !== undefined)!;
        findings.push(
          structuralFinding(
            'structural:revision-history',
            'risk.revision-history',
            marker,
            marker.attrs?.['revision'] ?? 'revision',
            Confidence.STRONG,
            [{
              signal: 'structure:revision',
              note: 'the file retains earlier revisions, from which pre-redaction text can be recovered',
              weight: Confidence.STRONG,
            }],
          ),
        );
      }

      findings.push(...detectCosmeticRedactions(context));
      return findings;
    },
  };
}

/**
 * The signature failure: an opaque shape covering text that is still there.
 *
 * A filled rectangle sitting on top of a text run, where the text run is still
 * present in the model, means the document *looks* redacted and is not. This is
 * exactly what happened in the Manafort filing and in the DOJ release, and it
 * is mechanically detectable in about thirty lines, which is the frustrating
 * part.
 */
function detectCosmeticRedactions(context: DetectionContext): Finding[] {
  const findings: Finding[] = [];
  const opaqueShapes = [...context.index.ofKind('vector')].filter(isOpaqueFill);
  if (opaqueShapes.length === 0) return findings;

  const textNodes = [...context.index.ofKind('text')].filter(
    (n) => n.bbox !== undefined && n.text !== undefined && n.text.trim() !== '',
  );

  for (const shape of opaqueShapes) {
    if (shape.bbox === undefined) continue;
    for (const text of textNodes) {
      if (text.page !== shape.page) continue;
      if (!rectIntersects(shape.bbox, text.bbox!)) continue;

      findings.push(
        structuralFinding(
          'structural:cosmetic-redaction',
          'risk.cosmetic-redaction',
          text,
          text.text!,
          Confidence.VERIFIED,
          [{
            signal: 'structure:overlay-over-live-text',
            note: `an opaque shape covers this text but the text is still extractable; the document looks redacted and is not`,
            weight: Confidence.VERIFIED,
          }],
        ),
      );
    }
  }
  return findings;
}

/**
 * Whether a vector node is an opaque filled shape.
 *
 * Adapters report fill and opacity in `attrs`. Anything at or above 0.85 alpha
 * is treated as covering: below that a reader can still make out the text, so
 * it is a different (also bad) problem, and above it the text is invisible on
 * screen, which is what makes the failure so hard to catch by eye.
 */
function isOpaqueFill(node: ContentNode): boolean {
  const attrs = node.attrs;
  if (attrs === undefined) return false;
  if (attrs['filled'] !== 'true') return false;
  const alpha = attrs['opacity'] === undefined ? 1 : Number(attrs['opacity']);
  return Number.isFinite(alpha) && alpha >= 0.85;
}
