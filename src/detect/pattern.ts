/**
 * The pattern detector: a declarative rule format plus the runner that applies
 * it to every text-bearing node in a document.
 *
 * Rules are data, not code. That keeps pattern packs auditable by people who
 * are not TypeScript programmers, which for a compliance tool is most of the
 * people who need to check them.
 */

import { toBase32 } from '../internal/bytes.js';
import { sha256Text } from '../internal/hash.js';
import type { ContentNode, TextLocation } from '../model/document.js';
import { scoreContext, windowAround, type ContextSpec } from './context.js';
import {
  Confidence,
  type DetectionContext,
  type Detector,
  type EntityType,
  type Evidence,
  type Finding,
} from './types.js';

/** Result of a rule-supplied validator. */
export interface ValidationResult {
  readonly ok: boolean;
  /** Evidence recorded whether the check passed or failed. */
  readonly signal: string;
  readonly note: string;
  /** Confidence delta applied when `ok` is true. */
  readonly weight?: number;
}

/** One declarative detection rule. */
export interface PatternRule {
  /** Unique within a pack, e.g. `financial.card`. */
  readonly id: string;
  readonly type: EntityType;
  /**
   * The matching expression. Must carry the `g` flag; the runner manages
   * `lastIndex` and never shares a RegExp between scans.
   */
  readonly pattern: RegExp;
  /** Capture group holding the value. Defaults to 0, the whole match. */
  readonly group?: number;
  /** Confidence before validation and context adjustment. */
  readonly baseConfidence: number;
  /** Checksum or structural check. Absent means shape-only. */
  readonly validate?: (value: string, match: RegExpExecArray) => ValidationResult;
  /**
   * Whether a failed validation drops the match rather than demoting it.
   * Defaults to true, which is correct for checksummed identifiers: a failed
   * check means the value is a different kind of thing, not a weaker instance
   * of this one.
   */
  readonly dropOnInvalidation?: boolean;
  /** Canonical form, for cross-document token consistency. */
  readonly normalize?: (value: string) => string;
  readonly context?: ContextSpec;
  /** BCP 47 prefixes this rule applies to. Absent means all locales. */
  readonly locales?: readonly string[];
  /** One line, shown in review UIs and pack documentation. */
  readonly description: string;
}

/** A named, versioned collection of rules. */
export interface PatternPack {
  readonly id: string;
  readonly version: string;
  readonly rules: readonly PatternRule[];
}

/** Options for {@link patternDetector}. */
export interface PatternDetectorOptions {
  /** Findings below this confidence after scoring are discarded. Defaults to 0.15. */
  readonly minConfidence?: number;
  /** Restrict to these rule ids. */
  readonly include?: readonly string[];
  /** Exclude these rule ids; applied after `include`. */
  readonly exclude?: readonly string[];
}

/**
 * Build a detector from one or more pattern packs.
 *
 * Rules are validated once here rather than per document, and every RegExp is
 * cloned per node so a rule's `lastIndex` cannot leak between scans, a bug that
 * silently skips findings and is close to impossible to reproduce.
 */
export function patternDetector(
  packs: readonly PatternPack[],
  options: PatternDetectorOptions = {},
): Detector {
  const include = options.include ? new Set(options.include) : undefined;
  const exclude = new Set(options.exclude ?? []);
  const minConfidence = options.minConfidence ?? 0.15;

  const rules: PatternRule[] = [];
  const seen = new Set<string>();
  for (const pack of packs) {
    for (const rule of pack.rules) {
      if (include !== undefined && !include.has(rule.id)) continue;
      if (exclude.has(rule.id)) continue;
      if (seen.has(rule.id)) {
        throw new Error(`patternDetector: duplicate rule id ${JSON.stringify(rule.id)}`);
      }
      if (!rule.pattern.global) {
        throw new Error(`patternDetector: rule ${rule.id} pattern must have the g flag`);
      }
      seen.add(rule.id);
      rules.push(rule);
    }
  }

  const version = packs.map((p) => `${p.id}@${p.version}`).join('+');
  const emits = [...new Set(rules.map((r) => r.type))];

  return {
    id: 'pattern',
    version,
    emits,
    stage: 0,
    detect(context: DetectionContext): readonly Finding[] {
      const findings: Finding[] = [];
      for (const node of context.index.ofKind('text', 'metadata', 'annotation')) {
        if (node.text === undefined || node.text.length === 0) continue;
        for (const rule of rules) {
          if (!appliesToLocale(rule, context.locales)) continue;
          collectMatches(rule, node, node.text, minConfidence, findings);
        }
      }
      return findings;
    },
  };
}

function appliesToLocale(rule: PatternRule, locales: readonly string[]): boolean {
  if (rule.locales === undefined || rule.locales.length === 0) return true;
  if (locales.length === 0) return true;
  return rule.locales.some((ruleLocale) =>
    locales.some((active) => active.toLowerCase().startsWith(ruleLocale.toLowerCase())),
  );
}

function collectMatches(
  rule: PatternRule,
  node: ContentNode,
  text: string,
  minConfidence: number,
  out: Finding[],
): void {
  // A fresh RegExp per node keeps lastIndex strictly local to this scan.
  const re = new RegExp(rule.pattern.source, rule.pattern.flags);
  const groupIndex = rule.group ?? 0;

  let match: RegExpExecArray | null;
  while ((match = re.exec(text)) !== null) {
    // A zero-length match would spin forever; step past it.
    if (match[0].length === 0) {
      re.lastIndex++;
      continue;
    }

    const value = match[groupIndex];
    if (value === undefined || value.length === 0) continue;

    const offsetInMatch = groupIndex === 0 ? 0 : match[0].indexOf(value);
    const start = match.index + (offsetInMatch >= 0 ? offsetInMatch : 0);
    const end = start + value.length;

    const evidence: Evidence[] = [
      { signal: `pattern:${rule.id}`, note: rule.description, weight: rule.baseConfidence },
    ];
    let confidence = rule.baseConfidence;

    if (rule.validate !== undefined) {
      const result = rule.validate(value, match);
      if (!result.ok) {
        if (rule.dropOnInvalidation !== false) continue;
        confidence -= 0.3;
        evidence.push({ signal: result.signal, note: result.note, weight: -0.3 });
      } else {
        const weight = Math.max(0, result.weight ?? Confidence.VERIFIED - rule.baseConfidence);
        confidence = Math.min(Confidence.VERIFIED, confidence + weight);
        evidence.push({ signal: result.signal, note: result.note, weight });
      }
    }

    const score = scoreContext(rule.context, windowAround(text, start, end, rule.context?.window));
    if (score.rejected) continue;
    confidence = clamp01(confidence + score.delta);
    evidence.push(...score.evidence);

    if (confidence < minConfidence) continue;

    const location: TextLocation = { kind: 'text', node: node.id, start, end };
    const normalized = rule.normalize?.(value);
    out.push({
      id: findingId(rule.id, node.id, start, value),
      ruleId: `pattern:${rule.id}`,
      type: rule.type,
      location,
      value,
      confidence,
      evidence,
      ...(normalized !== undefined ? { normalized } : {}),
    });
  }
}

function clamp01(value: number): number {
  return value < 0 ? 0 : value > 1 ? 1 : value;
}

/**
 * Content-derived finding id.
 *
 * Deterministic ids let a review decision survive a re-scan of the same
 * document and let two pipeline runs be diffed. The value is hashed rather than
 * embedded so ids can be logged without disclosing what they refer to.
 */
export function findingId(
  ruleId: string,
  nodeId: string,
  start: number,
  value: string,
): string {
  return `f_${toBase32(sha256Text(`${ruleId} ${nodeId} ${start} ${value}`), 16).toLowerCase()}`;
}
