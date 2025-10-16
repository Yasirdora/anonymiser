import assert from 'node:assert/strict';
import { describe, it } from 'node:test';

import { textAdapter, type TextDocument } from '../src/adapters/text/index.js';
import { classify } from '../src/classify/engine.js';
import { compilePolicy } from '../src/classify/lattice.js';
import { privacyPolicy } from '../src/classify/packs/index.js';
import { detect } from '../src/detect/engine.js';
import { standardDetectors } from '../src/detect/index.js';
import { ClassifiedError, VerificationFailedError } from '../src/errors.js';
import { utf8Encode } from '../src/internal/bytes.js';
import type { DocumentModel } from '../src/model/document.js';
import { redactDocument } from '../src/pipeline.js';
import { applyTextOperations, blackoutRegion } from '../src/redact/apply.js';
import { planRedactions, validatePlan, type RedactionOperation } from '../src/redact/plan.js';
import { maskValue, PseudonymGenerator } from '../src/redact/pseudonym.js';
import { assertStrategyPermitted, strategySpec } from '../src/redact/strategies.js';
import { verify } from '../src/verify/verifier.js';

const policy = compilePolicy(privacyPolicy);
const KEY = utf8Encode('a-test-key-of-sufficient-length-for-hmac');
const SALT = utf8Encode('a-test-salt-of-sufficient-length');

function op(
  overrides: Partial<RedactionOperation> & Pick<RedactionOperation, 'location'>,
): RedactionOperation {
  const base: RedactionOperation = {
    id: 'op1',
    strategy: 'replace',
    reason: { code: 'test', authority: 'test' },
    findingIds: [],
    ...overrides,
  };
  // `remove` takes no replacement; anything else defaults to a visible marker.
  if (base.strategy === 'remove' || overrides.replacement !== undefined) return base;
  return { ...base, replacement: '[REDACTED]' };
}

describe('the safety model', () => {
  it('refuses blur, and says why', () => {
    assert.throws(
      () => assertStrategyPermitted('blur'),
      (error: unknown) => {
        assert.ok(error instanceof ClassifiedError);
        assert.equal(error.code, 'E_COSMETIC_REFUSED');
        assert.match(error.message, /Unredacter/);
        return true;
      },
    );
  });

  it('refuses pixelation on the same grounds', () => {
    assert.throws(() => assertStrategyPermitted('pixelate'), /E_COSMETIC_REFUSED|does not destroy/);
  });

  it('permits an unsafe strategy only with an explicit opt-in', () => {
    assert.doesNotThrow(() =>
      assertStrategyPermitted('blur', { allowRecoverableStrategies: true }),
    );
  });

  it('permits every destructive strategy without ceremony', () => {
    for (const strategy of ['remove', 'replace', 'mask', 'pseudonymize', 'blackout'] as const) {
      assert.doesNotThrow(() => assertStrategyPermitted(strategy));
    }
  });

  it('classifies blur and pixelate as non-destructive and recoverable', () => {
    for (const strategy of ['blur', 'pixelate'] as const) {
      const spec = strategySpec(strategy);
      assert.equal(spec.destructive, false);
      assert.equal(spec.recoverability, 'recoverable');
      assert.ok(spec.knownAttack, 'an unsafe strategy must cite the attack that defeats it');
    }
  });
});

describe('text rewriting', () => {
  it('applies several spans without shifting later ones', () => {
    const text = 'Call 555-0100 or email dana@example.com today.';
    const result = applyTextOperations(text, [
      op({ id: 'a', location: { kind: 'text', node: 'p0', start: 5, end: 13 }, replacement: '[PHONE]' }),
      op({ id: 'b', location: { kind: 'text', node: 'p0', start: 23, end: 39 }, replacement: '[EMAIL]' }),
    ]);
    assert.equal(result.text, 'Call [PHONE] or email [EMAIL] today.');
  });

  it('applies operations correctly regardless of the order given', () => {
    const text = 'aaaa bbbb cccc';
    const forward = applyTextOperations(text, [
      op({ id: 'a', location: { kind: 'text', node: 'p0', start: 0, end: 4 }, replacement: 'X' }),
      op({ id: 'b', location: { kind: 'text', node: 'p0', start: 10, end: 14 }, replacement: 'Y' }),
    ]);
    const reverse = applyTextOperations(text, [
      op({ id: 'b', location: { kind: 'text', node: 'p0', start: 10, end: 14 }, replacement: 'Y' }),
      op({ id: 'a', location: { kind: 'text', node: 'p0', start: 0, end: 4 }, replacement: 'X' }),
    ]);
    assert.equal(forward.text, 'X bbbb Y');
    assert.equal(forward.text, reverse.text);
  });

  it('removes rather than replaces when asked to', () => {
    const result = applyTextOperations('keep REMOVE keep', [
      op({ location: { kind: 'text', node: 'p0', start: 5, end: 12 }, strategy: 'remove' }),
    ]);
    assert.equal(result.text, 'keep keep');
  });

  it('maps offsets across the edits', () => {
    const result = applyTextOperations('0123456789', [
      op({ location: { kind: 'text', node: 'p0', start: 2, end: 5 }, replacement: 'XX' }),
    ]);
    assert.equal(result.text, '01XX56789');
    assert.equal(result.mapOffset(0), 0, 'before the edit');
    assert.equal(result.mapOffset(3), 2, 'inside the edit collapses to its start');
    assert.equal(result.mapOffset(5), 4, 'after the edit shifts by the length delta');
  });

  it('rejects overlapping operations instead of silently merging them', () => {
    assert.throws(
      () =>
        applyTextOperations('abcdefghij', [
          op({ id: 'a', location: { kind: 'text', node: 'p0', start: 0, end: 5 } }),
          op({ id: 'b', location: { kind: 'text', node: 'p0', start: 3, end: 8 } }),
        ]),
      /overlapping/,
    );
  });
});

describe('pseudonymisation', () => {
  it('gives the same entity the same token everywhere', () => {
    const generator = new PseudonymGenerator({ key: KEY });
    const a = generator.forValue('person.name', 'Dana Reyes');
    const b = generator.forValue('person.name', 'dana reyes');
    assert.equal(a, b, 'case must not create a second identity');
    assert.match(a, /^PERSON_[A-Z2-7]{6}$/);
  });

  it('unifies spellings through the normalised form', () => {
    const generator = new PseudonymGenerator({ key: KEY });
    const a = generator.forValue('contact.phone', '+1 (555) 010-9999', '+15550109999');
    const b = generator.forValue('contact.phone', '555-010-9999', '+15550109999');
    assert.equal(a, b);
  });

  it('gives different keys different tokens, so corpora cannot be joined', () => {
    const one = new PseudonymGenerator({ key: KEY });
    const two = new PseudonymGenerator({ key: utf8Encode('a-different-key-of-sufficient-len') });
    assert.notEqual(one.forValue('person.name', 'Dana Reyes'), two.forValue('person.name', 'Dana Reyes'));
  });

  it('refuses a key short enough to brute force', () => {
    assert.throws(() => new PseudonymGenerator({ key: utf8Encode('short') }), /at least 16 bytes/);
  });

  it('keeps a re-identification table for the key holder', () => {
    const generator = new PseudonymGenerator({ key: KEY });
    const token = generator.forValue('person.name', 'Dana Reyes');
    assert.equal(generator.reidentificationTable().get(token), 'dana reyes');
  });

  it('masks while preserving the recognisable shape', () => {
    assert.equal(maskValue('4111 1111 1111 1234', { keep: 4 }), '**** **** **** 1234');
    assert.equal(maskValue('dana@example.com', { keep: 4, from: 'start' }), 'dana@*******.***');
  });
});

describe('plan validation', () => {
  const model = textAdapter.parse('The subject is dana.reyes@example.com.');

  it('rejects a plan built against different bytes', () => {
    const other = textAdapter.parse('A different document entirely.');
    const detection = detect(model, standardDetectors());
    const plan = planRedactions(model, classify(model, detection, policy), policy);
    assert.throws(() => validatePlan(other, plan), /different source bytes/);
  });

  it('rejects an operation targeting a node that does not exist', () => {
    const detection = detect(model, standardDetectors());
    const plan = planRedactions(model, classify(model, detection, policy), policy);
    const broken = {
      ...plan,
      operations: [op({ location: { kind: 'text', node: 'ghost', start: 0, end: 1 } })],
    };
    assert.throws(() => validatePlan(model, broken), /not in the document/);
  });

  it('rejects a span that runs past the end of its node', () => {
    const detection = detect(model, standardDetectors());
    const plan = planRedactions(model, classify(model, detection, policy), policy);
    const broken = {
      ...plan,
      operations: [op({ location: { kind: 'text', node: 'p0', start: 0, end: 99999 } })],
    };
    assert.throws(() => validatePlan(model, broken), /outside the node/);
  });

  it('rejects a blackout aimed at a text span', () => {
    const detection = detect(model, standardDetectors());
    const plan = planRedactions(model, classify(model, detection, policy), policy);
    const broken = {
      ...plan,
      operations: [
        op({ location: { kind: 'text', node: 'p0', start: 0, end: 3 }, strategy: 'blackout' }),
      ],
    };
    assert.throws(() => validatePlan(model, broken), /cannot act on/);
  });
});

describe('overlapping operations', () => {
  it('never emits a plan whose operations overlap', () => {
    // Regression: two name rules matched nested spans of "Prepared by Colonel
    // Jane Whitfield" and the plan handed both to the adapter, which correctly
    // refused. Detection now collapses containment and the plan fuses whatever
    // partial overlaps survive, so this reaches the adapter clean.
    const source =
      'Prepared by Colonel Jane Whitfield.\n\nReachable at j.whitfield@example.mil, +1 202 555 0143.';
    const model = textAdapter.parse(source);
    const detection = detect(model, standardDetectors());
    const plan = planRedactions(model, classify(model, detection, policy), policy);

    const byNode = new Map<string, Array<{ start: number; end: number }>>();
    for (const operation of plan.operations) {
      if (operation.location.kind !== 'text') continue;
      const bucket = byNode.get(operation.location.node) ?? [];
      bucket.push({ start: operation.location.start, end: operation.location.end });
      byNode.set(operation.location.node, bucket);
    }
    for (const [node, spans] of byNode) {
      spans.sort((a, b) => a.start - b.start);
      for (let i = 1; i < spans.length; i++) {
        assert.ok(
          spans[i]!.start >= spans[i - 1]!.end,
          `operations on ${node} overlap: [${spans[i - 1]!.start},${spans[i - 1]!.end}) and [${spans[i]!.start},${spans[i]!.end})`,
        );
      }
    }
  });

  it('redacts the document that triggered the overlap, end to end', () => {
    const source =
      'Prepared by Colonel Jane Whitfield.\n\nReachable at j.whitfield@example.mil, +1 202 555 0143.';
    const result = redactDocument(source, { adapter: textAdapter, policy });
    assert.equal(result.verification.passed, true);
    assert.ok(!result.output.text.includes('Whitfield'));
    assert.ok(!result.output.text.includes('j.whitfield@example.mil'));
  });

  /**
   * Two findings that partially overlap, built by hand.
   *
   * Detection collapses containment, so a document that reaches the merge path
   * is genuinely hard to come by -- which is exactly why the path needs a test
   * that does not depend on finding one. These are constructed rather than
   * detected, and the plan's fusing logic is what is under test.
   */
  function overlapping(source: string, spans: ReadonlyArray<readonly [number, number]>) {
    const model = textAdapter.parse(source);
    const findings = spans.map(([start, end], i) => ({
      id: `f${i}`,
      ruleId: 'test:span',
      type: 'person.name' as const,
      location: { kind: 'text' as const, node: 'p0', start, end },
      value: source.slice(start, end),
      confidence: 0.9,
      evidence: [{ signal: 'test', note: 'constructed for this test', weight: 0.9 }],
    }));
    const detection = {
      all: findings,
      findings,
      detectors: [{ id: 'test:span', version: '1.0.0' }],
      countsByType: { 'person.name': findings.length },
    };
    return { model, classification: classify(model, detection, policy) };
  }

  it('keeps the cited authority in the marker when two spans fuse', () => {
    // The marker a release prints -- `[REDACTED (b)(6)]` -- is what a requester
    // reads; the manifest travels separately and often not at all. Losing the
    // citation at exactly the moment two redactions touch would leave one span
    // on the page silently weaker than its neighbours.
    const source = 'Prepared by Colonel Jane Whitfield.';
    const { model, classification } = overlapping(source, [[12, 25], [20, 33]]);
    const plan = planRedactions(model, classification, policy, {
      replacementText: () => '[REDACTED (b)(6)]',
    });

    const fused = plan.operations.filter((o) => o.findingIds.length > 1);
    assert.equal(fused.length, 1, 'the two spans should have fused into one operation');
    assert.equal(fused[0]!.replacement, '[REDACTED (b)(6)]');
  });

  it('falls back to the bare marker when fused spans cite different authorities', () => {
    // A span covering two findings withheld under different exemptions cannot
    // honestly cite either one of them, so it cites neither and the manifest
    // carries both.
    const source = 'Prepared by Colonel Jane Whitfield.';
    const { model, classification } = overlapping(source, [[12, 25], [20, 33]]);
    let n = 0;
    const plan = planRedactions(model, classification, policy, {
      replacementText: () => `[REDACTED (b)(${++n})]`,
    });

    const fused = plan.operations.filter((o) => o.findingIds.length > 1);
    assert.equal(fused.length, 1);
    assert.equal(fused[0]!.replacement, '[REDACTED]');
    assert.equal(fused[0]!.findingIds.length, 2, 'both findings are still recorded against it');
  });

  it('fuses partially overlapping operations into one covering replacement', () => {
    const model = textAdapter.parse('alpha bravo charlie');
    const fused = applyTextOperations('alpha bravo charlie', [
      op({ id: 'a', location: { kind: 'text', node: 'p0', start: 0, end: 11 }, replacement: '[X]' }),
    ]);
    assert.equal(fused.text, '[X] charlie');
    void model;
  });
});

describe('raster redaction', () => {
  it('writes opaque pixels even when the fill names a transparent alpha', () => {
    const pixels = new Uint8ClampedArray(4 * 4 * 4).fill(180);
    blackoutRegion(pixels, 4, 4, { x: 0, y: 0, width: 4, height: 4 }, [0, 0, 0, 0]);
    for (let i = 0; i < pixels.length; i += 4) {
      assert.equal(pixels[i + 3], 255, 'a transparent fill must not punch a hole');
      assert.equal(pixels[i], 0);
    }
  });

  it('destroys the pixels under a region rather than compositing over them', () => {
    const pixels = new Uint8ClampedArray(4 * 4 * 4).fill(200);
    blackoutRegion(pixels, 4, 4, { x: 1, y: 1, width: 2, height: 2 });

    // Inside the region: every channel overwritten.
    const inside = (1 * 4 + 1) * 4;
    assert.deepEqual([...pixels.slice(inside, inside + 4)], [0, 0, 0, 255]);
    // Outside: untouched.
    assert.equal(pixels[0], 200);
  });

  it('clamps a region that runs off the edge', () => {
    const pixels = new Uint8ClampedArray(2 * 2 * 4).fill(255);
    assert.doesNotThrow(() => blackoutRegion(pixels, 2, 2, { x: -5, y: -5, width: 100, height: 100 }));
    assert.ok([...pixels].every((v) => v === 0 || v === 255));
  });
});

describe('verification', () => {
  /**
   * An adapter that applies body redactions but ignores metadata operations.
   * This is exactly how real redaction fails, and the point of the test is that
   * the pipeline catches it rather than shipping the result.
   */
  const leakyAdapter = {
    ...textAdapter,
    id: 'leaky',
    apply(model: DocumentModel, operations: readonly RedactionOperation[]): TextDocument {
      const bodyOnly = operations.filter((o) => !o.location.node.startsWith('meta:'));
      return textAdapter.apply(model, bodyOnly);
    },
  };

  const source: TextDocument = {
    text: 'The reviewer may be reached at dana.reyes@example.com.',
    metadata: { Author: 'dana.reyes@example.com' },
  };

  it('catches content that survived in metadata', () => {
    assert.throws(
      () =>
        redactDocument(source, {
          adapter: leakyAdapter,
          policy,
          manifestSalt: SALT,
        }),
      (error: unknown) => {
        assert.ok(error instanceof VerificationFailedError);
        assert.ok(error.leaks.length > 0);
        assert.ok(
          error.leaks.some((l) => l.channel === 'metadata'),
          'the leak must be attributed to the metadata channel',
        );
        return true;
      },
    );
  });

  it('never reproduces the leaked value in the report', () => {
    try {
      redactDocument(source, { adapter: leakyAdapter, policy });
      assert.fail('expected a verification failure');
    } catch (error) {
      assert.ok(error instanceof VerificationFailedError);
      for (const leak of error.leaks) {
        assert.ok(!leak.preview.includes('dana.reyes@example.com'), 'previews must not disclose');
        assert.match(leak.preview, /\*/);
      }
    }
  });

  it('does not put six digits of an SSN into a leak preview', () => {
    const ssnSource: TextDocument = {
      text: 'SSN: 123-45-6789 is the subject.',
      metadata: { Note: '123-45-6789' },
    };
    try {
      redactDocument(ssnSource, { adapter: leakyAdapter, policy });
      assert.fail('expected a verification failure');
    } catch (error) {
      assert.ok(error instanceof VerificationFailedError);
      for (const leak of error.leaks) {
        const digits = leak.preview.replace(/\D/g, '');
        assert.ok(digits.length <= 2, `preview leaked ${digits.length} digits: ${leak.preview}`);
      }
    }
  });

  it('passes when the adapter does its job', () => {
    const result = redactDocument(source, { adapter: textAdapter, policy, manifestSalt: SALT });
    assert.equal(result.verification.passed, true);
    assert.ok(!result.output.text.includes('dana.reyes@example.com'));
    assert.ok(!JSON.stringify(result.output.metadata ?? {}).includes('dana.reyes@example.com'));
  });

  it('reports a recoverable strategy as unverifiable rather than passing it', () => {
    const model = textAdapter.parse('body');
    const plan = {
      id: 'p',
      documentId: model.id,
      sourceDigest: model.sourceDigest,
      policyId: 'x',
      policyVersion: '1',
      engine: { name: 'test', version: '0' },
      containsRecoverableStrategies: true,
      retainedValues: {},
      operations: [
        op({
          location: { kind: 'region', node: 'p0', rect: { x: 0, y: 0, width: 1, height: 1 } },
          strategy: 'blur',
          originalValue: 'body',
        }),
      ],
    };
    const report = verify(plan, model);
    assert.equal(report.unverifiable.length, 1);
    assert.match(report.unverifiable[0]!.reason, /recoverable encoding/);
  });

  it('catches a value that survived with different spacing', () => {
    const model = textAdapter.parse('reference 555 01 9999 retained');
    const plan = {
      id: 'p',
      documentId: model.id,
      sourceDigest: model.sourceDigest,
      policyId: 'x',
      policyVersion: '1',
      engine: { name: 'test', version: '0' },
      containsRecoverableStrategies: false,
    retainedValues: {},
      operations: [
        op({
          location: { kind: 'text', node: 'p0', start: 10, end: 21 },
          originalValue: '555-01-9999',
        }),
      ],
    };
    const report = verify(plan, model);
    assert.equal(report.passed, false, 'normalisation must see through the separator change');
  });
});

describe('keeping one occurrence of a repeated value', () => {
  /**
   * The reviewer's own decision must not read as a leak.
   *
   * A name appears twice; the reviewer removes one and keeps the other. The
   * read-back searches the output for what the plan removed, finds the kept
   * copy, and used to blame it on the operation that removed the other one --
   * refusing to release a document that was exactly what was asked for.
   */
  const source = 'Prepared by Marcus Vance.\n\nCountersigned by Marcus Vance, auditor.';

  const planFor = (exclude: readonly string[]) => {
    const model = textAdapter.parse(source);
    const detection = detect(model, standardDetectors());
    const classification = classify(model, detection, policy);
    const names = detection.findings.filter((f) => f.value === 'Marcus Vance');
    return {
      model,
      names,
      plan: planRedactions(model, classification, policy, { excludeFindings: exclude }),
    };
  };

  it('records what was kept, and how many times', () => {
    const { names, plan } = planFor([]);
    assert.ok(names.length >= 2, 'the fixture needs the same name twice');
    assert.deepEqual(plan.retainedValues, {});

    const kept = planFor([names[0]!.id]);
    assert.equal(kept.plan.retainedValues['marcus vance'], 1);
  });

  it('passes verification when the surviving copy is the one that was kept', () => {
    const { names } = planFor([]);
    const result = redactDocument(source, {
      adapter: textAdapter,
      policy,
      plan: { excludeFindings: [names[0]!.id] },
    });
    assert.equal(result.verification.passed, true, 'keeping one copy must not read as a leak');
    assert.equal(result.verification.leaks.length, 0);
    // The kept copy is still there, which is the point of keeping it.
    assert.match(result.output.text, /Marcus Vance/);
  });

  it('still catches a removal that silently did nothing', () => {
    // An adapter that drops body edits: one copy is expected to survive, two
    // are not, and the count is what makes the difference visible.
    const lazy = {
      ...textAdapter,
      id: 'lazy',
      apply: (model: DocumentModel) => textAdapter.apply(model, []),
    };
    const { names } = planFor([]);
    assert.throws(
      () =>
        redactDocument(source, {
          adapter: lazy as never,
          policy,
          plan: { excludeFindings: [names[0]!.id] },
        }),
      VerificationFailedError,
    );
  });

  it('keeps every copy only when every copy was kept', () => {
    const { names } = planFor([]);
    const result = redactDocument(source, {
      adapter: textAdapter,
      policy,
      plan: { excludeFindings: names.map((f) => f.id) },
    });
    assert.equal(result.verification.passed, true);
    assert.equal((result.output.text.match(/Marcus Vance/g) ?? []).length, names.length);
  });
});
