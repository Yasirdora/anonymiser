import assert from 'node:assert/strict';
import { describe, it } from 'node:test';

import { textAdapter, type TextDocument } from '../src/adapters/text/index.js';
import { compilePolicy } from '../src/classify/lattice.js';
import { privacyPolicy } from '../src/classify/packs/index.js';
import { utf8Encode } from '../src/internal/bytes.js';
import { hmacSha256 } from '../src/internal/hash.js';
import { redactDocument } from '../src/pipeline.js';
import { confirmRemovedValue, verifyManifest } from '../src/provenance/manifest.js';
import { PseudonymGenerator } from '../src/redact/pseudonym.js';

const policy = compilePolicy(privacyPolicy);
const SALT = utf8Encode('a-manifest-salt-of-sufficient-length');
const KEY = utf8Encode('a-signing-key-of-sufficient-length');

const CASE_FILE: TextDocument = {
  text: [
    'Case summary prepared for internal review.',
    '',
    'The complainant, reachable at dana.reyes@example.com, provided card 4111 1111 1111 1111 as proof of the disputed charge.',
    '',
    'A second complainant used the same card and can be reached at dana.reyes@example.com.',
  ].join('\n'),
  metadata: { Author: 'M. Okonkwo', Producer: 'CaseTrack 7.2' },
};

function run() {
  return redactDocument(CASE_FILE, {
    adapter: textAdapter,
    policy,
    manifestSalt: SALT,
  });
}

describe('the provenance manifest', () => {
  it('records one entry per operation, chained', () => {
    const { manifest, plan } = run();
    assert.ok(manifest);
    assert.equal(manifest.entries.length, plan.operations.length);
    assert.equal(manifest.entries[0]?.previous, '0'.repeat(64));
    for (let i = 1; i < manifest.entries.length; i++) {
      assert.equal(manifest.entries[i]!.previous, manifest.entries[i - 1]!.hash);
    }
  });

  it('verifies an untouched manifest', () => {
    const { manifest } = run();
    assert.ok(manifest);
    const result = verifyManifest(manifest);
    assert.equal(result.valid, true);
    assert.equal(result.brokenAt, -1);
  });

  it('detects an altered entry and says where the chain broke', () => {
    const { manifest } = run();
    assert.ok(manifest);
    assert.ok(manifest.entries.length >= 2, 'need at least two entries for this test');

    const tampered = {
      ...manifest,
      entries: manifest.entries.map((e, i) =>
        i === 1 ? { ...e, reasonCode: 'foia.b1' } : e,
      ),
    };
    const result = verifyManifest(tampered);
    assert.equal(result.valid, false);
    assert.equal(result.brokenAt, 1);
    assert.match(result.problems[0]!, /altered/);
  });

  it('detects a removed entry', () => {
    const { manifest } = run();
    assert.ok(manifest);
    assert.ok(manifest.entries.length >= 2);
    const tampered = { ...manifest, entries: manifest.entries.slice(1) };
    assert.equal(verifyManifest(tampered).valid, false);
  });

  it('detects an altered summary even when every entry is intact', () => {
    const { manifest } = run();
    assert.ok(manifest);
    const tampered = {
      ...manifest,
      summary: { ...manifest.summary, verified: !manifest.summary.verified },
    };
    const result = verifyManifest(tampered);
    assert.equal(result.valid, false);
    assert.match(result.problems[0]!, /summary/);
  });

  it('never contains the values it recorded', () => {
    const { manifest } = run();
    assert.ok(manifest);
    const serialized = JSON.stringify(manifest);
    assert.ok(!serialized.includes('dana.reyes@example.com'));
    assert.ok(!serialized.includes('4111111111111111'));
    assert.ok(!serialized.includes('4111 1111 1111 1111'));
  });

  it('lets a key holder confirm what was removed', () => {
    const { manifest, plan } = run();
    assert.ok(manifest);
    const emailOp = plan.operations.find((o) => o.originalValue?.includes('@'));
    assert.ok(emailOp, 'expected an email operation');
    const entry = manifest.entries.find((e) => e.operationId === emailOp.id);
    assert.ok(entry);

    assert.equal(confirmRemovedValue(entry, emailOp.originalValue!, SALT), true);
    assert.equal(confirmRemovedValue(entry, 'someone.else@example.com', SALT), false);
    assert.equal(
      confirmRemovedValue(entry, emailOp.originalValue!, utf8Encode('a-different-salt-value-here')),
      false,
      'the wrong salt must not confirm',
    );
  });

  it('is reproducible: the same input yields the same root hash', () => {
    const a = run();
    const b = run();
    assert.equal(a.manifest?.root, b.manifest?.root);
    assert.equal(a.plan.id, b.plan.id);
  });

  it('changes the root when the input changes', () => {
    const a = run();
    const b = redactDocument(
      { ...CASE_FILE, text: `${CASE_FILE.text}\n\nAn extra paragraph.` },
      { adapter: textAdapter, policy, manifestSalt: SALT },
    );
    assert.notEqual(a.manifest?.root, b.manifest?.root);
  });

  it('binds to the policy, so a policy edit is detectable', () => {
    const a = run();
    const edited = compilePolicy({ ...privacyPolicy, version: '1.0.1' });
    const b = redactDocument(CASE_FILE, { adapter: textAdapter, policy: edited, manifestSalt: SALT });
    assert.notEqual(a.manifest?.summary.policyDigest, b.manifest?.summary.policyDigest);
  });

  it('carries a detached signature when a signer is supplied', () => {
    const result = redactDocument(CASE_FILE, {
      adapter: textAdapter,
      policy,
      manifestSalt: SALT,
      sign: (root) => hmacSha256(KEY, root),
    });
    assert.ok(result.manifest?.signature);
    assert.match(result.manifest.signature, /^[0-9a-f]{64}$/);
  });

  it('records every removal with a citable authority', () => {
    const { manifest } = run();
    assert.ok(manifest);
    assert.ok(manifest.entries.length > 0);
    for (const entry of manifest.entries) {
      assert.ok(entry.authority.length > 0, 'no anonymous redactions');
      assert.ok(entry.reasonCode.length > 0);
    }
  });

  it('reports the run as defensible when nothing was left unverified', () => {
    const result = run();
    assert.equal(result.defensible, true);
    assert.equal(result.manifest?.summary.usedRecoverableStrategies, false);
  });

  it('omits a timestamp by default so runs stay byte-reproducible', () => {
    const { manifest } = run();
    assert.equal(manifest?.summary.issuedAt, undefined);
  });

  it('carries the timestamp and operator when supplied', () => {
    const result = redactDocument(CASE_FILE, {
      adapter: textAdapter,
      policy,
      manifestSalt: SALT,
      issuedAt: '2026-09-02T10:00:00Z',
      issuedBy: 'records-office',
    });
    assert.equal(result.manifest?.summary.issuedAt, '2026-09-02T10:00:00Z');
    assert.equal(result.manifest?.summary.issuedBy, 'records-office');
    assert.equal(verifyManifest(result.manifest!).valid, true);
  });

  it('refuses a salt short enough to reverse a nine-digit digest', () => {
    assert.throws(
      () =>
        redactDocument(CASE_FILE, {
          adapter: textAdapter,
          policy,
          manifestSalt: utf8Encode('short'),
        }),
      /at least 16 bytes/,
    );
  });
});

describe('end-to-end pipeline', () => {
  it('removes every detected value from every channel', () => {
    const { output } = run();
    const everything = JSON.stringify(output);
    assert.ok(!everything.includes('dana.reyes@example.com'));
    assert.ok(!everything.includes('4111 1111 1111 1111'));
  });

  it('derives a banner reflecting what the content actually holds', () => {
    const { classification } = run();
    // Cardholder data and contact details put this above OPEN.
    assert.notEqual(classification.banner.level, 'open');
    assert.ok(classification.bannerMarking.length > 0);
  });

  it('gives one entity the same pseudonym in both paragraphs', () => {
    const pseudonyms = new PseudonymGenerator({ key: KEY });
    const result = redactDocument(CASE_FILE, {
      adapter: textAdapter,
      policy,
      plan: { pseudonyms, strategyByType: { 'contact.email': 'pseudonymize' } },
    });

    const tokens = [...result.output.text.matchAll(/EMAIL_[A-Z2-7]{6}/g)].map((m) => m[0]);
    assert.ok(tokens.length >= 2, 'the address appears in two paragraphs');
    assert.equal(new Set(tokens).size, 1, 'one entity must read as one entity');
  });

  it('leaves the document readable', () => {
    const { output } = run();
    assert.ok(output.text.includes('Case summary prepared for internal review.'));
    assert.ok(output.text.includes('[REDACTED]'));
  });

  it('analyses without altering anything', async () => {
    const { analyze } = await import('../src/pipeline.js');
    const before = JSON.stringify(CASE_FILE);
    const result = analyze(CASE_FILE, { adapter: textAdapter, policy });
    assert.equal(JSON.stringify(CASE_FILE), before, 'analysis must not mutate its input');
    assert.ok(result.detection.findings.length > 0);
  });
});
