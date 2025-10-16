import assert from 'node:assert/strict';
import { describe, it } from 'node:test';

import { textAdapter } from '../src/adapters/text/index.js';
import { detect, resolveOverlaps } from '../src/detect/engine.js';
import { classify } from '../src/classify/engine.js';
import { compilePolicy } from '../src/classify/lattice.js';
import { privacyPolicy } from '../src/classify/packs/index.js';
import { redactDocument } from '../src/pipeline.js';
import { utf8Encode } from '../src/internal/bytes.js';
import { patternDetector } from '../src/detect/pattern.js';
import { allPacks, financialPack, identityPack, personalDataPacks, secretsPack, transcribeSpokenNumber } from '../src/detect/patterns/index.js';
import { manualDetector, standardDetectors, termDetector } from '../src/detect/index.js';
import { structuralDetector } from '../src/detect/structural.js';
import type { Finding } from '../src/detect/types.js';
import { abaRouting, iban, luhn, mrzCheckDigit, nhsNumber, shannonEntropy, ukNino, usSsn } from '../src/detect/validators.js';
import type { DocumentModel } from '../src/model/document.js';

function scan(text: string, packs = personalDataPacks): Finding[] {
  const model = textAdapter.parse(text);
  return [...detect(model, [patternDetector(packs)]).findings];
}

function typesIn(text: string, packs = personalDataPacks): string[] {
  return [...new Set(scan(text, packs).map((f) => f.type))].sort();
}

/** The full standard set, for detectors that consume earlier stages' findings. */
function scanStandard(text: string): Finding[] {
  return [...detect(textAdapter.parse(text), standardDetectors()).findings];
}

describe('checksum validators', () => {
  it('accepts and rejects Luhn candidates', () => {
    assert.equal(luhn('4111111111111111'), true);
    assert.equal(luhn('4111 1111 1111 1111'), true);
    assert.equal(luhn('4111111111111112'), false);
  });

  it('validates IBANs including the country length table', () => {
    assert.equal(iban('GB82 WEST 1234 5698 7654 32'), true);
    assert.equal(iban('DE89 3704 0044 0532 0130 00'), true);
    assert.equal(iban('GB82WEST12345698765433'), false, 'a wrong check digit must fail');
    assert.equal(iban('GB82WEST123456987654'), false, 'a wrong length for GB must fail');
  });

  it('rejects SSN blocks that are never issued', () => {
    assert.equal(usSsn('123-45-6789'), true);
    assert.equal(usSsn('000-45-6789'), false);
    assert.equal(usSsn('666-45-6789'), false);
    assert.equal(usSsn('900-45-6789'), false);
    assert.equal(usSsn('123-00-6789'), false);
    assert.equal(usSsn('123-45-0000'), false);
  });

  it('validates the ABA weighted checksum', () => {
    assert.equal(abaRouting('021000021'), true);
    assert.equal(abaRouting('021000022'), false);
  });

  it('validates NHS mod-11 numbers', () => {
    assert.equal(nhsNumber('943 476 5919'), true);
    assert.equal(nhsNumber('943 476 5918'), false);
  });

  it('applies the NINO prefix rules', () => {
    assert.equal(ukNino('AB123456C'), true);
    assert.equal(ukNino('DA123456C'), false, 'D is not a valid first letter');
    assert.equal(ukNino('AO123456C'), false, 'O is not a valid second letter');
    assert.equal(ukNino('GB123456C'), false, 'GB is a reserved prefix');
  });

  it('computes ICAO 9303 check digits', () => {
    // Worked example from ICAO Doc 9303 Part 3.
    assert.equal(mrzCheckDigit('D23145890', '7'), true);
    assert.equal(mrzCheckDigit('D23145890', '6'), false);
  });

  it('separates random tokens from prose by entropy', () => {
    assert.ok(shannonEntropy('xK9$mPq2Lw7nZr4T') > 3.5);
    assert.ok(shannonEntropy('aaaaaaaaaaaaaaaa') < 0.5);
  });
});

describe('pattern detection', () => {
  it('finds an email address and normalises its case', () => {
    const findings = scan('Write to Dana.Reyes@Example.COM about the filing.');
    const email = findings.find((f) => f.type === 'contact.email');
    assert.ok(email, 'expected an email finding');
    assert.equal(email.value, 'Dana.Reyes@Example.COM');
    assert.equal(email.normalized, 'dana.reyes@example.com');
  });

  it('accepts a card that passes Luhn and matches an issuer range', () => {
    const findings = scan('Card on file: 4111 1111 1111 1111', [financialPack]);
    const card = findings.find((f) => f.type === 'financial.card');
    assert.ok(card, 'expected a card finding');
    assert.ok(card.confidence > 0.9, 'a checksum-verified card should be high confidence');
    assert.equal(card.normalized, '4111111111111111');
  });

  it('rejects a sixteen-digit number that fails Luhn', () => {
    const findings = scan('Order reference 1234567890123456', [financialPack]);
    assert.equal(findings.filter((f) => f.type === 'financial.card').length, 0);
  });

  it('requires a label before treating nine bare digits as an SSN', () => {
    assert.equal(scan('Part number 123456789', [identityPack]).length, 0);
    const labelled = scan('SSN: 123456789', [identityPack]);
    assert.ok(labelled.some((f) => f.type === 'gov.ssn'), 'a labelled SSN must be found');
  });

  it('records the rule and the structural check behind a confidence score', () => {
    // Unlabelled, so the shape-plus-checksum rule is the one that fires and its
    // structural check is what the evidence has to cite.
    const [finding] = scan('Reference 123-45-6789 filed', [identityPack]);
    assert.ok(finding);
    const signals = finding.evidence.map((e) => e.signal);
    assert.ok(signals.some((s) => s.startsWith('pattern:')), 'the matching rule must be cited');
    assert.ok(signals.includes('structure:ssn-blocks'), 'the structural check must be cited');
  });

  it('records the supporting label when a rule needed one', () => {
    // A nine-digit routing number is noise without a label; the evidence must
    // name the label that made it a finding.
    const [finding] = scan('ABA routing: 121000358', [financialPack]);
    assert.ok(finding);
    const support = finding.evidence.find((e) => e.signal === 'context:support');
    assert.ok(support, 'the corroborating label must be recorded');
    assert.match(support.note, /routing/);
  });

  it('lets an explicit label outrank a failed structural check', () => {
    // Area 000 is never issued, so the shape rule rejects it. The document says
    // it is an SSN, and in a redaction tool the label has to win: skipping the
    // field literally labelled SSN is the worst outcome available.
    const findings = scan('Tax ID / SSN: 000-12-3456', [identityPack]);
    const ssn = findings.find((f) => f.type === 'gov.ssn');
    assert.ok(ssn, 'a labelled SSN must be found even when its blocks are unissuable');
    assert.ok(ssn.confidence >= 0.9, 'and it must be confident enough to redact automatically');
  });

  it('does not read an IP address or an SSN as a telephone number', () => {
    for (const [text, wrong] of [
      ['originated from 192.0.2.45 at 03:14', 'net.ipv4'],
      ['Tax ID / SSN: 000-12-3456', 'gov.ssn'],
    ] as const) {
      const findings = scan(text, allPacks);
      assert.ok(
        !findings.some((f) => f.type === 'contact.phone'),
        `${text} must not produce a phone finding`,
      );
      assert.ok(findings.some((f) => f.type === wrong), `it must be typed as ${wrong}`);
    }
  });

  it('finds vendor-prefixed credentials without any context', () => {
    const types = typesIn('export AWS_KEY=AKIAIOSFODNN7EXAMPLE', [secretsPack]);
    assert.ok(types.includes('secret.api-key'));
  });

  it('treats a placeholder credential as a placeholder', () => {
    const findings = scan('password = "xxxxxxxxxxxx"', [secretsPack]);
    assert.equal(findings.filter((f) => f.type === 'secret.password').length, 0);
  });

  it('finds a JWT, whose payload is readable by anyone holding it', () => {
    const jwt =
      'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dBjftJeZ4CVPmB92K27uhbUJU1p1r_wW1gFWFOEjXk';
    assert.ok(typesIn(`Authorization: Bearer ${jwt}`, [secretsPack]).includes('secret.jwt'));
  });

  it('ignores documentation and loopback IP ranges', () => {
    const findings = scan('Connect to 127.0.0.1 or 192.0.2.15', allPacks);
    assert.equal(findings.filter((f) => f.type === 'net.ipv4').length, 0);
  });

  it('reports coordinate precision as evidence', () => {
    const findings = scan('Meeting at 51.501364, -0.141890', allPacks);
    const coords = findings.find((f) => f.type === 'geo.coordinates');
    assert.ok(coords, 'expected a coordinate finding');
    assert.ok(
      coords.evidence.some((e) => e.note.includes('m on the ground')),
      'the finding should say how precisely it locates someone',
    );
  });

  it('produces the same finding ids for the same input', () => {
    const first = scan('Contact: dana@example.com');
    const second = scan('Contact: dana@example.com');
    assert.deepEqual(first.map((f) => f.id), second.map((f) => f.id));
  });

  it('does not let a rule leak lastIndex between documents', () => {
    // A shared global RegExp would find the card in the first scan and, with
    // lastIndex left past it, miss the identical card in the second.
    const detector = patternDetector([financialPack]);
    const first = detect(textAdapter.parse('Card: 4111 1111 1111 1111'), [detector]);
    const second = detect(textAdapter.parse('Card: 4111 1111 1111 1111'), [detector]);
    assert.equal(first.findings.length, 1);
    assert.equal(second.findings.length, 1, 'the second scan must find the same card');
  });
});

describe('overlap resolution', () => {
  it('drops a weaker finding contained in a stronger one', () => {
    const base = { evidence: [], ruleId: 'test' } as const;
    const wide: Finding = {
      ...base,
      id: 'a',
      type: 'financial.card',
      value: '4111111111111111',
      confidence: 0.99,
      location: { kind: 'text', node: 'p0', start: 0, end: 16 },
    };
    const narrow: Finding = {
      ...base,
      id: 'b',
      type: 'secret.api-key',
      value: '11111111111',
      confidence: 0.2,
      location: { kind: 'text', node: 'p0', start: 4, end: 15 },
    };
    const resolved = resolveOverlaps([wide, narrow]);
    assert.deepEqual(resolved.map((f) => f.id), ['a']);
  });

  it('collapses containment even when the inner finding scored higher', () => {
    // "Prepared by Colonel Jane Whitfield" -- a role-label rule matches the
    // whole phrase, an honorific rule matches the name inside it at higher
    // confidence. Keeping both produces overlapping edits with no defined
    // result; keeping only the inner one leaves "Colonel" beside a redaction.
    const base = { evidence: [], ruleId: 'test' } as const;
    const outer: Finding = {
      ...base,
      id: 'outer',
      type: 'person.name',
      value: 'Colonel Jane Whitfield',
      confidence: 0.83,
      location: { kind: 'text', node: 'p0', start: 12, end: 34 },
    };
    const inner: Finding = {
      ...base,
      id: 'inner',
      type: 'person.name',
      value: 'Jane Whitfield',
      confidence: 0.95,
      location: { kind: 'text', node: 'p0', start: 20, end: 34 },
    };

    const resolved = resolveOverlaps([outer, inner]);
    assert.equal(resolved.length, 1, 'containment must always collapse to one finding');
    assert.equal(resolved[0]!.id, 'outer', 'the wider span survives, so nothing is left exposed');
    assert.equal(resolved[0]!.confidence, 0.95, 'the survivor inherits the higher confidence');
    assert.ok(
      resolved[0]!.evidence.some((e) => e.signal.startsWith('subsumed:')),
      'the evidence must record what it absorbed',
    );
  });

  it('keeps two findings that merely abut', () => {
    const make = (id: string, start: number, end: number): Finding => ({
      id,
      ruleId: 'test',
      type: 'contact.email',
      value: 'x',
      confidence: 0.8,
      evidence: [],
      location: { kind: 'text', node: 'p0', start, end },
    });
    const resolved = resolveOverlaps([make('a', 0, 10), make('b', 10, 20)]);
    assert.equal(resolved.length, 2);
  });
});

describe('structural detection', () => {
  it('finds the classic overlay-over-live-text failure', () => {
    const model: DocumentModel = {
      id: 'd',
      mediaType: 'application/pdf',
      adapterId: 'stub',
      origin: 'top-left',
      pages: [{ x: 0, y: 0, width: 612, height: 792 }],
      sourceDigest: 'x'.repeat(64),
      nodes: [
        {
          id: 't1',
          kind: 'text',
          page: 0,
          role: 'paragraph',
          text: 'The informant is Dana Reyes.',
          bbox: { x: 72, y: 100, width: 300, height: 12 },
        },
        {
          id: 'r1',
          kind: 'vector',
          page: 0,
          bbox: { x: 70, y: 98, width: 310, height: 16 },
          attrs: { filled: 'true', opacity: '1' },
        },
      ],
    };

    const result = detect(model, [structuralDetector()]);
    const cosmetic = result.findings.find((f) => f.type === 'risk.cosmetic-redaction');
    assert.ok(cosmetic, 'an opaque box over extractable text must be reported');
    assert.ok(cosmetic.evidence[0]?.note.includes('still extractable'));
  });

  it('reports identifying metadata and leaves innocuous fields alone', () => {
    const model = textAdapter.parse({
      text: 'Report body.',
      metadata: { Author: 'Dana Reyes', Title: 'Quarterly Report', Producer: 'Acme PDF 3.1' },
    });
    const result = detect(model, [structuralDetector()]);
    const keys = result.findings.map((f) => f.location.node);
    assert.ok(keys.includes('meta:Author'));
    assert.ok(keys.includes('meta:Producer'));
    assert.ok(!keys.includes('meta:Title'), 'a title is not an identifier');
  });

  it('does not repeat a claim a pattern detector already made precisely', () => {
    // A GPS metadata field is a location risk to the structural detector and a
    // coordinate to the geo rules. Emitting both counts one disclosure twice and
    // produces two redaction operations for the same value.
    const model: DocumentModel = {
      id: 'd',
      mediaType: 'image/jpeg',
      adapterId: 'stub',
      origin: 'top-left',
      pages: [],
      sourceDigest: 'x'.repeat(64),
      nodes: [
        { id: 'gps', kind: 'metadata', text: '51.508333, -0.125000', attrs: { key: 'GPSPosition' } },
        { id: 'author', kind: 'metadata', text: 'M. Okonkwo', attrs: { key: 'Author' } },
      ],
    };

    const findings = detect(model, standardDetectors()).findings;
    const onGps = findings.filter((f) => f.location.node === 'gps');
    assert.equal(onGps.length, 1, 'one value, one finding');
    assert.equal(onGps[0]!.location.kind, 'text', 'the precise span wins over the whole-node claim');

    // A different claim about the same node survives: the author field is both
    // a value and an attribution.
    assert.ok(findings.some((f) => f.location.node === 'author' && f.type === 'risk.metadata'));
  });

  it('reports annotations, which readers do not see and extractors do', () => {
    const model = textAdapter.parse({
      text: 'Public body.',
      annotations: [{ id: '1', text: 'do not release the name Dana Reyes', author: 'reviewer' }],
    });
    const result = detect(model, [structuralDetector()]);
    assert.ok(result.findings.some((f) => f.type === 'risk.hidden-content'));
  });
});

/**
 * A breach complaint of the kind this engine exists for.
 *
 * Every value here was missed or mistyped by an earlier build: the SSN was
 * dropped for failing its block check and then re-matched as a phone number, the
 * IP was read as a phone number too, the CVV and the labelled IBAN had no rules
 * at all, and the AWS secret key sat behind a label the credential rule did not
 * recognise. The rest were found but scored just under the auto-redact line and
 * silently left in the output.
 *
 * This is the regression guard for all of it.
 */
describe('a real breach complaint', () => {
  const COMPLAINT = [
    'Full Name: Marcus Vance (DOB: 22/11/1984)',
    'Tax ID / SSN: 000-12-3456',
    'Billing Address: 742 Evergreen Terrace, Springfield, OR 97477',
    'Primary Contact: marcus.vance@example.com | +1 (555) 019-2831',
    'Primary Account Number (PAN): 4111 1111 1111 1111 (Exp: 08/29, CVV: 123)',
    'Secondary Card (Mastercard): 5500 0000 0000 0004',
    'IBAN / Routing: US64SVBK12345678901234 | Routing: 121000358',
    'System Account ID: ACC-99482-B',
    'The unauthorized requests originated from IP address 192.0.2.45 (MAC: 00:1A:2B:3C:4D:5E).',
    'API Secret Key: sk_test_51MzX92e4EXAMPLE990021384729103847209',
    'AWS Access Key ID: AKIAIOSFODNN7EXAMPLE',
    'AWS Secret Key: wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY',
    'Host Database Node: db-primary-us-east-1a.internal:5432',
  ].join('\n');

  const EXPECTED: ReadonlyArray<readonly [string, string]> = [
    ['Marcus Vance', 'person.name'],
    ['22/11/1984', 'person.dob'],
    ['000-12-3456', 'gov.ssn'],
    ['742 Evergreen Terrace', 'contact.address'],
    ['97477', 'geo.postcode|contact.address'],
    ['marcus.vance@example.com', 'contact.email'],
    ['019-2831', 'contact.phone'],
    ['4111 1111 1111 1111', 'financial.card'],
    ['5500 0000 0000 0004', 'financial.card'],
    ['US64SVBK12345678901234', 'financial.iban'],
    ['121000358', 'financial.routing'],
    ['ACC-99482-B', 'financial.account'],
    ['192.0.2.45', 'net.ipv4'],
    ['00:1A:2B:3C:4D:5E', 'net.mac'],
    ['db-primary-us-east-1a.internal', 'net.hostname'],
    ['AKIAIOSFODNN7EXAMPLE', 'secret.api-key'],
    ['wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY', 'secret.password'],
  ];

  /**
   * Find the finding that covers an expected value.
   *
   * Only a finding whose own value contains the expected one counts. Matching
   * the other way round -- expected contains finding -- makes the three-digit
   * CVV a "match" for every longer number in the document, which is how an
   * earlier version of this test reported a passing engine as broken.
   */
  const coveringFinding = (findings: readonly Finding[], value: string): Finding | undefined =>
    findings.find((f) => f.value.trim() === value || f.value.includes(value));

  it('finds every sensitive value, and types each one correctly', () => {
    const findings = scan(COMPLAINT, allPacks);
    for (const [value, type] of EXPECTED) {
      const hit = coveringFinding(findings, value);
      assert.ok(hit, `missed: ${value}`);
      // A value may legitimately be covered by a composite finding -- a whole
      // address line subsumes its city and postcode -- so the expectation lists
      // every type that would be a correct outcome.
      assert.ok(type.split('|').includes(hit.type),
        `${value} was typed as ${hit.type}, expected one of ${type}`);
    }
  });

  it('finds the CVV and the card expiry, which complete a usable card record', () => {
    const findings = scan(COMPLAINT, allPacks);
    assert.ok(findings.some((f) => f.ruleId.endsWith('card.cvv')), 'the CVV must be found');
    assert.ok(findings.some((f) => f.ruleId.endsWith('card.expiry')), 'the expiry must be found');
  });

  it('scores everything high enough to be redacted without a human lowering a threshold', () => {
    const findings = scan(COMPLAINT, allPacks);
    for (const [value] of EXPECTED) {
      const hit = coveringFinding(findings, value);
      assert.ok(hit && hit.confidence >= 0.5, `${value} scored ${hit?.confidence} and would be left in`);
    }
  });

  it('leaves none of it in the redacted output', () => {
    const result = redactDocument(COMPLAINT, {
      adapter: textAdapter,
      policy: compilePolicy(privacyPolicy),
    });
    assert.equal(result.verification.passed, true);
    assert.equal(result.defensible, true);

    for (const secret of [
      'Marcus Vance', '22/11/1984', '000-12-3456', '742 Evergreen Terrace', '97477',
      'marcus.vance@example.com', '019-2831', '4111 1111', '5500 0000', 'US64SVBK',
      '121000358', 'ACC-99482-B', '192.0.2.45', '00:1A:2B', 'AKIAIOSFODNN7EXAMPLE',
      'wJalrXUtnFEMI', 'db-primary-us-east-1a',
    ]) {
      assert.ok(!result.output.text.includes(secret), `${secret} survived into the output`);
    }
  });
});

/**
 * Repeat occurrences.
 *
 * This detector exists because the verifier refused a document: "Marcus Vance"
 * was removed from behind its "Full Name:" label and left standing in the
 * signature block, where no rule could see it. Redacting one occurrence and
 * leaving another is not a redaction.
 */
describe('repeat occurrences', () => {
  const LETTER = [
    'Full Name: Marcus Vance (DOB: 22/11/1984)',
    '',
    'Primary Contact: marcus.vance@example.com',
    '',
    'I expect a full refund within 24 hours.',
    '',
    'Marcus Vance',
    '',
    'Lead Auditor, Operations Unit',
    '',
    'marcus.vance@example.com',
  ].join('\n');

  it('finds a name that reappears with no label to identify it', () => {
    const findings = scanStandard(LETTER);
    const names = findings.filter((f) => f.type === 'person.name' && f.value.includes('Marcus Vance'));
    assert.equal(names.length, 2, 'both the labelled and the unlabelled occurrence must be found');
    assert.ok(
      names.some((f) => f.ruleId === 'repeat:value'),
      'the second occurrence must be attributed to the repeat detector',
    );
  });

  it('explains why a repeat is a finding', () => {
    const findings = scanStandard(LETTER);
    const repeat = findings.find((f) => f.ruleId === 'repeat:value');
    assert.ok(repeat);
    assert.equal(repeat.evidence[0]?.signal, 'repeat:identified-elsewhere');
    assert.match(repeat.evidence[0]!.note, /elsewhere in this document/);
  });

  it('does not report a repeat on top of the finding that seeded it', () => {
    const findings = scanStandard(LETTER);
    const spans = findings
      .filter((f) => f.location.kind === 'text')
      .map((f) => ({ node: f.location.node, ...(f.location as { start: number; end: number }) }));
    for (const a of spans) {
      for (const b of spans) {
        if (a === b || a.node !== b.node) continue;
        assert.ok(a.start >= b.end || b.start >= a.end, 'repeats must not overlap their seeds');
      }
    }
  });

  it('does not match inside a longer word', () => {
    const findings = scanStandard('Full Name: Ann Vance\n\nShe moved to Vancouver last year.');
    assert.ok(
      !findings.some((f) => f.ruleId === 'repeat:value' && f.value.toLowerCase() === 'vance'),
      'Vancouver must not be reported as a repeat of Vance',
    );
  });

  it('chases a card number that reappears without separators', () => {
    const findings = scanStandard(
      'Card on file: 4111 1111 1111 1111\n\nThe PAN 4111111111111111 was reused at the till.',
    );
    const cards = findings.filter((f) => f.value.replace(/\D/g, '') === '4111111111111111');
    assert.ok(cards.length >= 2, 'both the spaced and unspaced PAN must be found');
    assert.ok(
      cards.some((f) => f.ruleId === 'repeat:value') || cards.length >= 2,
      'the unspaced PAN is the same card as the labelled one',
    );
  });

  it('leaves nothing behind in the full letter', () => {
    const result = redactDocument(LETTER, {
      adapter: textAdapter,
      policy: compilePolicy(privacyPolicy),
    });
    assert.equal(result.verification.passed, true);
    assert.ok(!result.output.text.includes('Marcus Vance'));
    assert.ok(!result.output.text.includes('marcus.vance@example.com'));
  });
});

/**
 * A forwarded clinical incident report.
 *
 * Everything here was missed or mistyped by an earlier build, and several of the
 * failures were the dangerous kind rather than the merely incomplete kind:
 *
 * - `Siobhán O'Connor` was redacted as `Siobhán O'`, leaving **Connor** standing
 *   in the document. A partial name redaction looks finished and is not.
 * - The NHS number failed its mod-11 check, was dropped, and was then re-matched
 *   as a telephone number.
 * - A card number, a CVV, and an SSN written out in words passed straight
 *   through, as did a card number inside magnetic-stripe track data.
 * - Two IP addresses were missed because a sentence-ending full stop defeated
 *   the tail guard on both address rules.
 * - `2026-09-02T13:45:11Z` matched as `2026-09-02`, leaving the time.
 */
describe('a forwarded clinical incident report', () => {
  const REPORT = [
    'From: Dr. François Dubois f.dubois@med-clinic.co.uk',
    'Date: 2026-09-02T13:45:11Z',
    '',
    "My patient, Chloe O'Connor (DOB: 12-MAR-2011, NHS Number: 485 777 3456), was billed twice.",
    '',
    'The card is a Visa: four five three two, nine one zero zero, eight seven six five,',
    'four three two one. Expiration is 11/2028. The CVV she provided was three-eight-nine.',
    '',
    "Contact the guarantor, Mrs. Siobhan O'Connor, at +44 (0) 20 7123 4567,",
    'or siobhan_oconnor88@gmail.com. Home address is 128 Piccadilly, London, W1J 7JZ.',
    "Chloe's ICD-10 diagnosis code (E10.9 - Type 1 diabetes mellitus) leaked.",
    '',
    'The attacker originated from 2001:0db8:85a3:0000:0000:8a2e:0370:7334.',
    '{"social_security_number":"Nine-Nine-Eight, Forty-Two, Zero-Zero-One-Nine",',
    ' "payment_track_data":"%B4532910087654321^OCONNOR/SIOBHAN^2811101000000000?",',
    ' "internal_notes":"Patient is HIV+ (B20)."}',
    '',
    'Base64: dXNlcjphZG1pbiBwYXNzd29yZDpTdXBlclNlY3JldFBhc3N3b3JkMTIz',
    'GitHub PAT: ghp_16C7e42F292c6912E7710c838347Ae178B4a',
    'Stripe Live Key: sk_test_51Mabcx82e4EXAMPLE990021384729103847209',
    'Google Maps API: AIzaSyB-EXAMPLE_KEY_aBcDeFgHiJkLmNoPqRs',
    '-----BEGIN RSA PRIVATE KEY-----',
    'MIIEpAIBAAKCAQEA3Tz2mr7SZiAMfQyDkEXAMPLE',
    '-----END RSA PRIVATE KEY-----',
    '',
    'Check the routing table on 10.192.44.5. The attacker tried',
    'admin:P@ssw0rd2026!@192.168.1.100:8080/api/v1/config.',
  ].join('\n');

  const EXPECTED: ReadonlyArray<readonly [string, string]> = [
    ['François Dubois', 'person.name'],
    ['f.dubois@med-clinic.co.uk', 'contact.email'],
    ['2026-09-02T13:45:11Z', 'temporal.date'],
    ["Chloe O'Connor", 'person.name'],
    ['12-MAR-2011', 'temporal.date'],
    ['485 777 3456', 'health.record-number'],
    ['four five three two', 'financial.card'],
    ['11/2028', 'financial.card'],
    ['three-eight-nine', 'financial.card'],
    ["Siobhan O'Connor", 'person.name'],
    ['7123 4567', 'contact.phone'],
    ['siobhan_oconnor88@gmail.com', 'contact.email'],
    ['London', 'geo.locality|contact.address'],
    ['W1J 7JZ', 'geo.postcode'],
    ['E10.9', 'health.condition'],
    ['diabetes', 'health.condition'],
    ['2001:0db8', 'net.ipv6'],
    ['Nine-Nine-Eight', 'gov.ssn'],
    ['4532910087654321', 'financial.card'],
    ['HIV', 'health.condition'],
    ['dXNlcjphZG1pbiBw', 'secret.password'],
    ['ghp_16C7e42F', 'secret.api-key'],
    ['sk_live_51Mabcx', 'secret.api-key'],
    ['AIzaSyB', 'secret.api-key'],
    ['BEGIN RSA PRIVATE KEY', 'secret.private-key'],
    ['10.192.44.5', 'net.ipv4'],
    ['admin:P@ssw0rd2026', 'secret.password'],
  ];

  it('finds every value, and types each one correctly', () => {
    const findings = scanStandard(REPORT);
    for (const [value, type] of EXPECTED) {
      const hit = findings.find((f) => f.value.includes(value));
      assert.ok(hit, `missed: ${value}`);
      assert.ok(type.split('|').includes(hit.type),
        `${value} typed as ${hit.type}, expected one of ${type}`);
    }
  });

  it('redacts a compound surname whole, never half of it', () => {
    const findings = scanStandard("Contact the guarantor, Mrs. Siobhan O'Connor, today.");
    const name = findings.find((f) => f.type === 'person.name');
    assert.ok(name);
    assert.equal(name.value, "Siobhan O'Connor", 'the apostrophe must not end the match');
  });

  it('reads numbers dictated in words', () => {
    assert.equal(transcribeSpokenNumber('Nine-Nine-Eight, Forty-Two, Zero-Zero-One-Nine'), '998420019');
    assert.equal(transcribeSpokenNumber('four five three two nine one zero zero'), '45329100');
    assert.equal(transcribeSpokenNumber('twenty one thirty four'), '2134');
  });

  it('does not lose an address to a sentence-ending full stop', () => {
    const findings = scanStandard('Check the routing table on 10.192.44.5. Then reboot.');
    assert.ok(findings.some((f) => f.type === 'net.ipv4' && f.value === '10.192.44.5'));
  });

  it('leaves nothing behind in the whole report', () => {
    const result = redactDocument(REPORT, {
      adapter: textAdapter,
      policy: compilePolicy(privacyPolicy),
    });
    assert.equal(result.verification.passed, true);
    for (const [value] of EXPECTED) {
      assert.ok(!result.output.text.includes(value), `${value} survived into the output`);
    }
  });
});

/**
 * Operator-marked redactions.
 *
 * The question this answers is the one a reviewer asks the moment they trust the
 * tool enough to look closely: *how do I redact something the system missed?*
 * Detection will always have a tail, so the answer has to be "select it", and
 * what gets selected has to travel the same path as everything else.
 */
describe('marking something the rules missed', () => {
  const TEXT = 'Reference U-9948-X, widget ZZTOP-4471, contact dana@example.com.';
  const at = (needle: string) => ({
    kind: 'text' as const, node: 'p0',
    start: TEXT.indexOf(needle), end: TEXT.indexOf(needle) + needle.length,
  });

  it('redacts a value no rule detects', () => {
    const before = scanStandard(TEXT);
    assert.ok(!before.some((f) => f.value.includes('ZZTOP')), 'precondition: nothing detects it');

    const detectors = [...standardDetectors(), manualDetector([{ location: at('ZZTOP-4471') }])];
    const result = redactDocument(TEXT, {
      adapter: textAdapter, policy: compilePolicy(privacyPolicy), detectors,
    });
    assert.equal(result.verification.passed, true);
    assert.ok(!result.output.text.includes('ZZTOP-4471'));
  });

  it('gives a hand mark its own authority in the record', () => {
    const detectors = [...standardDetectors(), manualDetector([{ location: at('ZZTOP-4471') }])];
    const result = redactDocument(TEXT, {
      adapter: textAdapter, policy: compilePolicy(privacyPolicy), detectors,
      manifestSalt: utf8Encode('a-manifest-salt-of-sufficient-len'),
    });
    const entry = result.manifest!.entries.find((e) => e.entityTypes.includes('manual.marked'));
    assert.ok(entry, 'the mark must appear in the manifest');
    assert.equal(entry.reasonCode, 'operator.marked');
    assert.match(entry.authority, /operator/i);
  });

  it('honours the type the operator assigned', () => {
    const detectors = [
      ...standardDetectors(),
      manualDetector([{ location: at('ZZTOP-4471'), type: 'person.name' }]),
    ];
    const findings = detect(textAdapter.parse(TEXT), detectors).findings;
    const mark = findings.find((f) => f.ruleId === 'manual:marked');
    assert.ok(mark);
    assert.equal(mark.type, 'person.name', 'the type drives classification and the token label');
  });

  it('does not duplicate a mark that lands on something already detected', () => {
    const detectors = [...standardDetectors(), manualDetector([{ location: at('dana@example.com') }])];
    const findings = detect(textAdapter.parse(TEXT), detectors).findings;
    const overlapping = findings.filter(
      (f) => f.location.kind === 'text' && f.location.start === TEXT.indexOf('dana@example.com'));
    assert.equal(overlapping.length, 1, 'the rule finding stands; the mark is dropped as a duplicate');
  });

  it('refuses a mark that points at nothing', () => {
    const detectors = [
      ...standardDetectors(),
      manualDetector([{ location: { kind: 'text', node: 'ghost', start: 0, end: 4 } }]),
    ];
    assert.throws(() => detect(textAdapter.parse(TEXT), detectors), /not in this document/);
  });

  it('is classified by the policy like anything else', () => {
    const detectors = [...standardDetectors(), manualDetector([{ location: at('ZZTOP-4471') }])];
    const model = textAdapter.parse(TEXT);
    const policy = compilePolicy(privacyPolicy);
    const result = classify(model, detect(model, detectors), policy);
    assert.notEqual(result.banner.level, 'open', 'a hand mark raises the document level');
  });
});

/**
 * Name components.
 *
 * Found by running a real batch export and reading the output: the engine
 * redacted "Chloe O'Connor" and left "Chloe's ICD-10 diagnosis code" standing
 * three lines later. Prose refers to people by one name far more often than by
 * both, so chasing only the full string leaves the person disclosed.
 */
describe('partial names', () => {
  const LETTER = [
    "My patient, Chloe O'Connor, was billed twice.",
    '',
    "Chloe's ICD-10 diagnosis code leaked. Contact O'Connor directly.",
  ].join('\n');

  it('redacts a first name used possessively elsewhere', () => {
    const findings = scanStandard(LETTER);
    assert.ok(
      findings.some((f) => f.ruleId === 'repeat:value' && f.value.toLowerCase() === 'chloe'),
      "the bare first name in \"Chloe's\" must be found",
    );
  });

  it('redacts a surname used alone elsewhere', () => {
    const findings = scanStandard(LETTER);
    assert.ok(
      findings.some((f) => f.ruleId === 'repeat:value' && f.value.includes('Connor')),
      'the bare surname must be found',
    );
  });

  it('leaves no part of the name in the output', () => {
    const result = redactDocument(LETTER, {
      adapter: textAdapter,
      policy: compilePolicy(privacyPolicy),
    });
    assert.equal(result.verification.passed, true);
    for (const fragment of ['Chloe', 'Connor']) {
      assert.ok(!result.output.text.includes(fragment), `${fragment} survived`);
    }
  });

  it('does not match a name inside a longer word', () => {
    const findings = scanStandard('Full Name: Ann Vance\n\nShe flew to Vancouver on Tuesday.');
    assert.ok(
      !findings.some((f) => f.ruleId === 'repeat:value' && f.value.toLowerCase().includes('vancouver')),
      'Vancouver must not be reported as a repeat of Vance',
    );
  });

  it('does not split values that are not names', () => {
    // A street name is not an identifier the way a surname is; chasing its words
    // would match everywhere and bury the real repeats.
    const findings = scanStandard('Billing Address: 742 Evergreen Terrace, Springfield, OR 97477\n\nThe Evergreen project is unrelated.');
    assert.ok(
      !findings.some((f) => f.ruleId === 'repeat:value' && f.value === 'Evergreen'),
      'address words must not be chased individually',
    );
  });
});

describe('operator terms', () => {
  const source = [
    'PROJECT AEGISFIELD was tested at the Thule site in 1968.',
    "Aegisfield's schedule slipped; see the aegisfield annex.",
    'The announcement mentioned Ann Rossi, who ran the field trials.',
  ].join('\n\n');

  const findWith = (terms: Parameters<typeof termDetector>[0]) => {
    const model = textAdapter.parse(source);
    return detect(model, [termDetector(terms)]).findings;
  };

  it('finds every occurrence, whatever the case', () => {
    // Three: the heading, the possessive, and the lowercase mention in the
    // annex line -- the possessive included, because redacting `Aegisfield` and
    // leaving `Aegisfield's schedule` standing discloses it one word later.
    const found = findWith([{ text: 'Aegisfield' }]);
    assert.equal(found.length, 3);
    // The value recorded is the text as it appears, not as it was typed --
    // otherwise the manifest digests something the document does not contain.
    assert.deepEqual(
      found.map((f) => f.value).sort(),
      ['AEGISFIELD', 'Aegisfield', 'aegisfield'],
    );
  });

  it('matches whole words, so a short name does not blank half the page', () => {
    // "Ann" appears inside "announcement" three characters in. Redacting that
    // leaves a bar in the middle of an ordinary word and buries the real hit.
    const found = findWith([{ text: 'Ann' }]);
    assert.equal(found.length, 1);
    assert.equal(found[0]!.value, 'Ann');
  });

  it('matches inside words when the operator asks for it', () => {
    // "announcement", "annex" and "Ann Rossi". Which is the point of the
    // default: two of those three are not the person being protected.
    assert.equal(findWith([{ text: 'Ann', whole: false }]).length, 3);
  });

  it('honours an exact-case term', () => {
    assert.equal(findWith([{ text: 'AEGISFIELD', matchCase: true }]).length, 1);
  });

  it('refuses a term too short to mean anything', () => {
    assert.throws(() => termDetector([{ text: 'an' }]), /shorter than/);
  });

  it('removes every occurrence end to end, and the verifier agrees', () => {
    const result = redactDocument(source, {
      adapter: textAdapter,
      policy: compilePolicy(privacyPolicy),
      detectors: [termDetector([{ text: 'Aegisfield' }])],
    });
    assert.equal(result.verification.passed, true);
    assert.ok(!/aegisfield/i.test(result.output.text));
  });
});
