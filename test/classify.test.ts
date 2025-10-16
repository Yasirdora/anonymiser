import assert from 'node:assert/strict';
import { describe, it } from 'node:test';

import { textAdapter } from '../src/adapters/text/index.js';
import { classify } from '../src/classify/engine.js';
import {
  applyDomination,
  compilePolicy,
  dominatedBy,
  join,
  joinAll,
  pruneIneligibleMarkings,
} from '../src/classify/lattice.js';
import { parseMarking, renderMarking } from '../src/classify/marking.js';
import { corporatePolicy, privacyPolicy, ukGscpPolicy, usCapcoPolicy } from '../src/classify/packs/index.js';
import type { Assertion } from '../src/classify/types.js';
import { detect } from '../src/detect/engine.js';
import { standardDetectors } from '../src/detect/index.js';

const capco = compilePolicy(usCapcoPolicy);
const uk = compilePolicy(ukGscpPolicy);
const privacy = compilePolicy(privacyPolicy);

const A = (level: string, markings: Record<string, string[]> = {}): Assertion => ({ level, markings });

describe('the marking lattice', () => {
  it('takes the higher level when joining', () => {
    assert.equal(join(capco, A('confidential'), A('secret')).level, 'secret');
    assert.equal(join(capco, A('secret'), A('confidential')).level, 'secret');
  });

  it('is commutative', () => {
    const a = A('secret', { dissemination: ['orcon'] });
    const b = A('confidential', { dissemination: ['propin'] });
    assert.deepEqual(join(capco, a, b), join(capco, b, a));
  });

  it('is associative', () => {
    const a = A('confidential', { dissemination: ['orcon'] });
    const b = A('secret', { 'cui-category': ['sp-prvcy'] });
    const c = A('top-secret', { dissemination: ['propin'] });
    assert.deepEqual(join(capco, join(capco, a, b), c), join(capco, a, join(capco, b, c)));
  });

  it('is idempotent, so re-classifying changes nothing', () => {
    const a = A('secret', { dissemination: ['orcon', 'propin'] });
    assert.deepEqual(join(capco, a, a), applyDomination(capco, a));
  });

  it('has the unmarked assertion as its identity', () => {
    const a = A('secret', { dissemination: ['orcon'] });
    assert.deepEqual(join(capco, a, capco.unit), applyDomination(capco, a));
  });

  it('accumulates restrictions as a union', () => {
    const joined = join(
      capco,
      A('secret', { dissemination: ['orcon'] }),
      A('secret', { dissemination: ['propin'] }),
    );
    assert.deepEqual([...(joined.markings['dissemination'] ?? [])].sort(), ['orcon', 'propin']);
  });

  it('narrows releasability as an intersection, not a union', () => {
    // This is the rule hand-rolled marking tools get wrong. A document with a
    // portion releasable to five nations and one releasable to three is
    // releasable to the three, never to the five.
    const joined = join(
      capco,
      A('secret', { releasable: ['usa', 'gbr', 'can', 'aus', 'nzl'] }),
      A('secret', { releasable: ['usa', 'gbr', 'can'] }),
    );
    assert.deepEqual(
      [...(joined.markings['releasable'] ?? [])].sort(),
      ['can', 'gbr', 'usa'],
      'the wider set must be narrowed to the nations both portions share',
    );
  });

  it('treats an unmarked portion as releasable only to the originator', () => {
    // Silence is not consent: joining a FVEY-releasable portion with an
    // unmarked one must not leave the document releasable to FVEY.
    const joined = join(capco, A('secret', { releasable: ['usa', 'fvey'] }), A('secret'));
    assert.equal(
      joined.markings['releasable'],
      undefined,
      'the intersection collapsed to the baseline, so no releasability may be claimed',
    );
  });

  it('lets NOFORN dominate every releasability marking', () => {
    const joined = join(
      capco,
      A('secret', { releasable: ['usa', 'fvey'] }),
      A('secret', { dissemination: ['noforn'] }),
    );
    assert.deepEqual(joined.markings['dissemination'], ['noforn']);
    assert.equal(joined.markings['releasable'], undefined, 'REL TO must not survive NOFORN');
  });

  it('applies domination regardless of which operand contributed it', () => {
    const left = join(capco, A('secret', { dissemination: ['noforn'] }), A('secret', { releasable: ['fvey'] }));
    const right = join(capco, A('secret', { releasable: ['fvey'] }), A('secret', { dissemination: ['noforn'] }));
    assert.deepEqual(left, right);
  });

  it('drops markings the level does not permit', () => {
    const { assertion, dropped } = pruneIneligibleMarkings(capco, A('unclassified', { sci: ['si'] }));
    assert.deepEqual(dropped, ['si']);
    assert.equal(assertion.markings['sci'], undefined);
  });

  it('orders assertions correctly for release checks', () => {
    assert.equal(dominatedBy(capco, A('confidential'), A('secret')), true);
    assert.equal(dominatedBy(capco, A('secret'), A('confidential')), false);
    assert.equal(
      dominatedBy(capco, A('secret', { dissemination: ['noforn'] }), A('secret')),
      false,
      'a NOFORN portion is not covered by a plain SECRET banner',
    );
  });

  it('treats more REL TO countries as less sensitive, not more', () => {
    const fvey = A('secret', { releasable: ['usa', 'fvey'] });
    const usaOnly = A('secret', { releasable: ['usa'] });
    assert.equal(
      dominatedBy(capco, fvey, usaOnly),
      true,
      'REL TO USA, FVEY is no more sensitive than REL TO USA',
    );
    assert.equal(
      dominatedBy(capco, usaOnly, fvey),
      false,
      'REL TO USA is more sensitive than REL TO USA, FVEY',
    );
    assert.equal(
      dominatedBy(capco, A('secret'), usaOnly),
      false,
      'an unmarked portion is originator-only and more sensitive than REL TO USA',
    );
  });

  it('intersects FVEY as the five nations, not as an opaque token', () => {
    const joined = join(
      capco,
      A('secret', { releasable: ['usa', 'fvey'] }),
      A('secret', { releasable: ['usa', 'gbr'] }),
    );
    assert.deepEqual(
      [...(joined.markings['releasable'] ?? [])].sort(),
      ['gbr', 'usa'],
      'FVEY ∩ GBR is USA, GBR, not USA alone',
    );
  });
});

describe('marking strings', () => {
  it('renders a full CAPCO banner', () => {
    const marking = renderMarking(
      capco,
      A('top-secret', { sci: ['si'], dissemination: ['noforn'] }),
      'banner',
    );
    assert.equal(marking, 'TOP SECRET//SI//NOFORN');
  });

  it('renders the abbreviated portion form', () => {
    assert.equal(
      renderMarking(capco, A('secret', { dissemination: ['noforn'] }), 'portion'),
      '(S//NF)',
    );
  });

  it('omits empty groups instead of emitting bare separators', () => {
    assert.equal(renderMarking(capco, A('confidential'), 'banner'), 'CONFIDENTIAL');
  });

  it('round-trips a banner through the parser', () => {
    const original = A('top-secret', { sci: ['si', 'tk'], dissemination: ['noforn'] });
    const rendered = renderMarking(capco, original, 'banner');
    const parsed = parseMarking(capco, rendered);
    assert.equal(renderMarking(capco, parsed.assertion, 'banner'), rendered);
    assert.deepEqual(parsed.unrecognized, []);
  });

  it('prefers the longest matching level, so TOP SECRET is not read as SECRET', () => {
    assert.equal(parseMarking(capco, 'TOP SECRET//NOFORN').assertion.level, 'top-secret');
    assert.equal(parseMarking(capco, 'SECRET//NOFORN').assertion.level, 'secret');
  });

  it('parses a multi-word marking value', () => {
    const parsed = parseMarking(uk, 'SECRET UK EYES ONLY');
    assert.equal(parsed.assertion.level, 'secret');
    assert.deepEqual(parsed.assertion.markings['caveat'], ['uk-eyes-only']);
    assert.deepEqual(parsed.unrecognized, []);
  });

  it('parses a bracketed UK descriptor without reporting the brackets as unknown', () => {
    const parsed = parseMarking(uk, 'OFFICIAL-SENSITIVE [PERSONAL]');
    assert.equal(parsed.assertion.level, 'official-sensitive');
    assert.deepEqual(parsed.assertion.markings['descriptor'], ['personal']);
    assert.deepEqual(parsed.unrecognized, []);
  });

  it('reports segments it does not understand rather than discarding them', () => {
    const parsed = parseMarking(capco, 'SECRET//WIDGETCON//NOFORN');
    assert.equal(parsed.assertion.level, 'secret');
    assert.deepEqual(parsed.assertion.markings['dissemination'], ['noforn']);
    assert.deepEqual(parsed.unrecognized, ['WIDGETCON']);
  });

  it('keeps the highest level when a string mentions several', () => {
    assert.equal(parseMarking(capco, 'SECRET//DOWNGRADE TO CONFIDENTIAL').assertion.level, 'secret');
  });

  it('strips portion delimiters before parsing', () => {
    assert.equal(parseMarking(capco, '(TS//SI)').assertion.level, 'top-secret');
  });
});

describe('document classification', () => {
  function run(text: string, policy = privacy) {
    const model = textAdapter.parse(text);
    const detection = detect(model, standardDetectors());
    return classify(model, detection, policy);
  }

  it('derives a banner from the portions beneath it', () => {
    const result = run(
      'Summary of the review.\n\nThe subject is reachable at dana.reyes@example.com and holds NHS number 943 476 5919.',
    );
    assert.equal(result.banner.level, 'special-category');
    assert.ok(result.bannerMarking.startsWith('SPECIAL CATEGORY'));
  });

  it('marks every portion, including the ones that need nothing', () => {
    const result = run('Nothing sensitive here.\n\nCall dana on +44 20 7946 0958.');
    assert.ok(result.portions.length >= 1);
    for (const portion of result.portions) {
      assert.ok(portion.marking.length > 0, 'every portion gets a marking');
    }
  });

  it('cites the authority behind each determination', () => {
    const result = run('Patient NHS number 943 476 5919 was admitted.');
    const basis = result.portions.flatMap((p) => p.basis);
    assert.ok(basis.length > 0);
    assert.ok(basis.every((b) => b.authority.length > 0), 'every rule must cite an authority');
  });

  it('escalates when quasi-identifiers combine', () => {
    // Neither a postcode nor a date of birth identifies anyone on its own.
    const result = run('Subject: DOB 14/03/1979, postcode SW1A 2AA.');
    assert.ok(
      result.warnings.some((w) => w.code === 'mosaic-risk'),
      'co-occurring quasi-identifiers must raise a mosaic warning',
    );
  });

  it('notices when a document is marked lower than its content warrants', () => {
    const model = textAdapter.parse(
      'PUBLIC\n\nThe account holder is dana.reyes@example.com, card 4111 1111 1111 1111.',
    );
    const detection = detect(model, standardDetectors());
    const result = classify(model, detection, compilePolicy(corporatePolicy));
    // The corporate pack's rules push this to CONFIDENTIAL; a PUBLIC banner
    // would be an under-marking.
    assert.ok(result.banner.level === 'confidential' || result.banner.level === 'restricted');
  });

  it('produces the same result whatever order the portions are visited in', () => {
    const forward = joinAll(capco, [
      A('confidential', { dissemination: ['orcon'] }),
      A('secret', { releasable: ['usa', 'fvey'] }),
      A('unclassified'),
    ]);
    const reverse = joinAll(capco, [
      A('unclassified'),
      A('secret', { releasable: ['usa', 'fvey'] }),
      A('confidential', { dissemination: ['orcon'] }),
    ]);
    assert.deepEqual(forward, reverse);
  });
});

describe('bundled policies', () => {
  it('all compile without structural errors', () => {
    for (const policy of [usCapcoPolicy, ukGscpPolicy, privacyPolicy, corporatePolicy]) {
      assert.doesNotThrow(() => compilePolicy(policy), `${policy.id} must compile`);
    }
  });

  it('rejects a policy whose default level is not declared', () => {
    assert.throws(
      () => compilePolicy({ ...privacyPolicy, defaultLevel: 'nonexistent' }),
      /defaultLevel/,
    );
  });

  it('rejects a marking declared in two groups', () => {
    const broken = {
      ...privacyPolicy,
      groups: [
        privacyPolicy.groups[0]!,
        { ...privacyPolicy.groups[1]!, values: [...privacyPolicy.groups[1]!.values, privacyPolicy.groups[0]!.values[0]!] },
      ],
    };
    assert.throws(() => compilePolicy(broken), /more than one group/);
  });
});
