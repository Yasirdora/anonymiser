# @anonymiser/core


🌐 **Try the Live Studio App:** [ysrdora.github.io/anonymiser.app](http://ysrdora.github.io/anonymiser.app)

A zero-dependency, framework-agnostic engine for **classifying documents, deriving security markings, redacting sensitive content, proving the redaction worked, and recording what was done.**

Runs unchanged in a browser, a service worker, Node, Deno, and Bun. No DOM, no Node built-ins, no dependencies — not "few dependencies", none.

```bash
npm install @anonymiser/core
```

---

## Why this exists

Redaction fails constantly, and it fails the same way every time.

The Manafort court filings, the DOJ Epstein release, a long line of FOIA disclosures and regulatory submissions — in each case a black rectangle was drawn over text that was never removed. The failure is invisible: a covering rectangle and a genuine deletion render identically on screen, and the person doing the work gets no feedback either way until a journalist selects the text and copies it.

Meanwhile every image tool in the ecosystem offers blur or pixelation as the default control for hiding a face or a number. Both are reversible. [Unredacter](https://bishopfox.com/blog/unredacter-winner) recovers text from pixelated screenshots by rendering candidates in the same font and matching the output; Positive Security demonstrated [exact recovery from pixelated video](https://positive.security/blog/video-depixelation) with no guessing at all.

And no library in the JavaScript ecosystem models classification markings at all. Not one implements banner derivation, portion marking, caveat propagation, or the difference between a restriction and a permission.

This engine is built on four positions.

### 1. A redaction that can be reversed is not a redaction

`blur` and `pixelate` are declared **recoverable** and refused at plan time. The refusal cites the published attack:

```ts
assertStrategyPermitted('blur');
// ClassifiedError [E_COSMETIC_REFUSED]
// the "blur" strategy does not destroy the content it covers and can be
// reversed. Blurring is a linear, deterministic transform. Rendering candidate
// text in the same font and blurring it with the same radius reproduces the
// output, which reduces recovery to a search over a small candidate set
// (Petro, Unredacter, 2022). Use "blackout" for image regions, or pass
// allowRecoverableStrategies to accept a redaction that is not defensible.
```

You can override it. You cannot override it silently: the manifest records the choice and the result is flagged as not defensible.

**The Solution: Synthetic Mosaic**
To provide the visual affordance of pixelation without the mathematical vulnerability, the engine implements a `synthetic-mosaic` strategy. Instead of averaging underlying pixel values (which leaks data), it generates a deterministic, cryptographically-seeded noise block over the region. The original pixels are unconditionally destroyed, yielding the aesthetic of a classic mosaic with mathematically guaranteed zero-reversibility.

### 2. Redaction is not finished until it is verified

After operations are applied, the output is **read back through the adapter and searched** for everything the plan promised to remove — across every channel that has ever leaked: the text layer, metadata, annotations, attachments, revision history, and pixels under an overlay. A leak throws. It is not a warning.

Verification found a real bug in this engine's own text adapter during development: node-level `replace` operations were being silently dropped, leaving author metadata in the output. That is the check doing its job on its own author.

### 3. Markings are derived, never asserted

A banner is the **lattice join** of the portions beneath it. Levels form a chain ordered by rank; each marking group is a lattice over its powerset; an assertion is a point in their product. Join is associative, commutative, and idempotent, so the banner does not depend on the order portions were visited and re-classifying a classified document changes nothing.

The distinction that matters, and that hand-rolled marking tools get wrong:

| Marking kind | Combines by | Because |
|---|---|---|
| Restrictions (`NOFORN`, `ORCON`) | **union** | If any portion is ORCON, the document is ORCON. |
| Permissions (`REL TO`) | **intersection** | Releasable to the nations *every* portion permits, never the union. |

```
SECRET//REL TO USA,FVEY  +  SECRET//REL TO USA,GBR   =>  SECRET//REL TO USA, GBR
SECRET//REL TO USA,FVEY  +  SECRET (unmarked)        =>  SECRET
SECRET//REL TO USA,FVEY  +  SECRET//NOFORN           =>  SECRET//NOFORN
CONFIDENTIAL//ORCON      +  TOP SECRET//SI           =>  TOP SECRET//SI//ORCON
```

The second line is subtle and important. A portion with no releasability marking is releasable to the originator alone — silence is not consent — so the intersection collapses to the baseline and no releasability may be claimed.

A marking the document already carries is **evidence to be checked**, not a fact to be trusted. The engine parses it and reports both directions of disagreement: `under-marked` (a disclosure risk) and `over-marked` (usually a missed portion mark, and the failure that makes releases unusable).

### 4. Every removal carries an authority

No anonymous redactions. Each operation names the statute, exemption, or policy paragraph it acts under — FOIA exemptions b(1) through b(9) ship built in — and the tamper-evident manifest records it. The manifest stores **salted digests of removed values, never the values**, so it can be published alongside a release without becoming a second copy of the disclosure.

---

## Quick start

```ts
import { redactDocument, compilePolicy, privacyPolicy, PseudonymGenerator, utf8Encode } from '@anonymiser/core';
import { textAdapter } from '@anonymiser/core/adapters/text';

const result = redactDocument(
  {
    text: 'Complainant Dana Reyes (DOB 14/03/1979) reports that card 4111 1111 1111 1111\n' +
          'was charged without authorisation. Reachable at dana.reyes@example.com.',
    metadata: { Author: 'M. Okonkwo', Producer: 'CaseTrack 7.2' },
  },
  {
    adapter: textAdapter,
    policy: compilePolicy(privacyPolicy),
    plan: {
      pseudonyms: new PseudonymGenerator({ key: utf8Encode('kept-with-the-originals') }),
      strategyByType: { 'person.name': 'pseudonymize', 'contact.email': 'pseudonymize' },
    },
    manifestSalt: utf8Encode('audit-salt-for-this-release'),
  },
);

console.log(result.output.text);
// Complainant PERSON_AWCXA2 (DOB [REDACTED]) reports that card [REDACTED]
// was charged without authorisation. Reachable at EMAIL_N7DKUP.

console.log(result.output.metadata);        // { }  — author and tool removed
console.log(result.classification.bannerMarking);
// RESTRICTED // GDPR-ART4/PCI-CHD // DO NOT PUBLISH
console.log(result.verification.passed);    // true
console.log(result.defensible);             // true
console.log(result.manifest.root);          // bbc30361cf439f4e...
```

To look without touching anything:

```ts
import { analyze } from '@anonymiser/core';

const { detection, classification } = analyze(source, { adapter: textAdapter, policy });
for (const w of classification.warnings) console.log(`[${w.code}] ${w.message}`);
```

---

## Architecture

```
source bytes
    │
    ▼  DocumentAdapter.parse()
DocumentModel ─────── a flat, format-agnostic node graph
    │                 text · raster · vector · metadata · annotation · attachment
    ▼  detect()
Findings ──────────── what, where, how confident, and the evidence for it
    │
    ▼  classify()
Portions + Banner ─── lattice join, checked against what the document claims
    │
    ▼  planRedactions()
RedactionPlan ─────── reviewable before anything is written; every op cites an authority
    │
    ▼  DocumentAdapter.apply()
output bytes
    │
    ▼  DocumentAdapter.reparse() + verify()
VerificationReport ── leaks throw; unverifiable is not the same as clean
    │
    ▼  buildManifest()
ProvenanceManifest ── hash-chained, salted, reproducible, discloses nothing
```

Every stage is exported separately. The default path runs all of them.

### Adding a format

Write a `DocumentAdapter`. Nothing else changes.

```ts
interface DocumentAdapter<TSource, TOutput> {
  parse(source: TSource, options?: ParseOptions): DocumentModel;
  apply(model: DocumentModel, operations: readonly RedactionOperation[]): TOutput;
  reparse(output: TOutput): DocumentModel;   // <- this is what makes verification possible
  readonly capabilities: AdapterCapabilities;
}
```

`reparse` is not optional convenience. An adapter that can write an output but cannot read it back is an adapter whose redactions cannot be checked. Declare `verifiable: false` if you genuinely cannot, and the pipeline reports the result as degraded rather than passing.

---

## What ships

**Detection.** Nine pattern packs — contact, people, identity, financial, health, secrets, network, geo, markings — gated on real checksums: Luhn plus issuer ranges for cards, ISO 13616 mod-97 for IBAN, ABA weighted mod-10, NHS mod-11, ICAO 9303 for passport MRZ, SSA block rules, NINO prefix rules. Plus context scoring, so `SSN: 123456789` is a finding and `Part number 123456789` is not, and every finding carries the evidence that produced its confidence score.

**Structural detection.** The half that catches how redaction actually fails: opaque shapes over live text, identifying metadata, annotations, attachments, revision history.

**Repeat detection.** Once a value is identified anywhere, every other occurrence of it is found. Rules match a name behind `Full Name:`; nothing matches the same name in the signature block, and redacting one while leaving the other is not a redaction. This detector exists because the verifier refused a document for exactly that.

**Classification.** Five policy packs — [US CAPCO/ISOO](https://www.dni.gov/index.php/who-we-are/organizations/ic-cio/ic-technical-specifications/information-security-marking-metadata) with CUI categories, [UK GSCP](https://en.wikipedia.org/wiki/Government_Security_Classifications_Policy), NATO, ISO 27001 corporate, and a GDPR/HIPAA privacy pack. Plus **mosaic rules**: Sweeney's result that ZIP code, date of birth, and sex uniquely identify most of the US population is invisible to any engine that scores findings one at a time, so co-occurring quasi-identifiers escalate the portion that contains them.

**Redaction.** Eight strategies with declared safety properties. Deterministic HMAC pseudonyms, so one entity reads as one entity across a whole corpus without disclosing it, and a different key makes two releases unjoinable.

**PDF.** A from-scratch DEFLATE decoder, object lexer, and content-stream interpreter — no dependency. Reads text with positions, filled rectangles, annotations, embedded files, metadata, and **every object superseded by an incremental update**, because the store is built by scanning for `N G obj` rather than by walking the xref. That inversion is what finds text a previous "redaction" merely superseded. It detects the signature failure — an opaque dark box over extractable text — **in files other tools produced**, and writes output as a single flattened revision so nothing survives in a prior one.

**Images.** Byte-level JPEG segment and PNG chunk surgery: EXIF, XMP, IPTC, and textual chunks are excised **without decoding or recompressing the image**, so the pixels stay bit-identical. GPS coordinates are decoded to decimal degrees and exposed as model nodes, so coordinates in EXIF are classified by exactly the same rule as coordinates in the body text. Region redaction overwrites pixels rather than compositing over them.

---

## Honest limits

- **Name detection is heuristic.** Names are found by their *frame* — an honorific, a role label, a signature block — not their content. That is precise where it fires and silent where it does not. For work where a missed name is unacceptable, add a named-entity recogniser as an extra `Detector`; the engine is built to compose them.
- **The PDF adapter does not read scans.** There is no OCR, so a scanned page is reported as having no extractable text rather than as clean. It also does not re-encode images, subset fonts, or handle encrypted files — an encrypted PDF is refused rather than half-processed. Text boxes come from an average glyph width rather than font metrics, so a burned bar is deliberately slightly generous.
- **Office adapters are not in this release.** DOCX and XLSX are next; revision history and comments are the primary leak channels there.
- **The classification packs are working models, not authoritative copies.** Marking vocabularies change, several compartments are themselves classified, and every adopting organisation adds local values. Unrecognised segments surface as `unparsed-marking` warnings rather than being silently dropped. Have whoever owns marking policy review the pack before it is deployed.
- **The CAPCO pack stops at CUI.** Whether information is national security information under EO 13526 is an original classification decision reserved to a human with the authority to make it. No pattern match substitutes for that. What the engine does derive is the CUI categories that follow mechanically from privacy, health, or law-enforcement content.
- **`deriveKey` is iterated SHA-256, not memory-hard.** A zero-dependency core cannot provide Argon2. It is appropriate for a carefully chosen project passphrase and not for a user-chosen password. Where the platform offers PBKDF2 or Argon2, use that and pass the bytes in.
- **Findings below `plan.minConfidence` (default 0.5) are reported, not redacted.** The default was 0.7 and that was wrong: against a real breach complaint it left a billing address, a postcode, and a labelled account number in the output — all detected, all scored just under the line. Raise it only where over-redaction is genuinely the greater risk.
- **A label outranks a failed checksum.** `Tax ID / SSN: 000-12-3456` is redacted even though area 000 is never issued, and `IBAN: US64SVBK…` even though the US issues no IBANs. When the document says what a value is, refusing to redact it because a check digit failed inverts the point of the tool.

---

## Security notes

- **The pseudonym key is the most sensitive artifact in the pipeline.** Anyone holding it can confirm a guess by hashing a candidate. Store it wherever the original documents are stored, and never in the released material.
- **A `RedactionPlan` contains the original values** — it must, in order to verify their removal. Handle it like the source document. The manifest does not, and is safe to publish.
- **Manifest salt choice is a policy decision.** One salt across a corpus lets an auditor confirm the same value was removed from two documents, which is often the point. A fresh salt per document prevents that linkage. Both are legitimate.
- The SHA-256 implementation is not constant-time against a local attacker measuring cache behaviour. That is out of scope: the engine hashes content the caller already holds in plaintext.

---

## Playground

You can try out the engine live in the browser without installing anything. It includes sample documents, five classification policies, every redaction strategy, live verification, and manifest inspection.

👉 **[Try the Anonymiser Playground](https://ysrdora.github.io/anonymiser.app)**

---

## Testing

```bash
npm test        # 172 tests, node:test, no test framework dependency
npm run typecheck
```

The suite covers FIPS 180-4 and RFC 4231 vectors, DEFLATE round-trips against Node's zlib, lattice algebra (commutativity, associativity, idempotence, identity), marking round-trips, checksum validators, offset-correct text rewriting, the safety refusals, manifest tamper detection, hand-built PNG/JPEG/PDF fixtures, a PDF with a fake redaction and one with a superseded revision, an adapter deliberately written to leak — and a real breach complaint asserted value by value, which is where several of these rules came from.

## Legal Disclaimer

This software is provided "as is", without warranty of any kind, express or implied. While the engine is designed to securely and permanently remove information, document security and compliance are ultimately the responsibility of the user. The authors and contributors assume no liability for data leaks, accidental disclosures, legal damages, or consequences resulting from the use of this tool. Always verify your releases.

## License

Apache-2.0
