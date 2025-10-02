/**
 * Personal and organisational names.
 *
 * Names are the hardest category to detect without a model, and this pack does
 * not pretend otherwise. There is no pattern that distinguishes "Dana Reyes"
 * from "Union Station", and a gazetteer large enough to help would be larger
 * than the rest of the engine and still wrong outside the cultures it was built
 * from.
 *
 * So these rules detect names by their *frame* rather than their content: an
 * honorific in front, a role label before them, a signature block around them.
 * That is precise where it fires and silent where it does not, which is the
 * right trade for a tool whose output a person has to review. The alternative --
 * flagging every capitalised word pair -- produces a review queue nobody reads.
 *
 * For work where a missed name is unacceptable, plug in a named-entity
 * recogniser as an additional {@link Detector}. The engine is built for that:
 * detectors compose, and a model-based one and these rules corroborate each
 * other through the confidence and evidence machinery rather than competing.
 */

import type { PatternPack, PatternRule } from '../pattern.js';
import { Confidence } from '../types.js';

/**
 * Capitalised words that are almost never a personal name.
 *
 * Kept short deliberately. A long stoplist becomes its own maintenance problem
 * and starts rejecting real surnames -- there are people called Marsh, Church,
 * and January.
 */
const NOT_A_NAME = new Set([
  'january', 'february', 'march', 'april', 'june', 'july', 'august', 'september',
  'october', 'november', 'december', 'monday', 'tuesday', 'wednesday', 'thursday',
  'friday', 'saturday', 'sunday',
  'department', 'ministry', 'agency', 'bureau', 'office', 'court', 'tribunal',
  'university', 'hospital', 'clinic', 'limited', 'ltd', 'inc', 'llc', 'plc',
  'corporation', 'company', 'holdings', 'group', 'trust', 'foundation',
  'street', 'avenue', 'road', 'lane', 'drive', 'square', 'station', 'airport',
  'north', 'south', 'east', 'west', 'united', 'states', 'kingdom',
]);

/** Every word in the candidate must be plausible as a name component. */
function looksLikeName(value: string): boolean {
  const words = value.split(/[\s'-]+/).filter((w) => w.length > 0);
  if (words.length === 0) return false;
  return !words.some((word) => NOT_A_NAME.has(word.toLowerCase()));
}

/**
 * One name component.
 *
 * Built on Unicode letter classes rather than an ASCII range, and -- the part
 * that matters -- a component may contain an apostrophe or hyphen followed by
 * another *capital* letter. `O'Connor`, `D'Angelo`, `McDonald-Reid` all have one.
 *
 * The earlier version ended the match at the apostrophe, so `Siobhán O'Connor`
 * was redacted as `Siobhán O'` and left `Connor` standing in the document. A
 * partial name redaction is worse than none: it looks finished.
 */
const NAME_WORDS = "\\p{Lu}\\p{L}*(?:['\u2019\\-]\\p{L}+)*";

/**
 * A name introduced by an honorific.
 *
 * The strongest frame available without a model: nothing but a person follows
 * "Dr" or "Ms", and the honorific itself is the disclosure risk as often as the
 * name is.
 */
const honorific: PatternRule = {
  id: 'person.name.honorific',
  type: 'person.name',
  pattern: new RegExp(
    `(?:Mr|Mrs|Ms|Miss|Mx|Dr|Prof(?:essor)?|Sir|Dame|Lord|Lady|Rev(?:erend)?|Hon(?:ourable)?|Judge|Justice|Officer|Det(?:ective)?|Sgt|Sergeant|Insp(?:ector)?|Capt(?:ain)?|Col(?:onel)?|Gen(?:eral)?|Lt|Lieutenant|Maj(?:or)?|Adm(?:iral)?|Sen(?:ator)?|Rep|Amb(?:assador)?)\\.?\\s+(${NAME_WORDS}(?:\\s+${NAME_WORDS}){0,2})`,
    'gu',
  ),
  group: 1,
  baseConfidence: Confidence.STRONG,
  description: 'a personal name following an honorific or rank',
  validate: (value) =>
    looksLikeName(value)
      ? { ok: true, signal: 'structure:name-shape', note: 'every word is plausible as part of a name', weight: 0.1 }
      : { ok: false, signal: 'structure:name-shape', note: 'contains a word that is not part of a personal name' },
  normalize: (value) => value.toLowerCase().replace(/\s+/g, ' '),
};

/**
 * A name introduced by a role label.
 *
 * Covers the shape of nearly every form, case file, and report: a label, then
 * the person it refers to. Both the colon and the bare forms appear in the
 * wild, so both are accepted.
 */
/**
 * Labels that introduce a person, written so the first letter of each word may
 * be either case.
 *
 * The obvious approach -- an `i` flag on the whole expression -- is wrong here:
 * it makes `\p{Lu}` in the name part case-insensitive too, and the rule starts
 * matching "the guarantor" as a name. The label has to flex without the name
 * following suit.
 */
const ROLE_LABELS = [
  'Name', 'Full\\s+name', 'Complainant', 'Claimant', 'Plaintiff', 'Defendant',
  'Respondent', 'Appellant', 'Witness', 'Patient', 'Client', 'Guarantor',
  'Applicant', 'Employee', 'Author', 'Owner', 'Contact', 'Signed', 'Signature',
  'Prepared\\s+by', 'Reviewed\\s+by', 'Submitted\\s+by', 'Interviewed',
  'Attn', 'Attention', 'Care\\s+of', 'c/o',
].map((label) => label.replace(/^([A-Za-z])/, (m) => `[${m.toUpperCase()}${m.toLowerCase()}]`));

/**
 * A name introduced by a role label.
 *
 * Covers the shape of nearly every form, case file, and report: a label, then
 * the person it refers to. The separator may be a colon, a comma, or nothing --
 * "Patient:", "My patient, Chloe O'Connor", "Full Name  Marcus Vance".
 */
const labelled: PatternRule = {
  id: 'person.name.labelled',
  type: 'person.name',
  pattern: new RegExp(
    `(?:${ROLE_LABELS.join('|')})\\s*[:,]?\\s+(${NAME_WORDS}(?:\\s+${NAME_WORDS}){1,3})`,
    'gu',
  ),
  group: 1,
  baseConfidence: Confidence.LIKELY,
  description: 'a personal name following a role label',
  validate: (value) =>
    looksLikeName(value)
      ? { ok: true, signal: 'structure:name-shape', note: 'every word is plausible as part of a name', weight: 0.18 }
      : { ok: false, signal: 'structure:name-shape', note: 'contains a word that is not part of a personal name' },
  normalize: (value) => value.toLowerCase().replace(/\s+/g, ' '),
};

/**
 * A surname-first name, as written in indexes and case citations.
 *
 * `Reyes, Dana` is a distinctive shape: two capitalised words separated by a
 * comma, inside a sentence rather than a list.
 */
const surnameFirst: PatternRule = {
  id: 'person.name.surname-first',
  type: 'person.name',
  pattern: new RegExp(`(?<![,\\w])(${NAME_WORDS}),\\s+(${NAME_WORDS})(?:\\s+${NAME_WORDS})?(?![,\\w])`, 'gu'),
  baseConfidence: Confidence.WEAK,
  description: 'a surname-first personal name',
  validate: (value) =>
    looksLikeName(value.replace(',', ' '))
      ? { ok: true, signal: 'structure:name-shape', note: 'both parts are plausible as name components', weight: 0.1 }
      : { ok: false, signal: 'structure:name-shape', note: 'contains a word that is not part of a personal name' },
  normalize: (value) => value.toLowerCase().replace(/\s+/g, ' '),
  context: {
    supports: ['name', 'surname', 'index', 'record', 'file', 'v', 'versus', 'signed', 'author'],
    requireSupport: true,
  },
};

/**
 * Organisation names carrying a legal-form suffix.
 *
 * Precise, because the suffix is a legal designation rather than a word anyone
 * uses loosely, and worth detecting because a company name is commercially
 * sensitive in exactly the documents where personal names are not.
 */
const organisation: PatternRule = {
  id: 'org.name.legal-form',
  type: 'org.name',
  pattern: new RegExp(
    `(?:${NAME_WORDS}\\s+){1,4}(?:Ltd|Limited|LLC|L\\.L\\.C|Inc|Incorporated|Corp|Corporation|PLC|plc|LLP|GmbH|AG|S\\.A|SARL|B\\.V|N\\.V|Pty|Pte|A/S|AB|Oy)\\.?`,
    'gu',
  ),
  baseConfidence: Confidence.STRONG,
  description: 'an organisation name with a legal-form suffix',
  normalize: (value) => value.toLowerCase().replace(/[\s.]+/g, ' ').trim(),
};

/** Employee and staff numbers, which link a record to a person via HR systems. */
const employeeId: PatternRule = {
  id: 'org.employee-id',
  type: 'org.employee-id',
  pattern: /(?<![A-Z0-9-])[A-Z]{0,3}-?\d{4,10}(?![A-Z0-9-])/g,
  baseConfidence: Confidence.HINT,
  description: 'an identifier labelled as an employee or staff number',
  normalize: (value) => value.toUpperCase().replace(/-/g, ''),
  context: {
    supports: ['employee', 'staff', 'personnel', 'payroll', 'badge', 'emp no', 'emp id', 'worker'],
    requireSupport: true,
    supportWeight: 0.35,
  },
};

/**
 * `SURNAME/FORENAME`, the form used in payment-card track data, boarding passes,
 * and airline records. Nothing else is written this way.
 */
const slashName: PatternRule = {
  id: 'person.name.slash',
  type: 'person.name',
  pattern: /(?<![\w/])\p{Lu}[\p{Lu}'\u2019 -]{1,30}\/\p{Lu}[\p{Lu}'\u2019 -]{1,30}(?![\w/])/gu,
  baseConfidence: Confidence.LIKELY,
  description: 'a surname and forename pair in the slash-separated form used by travel and card records',
  validate: (value) =>
    looksLikeName(value.replace('/', ' '))
      ? { ok: true, signal: 'structure:name-shape', note: 'both parts are plausible as name components', weight: 0.14 }
      : { ok: false, signal: 'structure:name-shape', note: 'contains a word that is not part of a personal name' },
  normalize: (value) => value.toLowerCase().replace(/\s+/g, ' '),
};

/**
 * An internal record identifier behind its label.
 *
 * `"user_id":"U-9948-X"` is a pseudonymous key into the system that holds
 * everything else about the person. Releasing it while redacting their name
 * protects nothing from anyone who can query that system, and it is the join
 * key that makes two released documents linkable.
 *
 * Matched only behind an explicit label, because the shape alone -- a letter,
 * some digits, a suffix -- is indistinguishable from a part number.
 */
const recordId: PatternRule = {
  id: 'org.record-id',
  type: 'org.employee-id',
  pattern:
    /(?:user[_\s-]?id|account[_\s-]?id|customer[_\s-]?id|subscriber[_\s-]?id|member[_\s-]?id|record[_\s-]?id|case[_\s-]?(?:id|number|no\.?)|client[_\s-]?id|profile[_\s-]?id|uid|guid)["'\s]{0,4}[:=]["'\s]{0,4}([A-Za-z0-9][A-Za-z0-9._-]{2,48})/gi,
  group: 1,
  baseConfidence: Confidence.STRONG,
  description: 'an identifier the document labels as a user, account, or case reference',
  normalize: (value) => value.toUpperCase(),
};

export const peoplePack: PatternPack = {
  id: 'people',
  version: '1.0.0',
  rules: [honorific, labelled, slashName, surnameFirst, organisation, recordId, employeeId] satisfies PatternRule[],
};

export const peopleRules = { honorific, labelled, slashName, surnameFirst, organisation, recordId, employeeId };
