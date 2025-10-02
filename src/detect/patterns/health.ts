/**
 * Health identifiers and clinical indicators.
 *
 * HIPAA's Safe Harbor method enumerates eighteen identifier classes that must
 * be removed before a data set counts as de-identified. Several of them look
 * entirely innocuous in isolation, which is why they survive manual review and
 * why they are worth detecting mechanically.
 */

import type { PatternPack, PatternRule } from '../pattern.js';
import { Confidence } from '../types.js';
import { nhsNumber, stripSeparators } from '../validators.js';

const nhs: PatternRule = {
  id: 'health.nhs-number',
  type: 'health.record-number',
  pattern: /(?<![\d-])\d{3}[ -]?\d{3}[ -]?\d{4}(?![\d-])/g,
  baseConfidence: Confidence.WEAK,
  description: 'an NHS number',
  validate: (value) =>
    nhsNumber(value)
      ? { ok: true, signal: 'checksum:nhs-mod11', note: 'passes the NHS mod-11 check digit', weight: 0.35 }
      : { ok: false, signal: 'checksum:nhs-mod11', note: 'fails the NHS mod-11 check digit' },
  normalize: (value) => stripSeparators(value),
  locales: ['en-GB'],
};

const medicareBeneficiary: PatternRule = {
  id: 'health.medicare.mbi',
  type: 'health.insurance-id',
  pattern:
    /(?<![A-Z0-9])[1-9][ACDEFGHJKMNPQRTUVWXY][AC-HJKMNP-RT-Y\d]\d[ACDEFGHJKMNPQRTUVWXY][AC-HJKMNP-RT-Y\d]\d[ACDEFGHJKMNPQRTUVWXY]{2}\d{2}(?![A-Z0-9])/g,
  baseConfidence: Confidence.STRONG,
  description: 'a Medicare Beneficiary Identifier',
  normalize: (value) => value.toUpperCase(),
  locales: ['en-US'],
};

/**
 * Medical record numbers have no national format, so this is context-only.
 * The label is almost always present in clinical documents.
 */
const medicalRecordNumber: PatternRule = {
  id: 'health.record-number.generic',
  type: 'health.record-number',
  pattern: /(?<![A-Z0-9-])[A-Z]{0,3}[-]?\d{5,12}(?![A-Z0-9-])/gi,
  baseConfidence: Confidence.HINT,
  description: 'an identifier labelled as a medical record number',
  normalize: (value) => stripSeparators(value).toUpperCase(),
  context: {
    supports: ['mrn', 'medical record', 'patient id', 'patient no', 'chart no', 'chart number', 'hospital number', 'nhs no', 'encounter'],
    requireSupport: true,
    supportWeight: 0.35,
  },
};

const insuranceMember: PatternRule = {
  id: 'health.insurance-id.member',
  type: 'health.insurance-id',
  pattern: /(?<![A-Z0-9-])[A-Z]{2,4}\d{6,12}(?![A-Z0-9-])/g,
  baseConfidence: Confidence.HINT,
  description: 'an identifier labelled as a health insurance member number',
  normalize: (value) => value.toUpperCase(),
  context: {
    supports: ['member id', 'member no', 'policy', 'subscriber', 'insurance', 'plan id', 'group number', 'payer'],
    requireSupport: true,
    supportWeight: 0.35,
  },
};

/**
 * Named conditions.
 *
 * A short, deliberately conservative list. Detecting arbitrary diagnoses needs
 * a clinical vocabulary, which does not belong in a zero-dependency core; a
 * caller with SNOMED or ICD-10 to hand supplies it as a custom detector. What
 * is here covers the conditions whose mere mention is legally special-cased in
 * several jurisdictions, so missing them is a compliance failure rather than a
 * quality shortfall.
 */
const sensitiveCondition: PatternRule = {
  id: 'health.condition.sensitive',
  type: 'health.condition',
  pattern:
    /\b(?:HIV(?:[/-]AIDS)?|AIDS|hepatitis\s?[ABC]|tuberculosis|schizophreni[ac]|bipolar\s+disorder|major\s+depressive\s+disorder|substance\s+(?:use|abuse)\s+disorder|opioid\s+dependence|alcohol\s+dependence|sickle\s+cell(?:\s+(?:disease|anaemia|anemia|trait))?|Huntington'?s?\s+disease|gender\s+dysphoria|termination\s+of\s+pregnancy|type\s?[12]\s+diabetes(?:\s+mellitus)?|diabetes\s+mellitus|epilepsy|multiple\s+sclerosis|cystic\s+fibrosis|sexually\s+transmitted\s+(?:infection|disease))\b/gi,
  baseConfidence: Confidence.LIKELY,
  description: 'a named condition whose disclosure is separately regulated in many jurisdictions',
  normalize: (value) => value.toLowerCase().replace(/\s+/g, ' '),
  context: {
    suppresses: ['policy', 'guideline', 'training', 'awareness', 'campaign', 'research funding'],
  },
};

/**
 * A health identifier behind its label.
 *
 * The NHS rule above drops a number whose mod-11 check fails, which is right on
 * shape alone. It is wrong when the document says "NHS Number:" -- a test or
 * mistyped number in a clinical record is still the field that identifies the
 * patient, and skipping it because the check digit failed leaves it in the
 * release. Same reasoning as the labelled SSN and IBAN rules.
 */
const healthIdLabelled: PatternRule = {
  id: 'health.record-number.labelled',
  type: 'health.record-number',
  pattern:
    /(?:NHS\s*(?:Number|No\.?|#)?|Medical\s+Record\s*(?:Number|No\.?|#)?|MRN|Patient\s*(?:ID|Number|No\.?|#)|Chart\s*(?:Number|No\.?|#)|Hospital\s*(?:Number|No\.?|#))[^\S\n]{0,4}[:#=][^\S\n]{0,4}([A-Z0-9][A-Z0-9 .-]{4,24}[A-Z0-9])/gi,
  group: 1,
  baseConfidence: Confidence.VERIFIED,
  description: 'a value the document labels as a patient or medical record number',
  normalize: (value) => stripSeparators(value).toUpperCase(),
};

/**
 * ICD-10 diagnosis codes.
 *
 * A diagnosis expressed as a code is exactly as identifying as one expressed in
 * words, and far easier to miss: `B20` is HIV disease, `E10.9` is type 1
 * diabetes. A release that redacts "HIV" and leaves "(B20)" standing beside it
 * has disclosed the diagnosis.
 */
const icd10: PatternRule = {
  id: 'health.condition.icd10',
  type: 'health.condition',
  pattern: /(?<![A-Z0-9.])[A-TV-Z]\d{2}(?:\.[A-Z0-9]{1,4})?(?![A-Z0-9.])/g,
  baseConfidence: Confidence.WEAK,
  description: 'an ICD-10 diagnosis code',
  normalize: (value) => value.toUpperCase(),
  context: {
    // A secondary code is written in the middle of a clinical note -- "Patient is
    // HIV+ (B20)" -- with no billing vocabulary anywhere near it, so the cue set
    // has to include the words that surround ordinary clinical writing.
    supports: [
      'icd', 'icd-10', 'icd10', 'diagnosis', 'diagnosed', 'diagnostic', 'dx', 'code', 'coded',
      'condition', 'billing', 'patient', 'clinical', 'notes', 'admitted', 'treatment', 'history',
    ],
    requireSupport: true,
    supportWeight: 0.35,
  },
};

export const healthPack: PatternPack = {
  id: 'health',
  version: '1.0.0',
  rules: [healthIdLabelled, icd10, nhs, medicareBeneficiary, medicalRecordNumber, insuranceMember, sensitiveCondition] satisfies PatternRule[],
};

export const healthRules = {
  healthIdLabelled,
  icd10,
  nhs,
  medicareBeneficiary,
  medicalRecordNumber,
  insuranceMember,
  sensitiveCondition,
};
