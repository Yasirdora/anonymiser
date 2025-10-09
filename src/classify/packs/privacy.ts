/**
 * A privacy-regulation policy for organisations with no formal classification
 * scheme: universities, newsrooms, hospitals, NGOs, and research groups.
 *
 * The levels track regulatory consequence rather than national security damage.
 * That is the right axis for this audience: a researcher preparing a dataset
 * for release does not need to know whether something is CONFIDENTIAL, they
 * need to know whether releasing it breaches Article 9 of the GDPR or the HIPAA
 * Safe Harbor rule, and what to do about it.
 *
 * Every rule cites the provision it implements, so the redaction log doubles as
 * the record of processing that these regimes require anyway.
 */

import type { ClassificationPolicy } from '../types.js';

export const privacyPolicy: ClassificationPolicy = {
  id: 'privacy',
  version: '1.0.0',
  name: 'Privacy and Data Protection',
  authority: 'EU/UK GDPR; HIPAA Privacy Rule (45 CFR 164); NIST SP 800-122',
  description:
    'Sensitivity tiers derived from data protection law, for research, journalism, and clinical release workflows.',

  levels: [
    {
      id: 'open',
      name: 'OPEN',
      abbreviation: 'O',
      rank: 0,
      tone: 'neutral',
      description: 'Contains no personal data. Publishable without further review.',
    },
    {
      id: 'personal',
      name: 'PERSONAL DATA',
      abbreviation: 'PD',
      rank: 20,
      tone: 'caution',
      description:
        'Contains data relating to identifiable individuals. Processing requires a lawful basis and disclosure requires assessment.',
    },
    {
      id: 'special-category',
      name: 'SPECIAL CATEGORY',
      abbreviation: 'SC',
      rank: 30,
      tone: 'warning',
      description:
        'Contains health, biometric, genetic, or belief data, or data revealing them. Processing requires an Article 9 condition.',
    },
    {
      id: 'restricted',
      name: 'RESTRICTED',
      abbreviation: 'R',
      rank: 40,
      tone: 'critical',
      description:
        'Contains live credentials or data whose disclosure creates immediate risk to a person or system.',
    },
  ],

  groups: [
    {
      id: 'basis',
      name: 'Regulatory Basis',
      combine: 'union',
      order: 1,
      valueSeparator: '/',
      values: [
        { id: 'gdpr-art4', name: 'GDPR-ART4', abbreviation: 'A4', description: 'Personal data as defined in GDPR Article 4(1).' },
        { id: 'gdpr-art9', name: 'GDPR-ART9', abbreviation: 'A9', description: 'Special category data under GDPR Article 9(1).' },
        { id: 'gdpr-art10', name: 'GDPR-ART10', abbreviation: 'A10', description: 'Criminal conviction and offence data under Article 10.' },
        { id: 'hipaa-phi', name: 'HIPAA-PHI', abbreviation: 'PHI', description: 'Protected health information under 45 CFR 160.103.' },
        { id: 'pci-chd', name: 'PCI-CHD', abbreviation: 'CHD', description: 'Cardholder data under PCI-DSS.' },
        { id: 'ferpa', name: 'FERPA', abbreviation: 'FERPA', description: 'Student education records under 20 USC 1232g.' },
      ],
    },
    {
      id: 'handling',
      name: 'Handling',
      combine: 'union',
      order: 2,
      valueSeparator: '/',
      values: [
        {
          id: 'no-publish',
          name: 'DO NOT PUBLISH',
          abbreviation: 'NP',
          description: 'Must not be released in any form without a documented lawful basis.',
          dominates: ['aggregate-only', 'pseudonymized'],
        },
        { id: 'aggregate-only', name: 'AGGREGATE ONLY', abbreviation: 'AGG', description: 'Releasable only as statistics over a sufficient population.' },
        { id: 'pseudonymized', name: 'PSEUDONYMIZED', abbreviation: 'PSEUDO', description: 'Releasable once direct identifiers are replaced with stable tokens.' },
        { id: 'consent-required', name: 'CONSENT REQUIRED', abbreviation: 'CONSENT', description: 'Release requires the data subject\'s explicit consent.' },
      ],
    },
  ],

  rules: [
    {
      id: 'privacy.direct-identifier',
      description: 'Names and contact points are personal data',
      authority: 'GDPR Article 4(1); NIST SP 800-122 section 2.1',
      when: { entityTypes: ['person.name', 'contact.*'], minConfidence: 0.6 },
      assert: { level: 'personal', markings: { basis: ['gdpr-art4'], handling: ['pseudonymized'] } },
    },
    {
      id: 'privacy.government-identifier',
      description: 'Government-issued identifiers are direct identifiers and are not pseudonymisable in place',
      authority: 'GDPR Article 4(1); 45 CFR 164.514(b)(2)(i)',
      when: { entityTypes: ['gov.*'], minConfidence: 0.6 },
      assert: { level: 'personal', markings: { basis: ['gdpr-art4'], handling: ['no-publish'] } },
    },
    {
      id: 'privacy.health',
      description: 'Health identifiers and named conditions are special category data and protected health information',
      authority: 'GDPR Article 9(1); 45 CFR 160.103',
      when: { entityTypes: ['health.*'], minConfidence: 0.6 },
      assert: {
        level: 'special-category',
        markings: { basis: ['gdpr-art9', 'hipaa-phi'], handling: ['no-publish'] },
      },
    },
    {
      id: 'privacy.cardholder-data',
      description: 'Payment card numbers are cardholder data and may not be stored in released material',
      authority: 'PCI-DSS requirement 3',
      when: { entityTypes: ['financial.card'], minConfidence: 0.7 },
      assert: { level: 'personal', markings: { basis: ['pci-chd'], handling: ['no-publish'] } },
    },
    {
      id: 'privacy.financial',
      description: 'Bank and wallet identifiers link directly to an individual and enable fraud',
      authority: 'GDPR Article 4(1); GDPR Recital 75',
      when: { entityTypes: ['financial.*'], minConfidence: 0.7 },
      assert: { level: 'personal', markings: { basis: ['gdpr-art4'], handling: ['no-publish'] } },
    },
    {
      id: 'privacy.credentials',
      description: 'Live credentials create immediate risk and must never survive into a release',
      authority: 'GDPR Article 32; NIST SP 800-53 IA-5',
      when: { entityTypes: ['secret.*'], minConfidence: 0.7 },
      assert: { level: 'restricted', markings: { handling: ['no-publish'] } },
    },
    {
      id: 'privacy.precise-location',
      description: 'Precise coordinates and full postcodes are quasi-identifiers that resolve to a household',
      authority: 'GDPR Recital 26; 45 CFR 164.514(b)(2)(i)(B)',
      when: { entityTypes: ['geo.coordinates', 'geo.postcode'], minConfidence: 0.6 },
      assert: { level: 'personal', markings: { basis: ['gdpr-art4'], handling: ['aggregate-only'] } },
    },
    {
      id: 'privacy.locality',
      description: 'A city or town places a person below the level Safe Harbor permits to remain',
      authority: '45 CFR 164.514(b)(2)(i)(B); GDPR Recital 26',
      when: { entityTypes: ['geo.locality'], minConfidence: 0.6 },
      assert: { level: 'personal', markings: { basis: ['gdpr-art4', 'hipaa-phi'], handling: ['aggregate-only'] } },
    },
    {
      id: 'privacy.dates',
      description: 'Every date element more specific than a year is a Safe Harbor identifier',
      authority: '45 CFR 164.514(b)(2)(i)(C)',
      when: { entityTypes: ['temporal.date'], minConfidence: 0.6 },
      assert: { level: 'personal', markings: { basis: ['hipaa-phi'], handling: ['aggregate-only'] } },
    },
    {
      id: 'privacy.amounts',
      description: 'A transaction amount joins a record to a ledger row and re-identifies it',
      authority: 'GDPR Recital 26, singling out; Article 29 WP Opinion 05/2014',
      when: { entityTypes: ['financial.amount'], minConfidence: 0.7 },
      assert: { level: 'personal', markings: { basis: ['gdpr-art4'], handling: ['aggregate-only'] } },
    },
    {
      id: 'privacy.metadata',
      description: 'Authorship and device metadata identifies the originator even when the visible content does not',
      authority: 'GDPR Article 4(1); ICO guidance on document metadata',
      when: { entityTypes: ['risk.metadata'], minConfidence: 0.8 },
      assert: { level: 'personal', markings: { basis: ['gdpr-art4'], handling: ['no-publish'] } },
    },
    {
      id: 'privacy.operator-marked',
      description: 'An operator reviewing this document marked this for removal',
      authority: 'Operator determination during review',
      when: { entityTypes: ['manual.marked'] },
      assert: { level: 'personal', markings: { handling: ['no-publish'] } },
    },
  ],

  mosaic: [
    {
      id: 'mosaic.safe-harbor',
      description:
        'Two or more Safe Harbor identifiers in one passage defeat de-identification even with names removed',
      types: ['person.dob', 'geo.postcode', 'geo.locality', 'temporal.date', 'person.age', 'contact.address', 'health.record-number'],
      threshold: 2,
      scope: 'portion',
      assert: { level: 'special-category', markings: { basis: ['hipaa-phi'], handling: ['aggregate-only'] } },
      authority: '45 CFR 164.514(b)(2); Sweeney (2000)',
    },
    {
      id: 'mosaic.singling-out',
      description:
        'Enough quasi-identifiers are present across the document to single out an individual',
      types: ['person.name', 'person.dob', 'geo.postcode', 'contact.*', 'org.employee-id', 'health.*'],
      threshold: 3,
      scope: 'document',
      assert: { level: 'personal', markings: { handling: ['pseudonymized'] } },
      authority: 'GDPR Recital 26; Article 29 WP Opinion 05/2014 on anonymisation techniques',
    },
  ],

  defaultLevel: 'open',

  banner: {
    segmentSeparator: ' // ',
    portionDelimiters: ['[', ']'],
    bannerUsesFullName: true,
    uppercase: true,
  },
};
