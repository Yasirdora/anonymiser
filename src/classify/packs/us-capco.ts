/**
 * United States classification and control markings.
 *
 * Modelled on the ODNI/CAPCO register and the NARA CUI registry. The vocabulary
 * here is a working subset, not the complete register: compartments and their
 * sub-controls change, several are themselves classified, and an engine that
 * silently accepted an out-of-date list would be worse than one that reports
 * what it does not recognise. Unknown segments surface as `unparsed-marking`
 * warnings, and organisations extend the pack with their own values.
 *
 * The classification rules deliberately stop at CUI. Whether information is
 * national security information under EO 13526 is an original classification
 * decision reserved to a human with the authority to make it, and no pattern
 * match can substitute for that. What the engine can do -- and does here -- is
 * recognise the CUI categories that follow mechanically from the presence of
 * privacy, health, or law-enforcement information.
 */

import type { ClassificationPolicy } from '../types.js';

export const usCapcoPolicy: ClassificationPolicy = {
  id: 'us-capco',
  version: '1.0.0',
  name: 'US Classification and Control Markings',
  authority: 'ODNI/CAPCO register; 32 CFR 2002 (CUI); EO 13526',
  description:
    'US Intelligence Community banner and portion marking grammar, with CUI categories derived from detected content.',

  levels: [
    {
      id: 'unclassified',
      name: 'UNCLASSIFIED',
      abbreviation: 'U',
      rank: 0,
      tone: 'neutral',
      description: 'No classification or control markings apply.',
    },
    {
      id: 'cui',
      name: 'CUI',
      abbreviation: 'CUI',
      rank: 10,
      tone: 'notice',
      description:
        'Controlled Unclassified Information: unclassified but subject to safeguarding or dissemination controls under law or policy.',
    },
    {
      id: 'confidential',
      name: 'CONFIDENTIAL',
      abbreviation: 'C',
      rank: 20,
      tone: 'caution',
      description:
        'Unauthorised disclosure could reasonably be expected to cause damage to national security.',
    },
    {
      id: 'secret',
      name: 'SECRET',
      abbreviation: 'S',
      rank: 30,
      tone: 'warning',
      description:
        'Unauthorised disclosure could reasonably be expected to cause serious damage to national security.',
    },
    {
      id: 'top-secret',
      name: 'TOP SECRET',
      abbreviation: 'TS',
      rank: 40,
      tone: 'critical',
      description:
        'Unauthorised disclosure could reasonably be expected to cause exceptionally grave damage to national security.',
    },
  ],

  groups: [
    {
      id: 'sci',
      name: 'Sensitive Compartmented Information',
      combine: 'union',
      order: 1,
      valueSeparator: '/',
      values: [
        { id: 'si', name: 'SI', abbreviation: 'SI', description: 'Special Intelligence.', minimumLevel: 'confidential' },
        { id: 'tk', name: 'TK', abbreviation: 'TK', description: 'Talent Keyhole.', minimumLevel: 'confidential' },
        { id: 'hcs', name: 'HCS', abbreviation: 'HCS', description: 'HUMINT Control System.', minimumLevel: 'confidential' },
        { id: 'kdk', name: 'KDK', abbreviation: 'KDK', description: 'Klondike.', minimumLevel: 'confidential' },
      ],
    },
    {
      id: 'cui-category',
      name: 'CUI Category',
      combine: 'union',
      order: 2,
      valueSeparator: '/',
      values: [
        { id: 'sp-prvcy', name: 'SP-PRVCY', abbreviation: 'PRVCY', description: 'Privacy information.', minimumLevel: 'cui' },
        { id: 'sp-hlth', name: 'SP-HLTH', abbreviation: 'HLTH', description: 'Health information.', minimumLevel: 'cui' },
        { id: 'sp-propin', name: 'SP-PROPIN', abbreviation: 'PROPIN', description: 'Proprietary business information.', minimumLevel: 'cui' },
        { id: 'sp-lei', name: 'SP-LEI', abbreviation: 'LEI', description: 'Law enforcement sensitive.', minimumLevel: 'cui' },
        { id: 'sp-tax', name: 'SP-TAX', abbreviation: 'TAX', description: 'Federal taxpayer information.', minimumLevel: 'cui' },
        { id: 'sp-opsec', name: 'SP-OPSEC', abbreviation: 'OPSEC', description: 'Operations security information.', minimumLevel: 'cui' },
      ],
    },
    {
      id: 'dissemination',
      name: 'Dissemination Controls',
      combine: 'union',
      order: 3,
      valueSeparator: '/',
      values: [
        {
          id: 'noforn',
          name: 'NOFORN',
          abbreviation: 'NF',
          description: 'Not releasable to foreign nationals.',
          // A single NOFORN portion makes the whole document non-releasable,
          // whatever the other portions permit. This is the specific rule that
          // hand-rolled marking tools get wrong.
          dominates: ['usa', 'fvey', 'nato', 'aus', 'can', 'gbr', 'nzl'],
        },
        { id: 'orcon', name: 'ORCON', abbreviation: 'OC', description: 'Dissemination and extraction controlled by originator.' },
        { id: 'propin', name: 'PROPIN', abbreviation: 'PR', description: 'Caution: proprietary information involved.' },
        { id: 'relido', name: 'RELIDO', abbreviation: 'RELIDO', description: 'Releasable by information disclosure official.' },
        { id: 'imcon', name: 'IMCON', abbreviation: 'IMC', description: 'Controlled imagery.' },
        { id: 'fisa', name: 'FISA', abbreviation: 'FISA', description: 'Foreign Intelligence Surveillance Act information.' },
        { id: 'fedcon', name: 'FED ONLY', abbreviation: 'FEDCON', description: 'Federal employees only.' },
        { id: 'nocontract', name: 'NOCONTRACT', abbreviation: 'NC', description: 'Not releasable to contractors.' },
      ],
    },
    {
      id: 'releasable',
      name: 'Releasable To',
      // Releasability is a permission, so it narrows as portions are combined.
      combine: 'intersection',
      order: 4,
      prefix: 'REL TO ',
      valueSeparator: ', ',
      // A portion with no releasability marking is releasable to the United
      // States alone. Without this default the roll-up would treat silence as
      // consent and produce a banner more permissive than its content.
      defaultValues: ['usa'],
      values: [
        { id: 'usa', name: 'USA', abbreviation: 'USA', description: 'United States.' },
        {
          id: 'fvey',
          name: 'FVEY',
          abbreviation: 'FVEY',
          description: 'Five Eyes partners.',
          expandsTo: ['usa', 'aus', 'can', 'gbr', 'nzl'],
        },
        { id: 'nato', name: 'NATO', abbreviation: 'NATO', description: 'NATO member nations.' },
        { id: 'aus', name: 'AUS', abbreviation: 'AUS', description: 'Australia.' },
        { id: 'can', name: 'CAN', abbreviation: 'CAN', description: 'Canada.' },
        { id: 'gbr', name: 'GBR', abbreviation: 'GBR', description: 'United Kingdom.' },
        { id: 'nzl', name: 'NZL', abbreviation: 'NZL', description: 'New Zealand.' },
      ],
    },
  ],

  rules: [
    {
      id: 'cui.privacy',
      description: 'Personally identifiable information is CUI under the Privacy category',
      authority: '32 CFR 2002; NARA CUI Registry, Privacy category',
      when: {
        entityTypes: ['person.*', 'contact.*', 'gov.ssn', 'gov.tax-id', 'gov.passport', 'gov.driver-license', 'gov.national-id', 'gov.mrz'],
        minConfidence: 0.6,
      },
      assert: { level: 'cui', markings: { 'cui-category': ['sp-prvcy'] } },
    },
    {
      id: 'cui.health',
      description: 'Health identifiers and conditions are CUI under the Health category',
      authority: 'NARA CUI Registry, Health Information category; 45 CFR 164.514',
      when: { entityTypes: ['health.*'], minConfidence: 0.6 },
      assert: { level: 'cui', markings: { 'cui-category': ['sp-hlth'] } },
    },
    {
      id: 'cui.tax',
      description: 'Taxpayer identifiers are CUI under the Tax category',
      authority: 'NARA CUI Registry, Tax category; 26 USC 6103',
      when: { entityTypes: ['gov.tax-id'], minConfidence: 0.6 },
      assert: { level: 'cui', markings: { 'cui-category': ['sp-tax'] } },
    },
    {
      id: 'cui.financial',
      description: 'Account and payment identifiers warrant privacy controls',
      authority: 'NARA CUI Registry, Privacy category; PCI-DSS 3.4',
      when: { entityTypes: ['financial.*'], minConfidence: 0.7 },
      assert: { level: 'cui', markings: { 'cui-category': ['sp-prvcy'] } },
    },
    {
      id: 'cui.opsec',
      description: 'Credentials and internal infrastructure detail are operations security information',
      authority: 'NARA CUI Registry, OPSEC category',
      when: { entityTypes: ['secret.*', 'net.hostname', 'net.ipv4', 'net.ipv6'], minConfidence: 0.7 },
      assert: { level: 'cui', markings: { 'cui-category': ['sp-opsec'] } },
    },
    {
      id: 'dissem.propin',
      description: 'Proprietary business information carries the PROPIN caution',
      authority: 'CAPCO register, PROPIN',
      when: { entityTypes: ['org.*'], minConfidence: 0.7 },
      assert: { level: 'cui', markings: { 'cui-category': ['sp-propin'], dissemination: ['propin'] } },
    },
    {
      id: 'us-capco.operator-marked',
      description: 'An operator reviewing this document marked this for removal',
      authority: 'Operator determination during review',
      when: { entityTypes: ['manual.marked'] },
      assert: { level: 'cui', markings: { 'cui-category': ['sp-prvcy'] } },
    },
  ],

  mosaic: [
    {
      id: 'mosaic.hipaa-quasi-identifiers',
      description:
        'Date of birth, sex, and postcode together identify most individuals, even with names removed',
      types: ['person.dob', 'geo.postcode', 'person.age', 'contact.address'],
      threshold: 2,
      scope: 'portion',
      assert: { level: 'cui', markings: { 'cui-category': ['sp-prvcy'] } },
      authority: 'Sweeney (2000), Simple Demographics Often Identify People Uniquely; 45 CFR 164.514(b)',
    },
    {
      id: 'mosaic.identity-dossier',
      description:
        'A name, a government identifier, and a contact point in one document constitute an identity dossier',
      types: ['person.name', 'gov.*', 'contact.email', 'contact.phone', 'contact.address'],
      threshold: 3,
      scope: 'document',
      assert: { level: 'cui', markings: { 'cui-category': ['sp-prvcy'] } },
      authority: 'NIST SP 800-122, linkability of PII',
    },
  ],

  defaultLevel: 'unclassified',

  banner: {
    segmentSeparator: '//',
    portionDelimiters: ['(', ')'],
    bannerUsesFullName: true,
    uppercase: true,
  },
};
