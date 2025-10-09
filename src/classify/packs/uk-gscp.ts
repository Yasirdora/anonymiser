/**
 * UK Government Security Classifications Policy.
 *
 * Three tiers rather than the US four, with handling instructions carried in a
 * `-SENSITIVE` suffix and descriptors in square brackets. The descriptor set is
 * open by design in the GSCP, so the values here are the commonly used ones and
 * organisations add their own.
 */

import type { ClassificationPolicy } from '../types.js';

export const ukGscpPolicy: ClassificationPolicy = {
  id: 'uk-gscp',
  version: '1.0.0',
  name: 'UK Government Security Classifications',
  authority: 'UK Cabinet Office, Government Security Classifications Policy',
  description:
    'Three-tier UK classification with sensitivity markers, handling descriptors, and national caveats.',

  levels: [
    {
      id: 'official',
      name: 'OFFICIAL',
      abbreviation: 'O',
      rank: 10,
      tone: 'notice',
      description:
        'The majority of routine government business. Compromise would have limited damaging consequences.',
    },
    {
      id: 'official-sensitive',
      name: 'OFFICIAL-SENSITIVE',
      abbreviation: 'OS',
      rank: 15,
      tone: 'caution',
      description:
        'OFFICIAL information where a limited number of people need access and compromise would cause more damage.',
    },
    {
      id: 'secret',
      name: 'SECRET',
      abbreviation: 'S',
      rank: 30,
      tone: 'warning',
      description:
        'Very sensitive information requiring heightened protection against determined and capable threat actors.',
    },
    {
      id: 'top-secret',
      name: 'TOP SECRET',
      abbreviation: 'TS',
      rank: 40,
      tone: 'critical',
      description:
        'The most sensitive information, requiring the highest levels of protection from the most serious threats.',
    },
  ],

  groups: [
    {
      id: 'descriptor',
      name: 'Handling Descriptor',
      combine: 'union',
      order: 1,
      prefix: '[',
      suffix: ']',
      valueSeparator: ', ',
      values: [
        { id: 'commercial', name: 'COMMERCIAL', abbreviation: 'COMM', description: 'Commercial or market-sensitive information.' },
        { id: 'personal', name: 'PERSONAL', abbreviation: 'PERS', description: 'Personal data about identifiable individuals.' },
        { id: 'legal', name: 'LEGAL', abbreviation: 'LEGAL', description: 'Legal professional privilege applies.' },
        { id: 'locsen', name: 'LOCSEN', abbreviation: 'LOCSEN', description: 'Sensitive to local staff or partners.' },
        { id: 'health', name: 'MEDICAL', abbreviation: 'MED', description: 'Medical or health information.' },
      ],
    },
    {
      id: 'caveat',
      name: 'National Caveat',
      combine: 'union',
      order: 2,
      valueSeparator: '/',
      values: [
        {
          id: 'uk-eyes-only',
          name: 'UK EYES ONLY',
          abbreviation: 'UKEO',
          description: 'Access restricted to UK nationals.',
          dominates: ['gbr', 'fvey', 'nato'],
          minimumLevel: 'secret',
        },
        { id: 'handling-instruction', name: 'HANDLING INSTRUCTIONS APPLY', abbreviation: 'HI', description: 'Additional handling instructions accompany this material.' },
      ],
    },
    {
      id: 'releasable',
      name: 'Releasable To',
      combine: 'intersection',
      order: 3,
      prefix: 'REL ',
      valueSeparator: ', ',
      defaultValues: ['gbr'],
      values: [
        { id: 'gbr', name: 'GBR', abbreviation: 'GBR', description: 'United Kingdom.' },
        { id: 'fvey', name: 'FVEY', abbreviation: 'FVEY', description: 'Five Eyes partners.' },
        { id: 'nato', name: 'NATO', abbreviation: 'NATO', description: 'NATO member nations.' },
      ],
    },
  ],

  rules: [
    {
      id: 'gscp.personal-data',
      description: 'Personal data attracts the PERSONAL descriptor at OFFICIAL-SENSITIVE',
      authority: 'GSCP paragraph 22; UK GDPR Article 4(1)',
      when: {
        entityTypes: ['person.*', 'contact.*', 'gov.national-id', 'gov.passport', 'gov.driver-license'],
        minConfidence: 0.6,
      },
      assert: { level: 'official-sensitive', markings: { descriptor: ['personal'] } },
    },
    {
      id: 'gscp.special-category',
      description: 'Health data is special category personal data and attracts the MEDICAL descriptor',
      authority: 'UK GDPR Article 9; GSCP handling descriptors',
      when: { entityTypes: ['health.*'], minConfidence: 0.6 },
      assert: { level: 'official-sensitive', markings: { descriptor: ['personal', 'health'] } },
    },
    {
      id: 'gscp.commercial',
      description: 'Financial and account detail attracts the COMMERCIAL descriptor',
      authority: 'GSCP handling descriptors',
      when: { entityTypes: ['financial.*'], minConfidence: 0.7 },
      assert: { level: 'official-sensitive', markings: { descriptor: ['commercial'] } },
    },
    {
      id: 'gscp.credentials',
      description: 'Live credentials require protection beyond routine OFFICIAL handling',
      authority: 'GSCP paragraph 22; NCSC guidance on secrets management',
      when: { entityTypes: ['secret.*'], minConfidence: 0.7 },
      assert: { level: 'official-sensitive' },
    },
    {
      id: 'uk-gscp.operator-marked',
      description: 'An operator reviewing this document marked this for removal',
      authority: 'Operator determination during review',
      when: { entityTypes: ['manual.marked'] },
      assert: { level: 'official-sensitive', markings: { descriptor: ['personal'] } },
    },
  ],

  mosaic: [
    {
      id: 'mosaic.uk-quasi-identifiers',
      description: 'Postcode, date of birth, and address combine to identify individuals',
      types: ['geo.postcode', 'person.dob', 'contact.address', 'person.name'],
      threshold: 2,
      scope: 'portion',
      assert: { level: 'official-sensitive', markings: { descriptor: ['personal'] } },
      authority: 'ICO Anonymisation Code of Practice, motivated intruder test',
    },
  ],

  defaultLevel: 'official',

  banner: {
    segmentSeparator: ' ',
    portionDelimiters: ['(', ')'],
    bannerUsesFullName: true,
    uppercase: true,
  },
};
