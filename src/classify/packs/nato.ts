/**
 * NATO classification markings.
 *
 * Four levels plus the ATOMAL compartment for atomic information, and the
 * COSMIC prefix carried by NATO's highest level. Releasability narrows to
 * named nations exactly as in the US scheme, so the same intersection semantics
 * apply.
 */

import type { ClassificationPolicy } from '../types.js';

export const natoPolicy: ClassificationPolicy = {
  id: 'nato',
  version: '1.0.0',
  name: 'NATO Security Markings',
  authority: 'C-M(2002)49, Security within the North Atlantic Treaty Organisation',
  description: 'NATO four-level classification with ATOMAL compartments and national releasability.',

  levels: [
    { id: 'nato-unclassified', name: 'NATO UNCLASSIFIED', abbreviation: 'NU', rank: 0, tone: 'neutral', description: 'Official NATO information not requiring classification.' },
    { id: 'nato-restricted', name: 'NATO RESTRICTED', abbreviation: 'NR', rank: 10, tone: 'notice', description: 'Disclosure would be disadvantageous to NATO interests.' },
    { id: 'nato-confidential', name: 'NATO CONFIDENTIAL', abbreviation: 'NC', rank: 20, tone: 'caution', description: 'Disclosure would damage NATO interests.' },
    { id: 'nato-secret', name: 'NATO SECRET', abbreviation: 'NS', rank: 30, tone: 'warning', description: 'Disclosure would seriously damage NATO interests.' },
    { id: 'cosmic-top-secret', name: 'COSMIC TOP SECRET', abbreviation: 'CTS', rank: 40, tone: 'critical', description: 'Disclosure would cause exceptionally grave damage to NATO.' },
  ],

  groups: [
    {
      id: 'compartment',
      name: 'Compartment',
      combine: 'union',
      order: 1,
      valueSeparator: '/',
      values: [
        { id: 'atomal', name: 'ATOMAL', abbreviation: 'A', description: 'US or UK atomic information released to NATO.', minimumLevel: 'nato-confidential' },
        { id: 'bohemia', name: 'BOHEMIA', abbreviation: 'BOH', description: 'Signals intelligence compartment.', minimumLevel: 'nato-secret' },
      ],
    },
    {
      id: 'dissemination',
      name: 'Dissemination Controls',
      combine: 'union',
      order: 2,
      valueSeparator: '/',
      values: [
        {
          id: 'nato-eyes-only',
          name: 'NATO EYES ONLY',
          abbreviation: 'NEO',
          description: 'Restricted to NATO member nations.',
          dominates: ['pfp', 'ico'],
        },
        { id: 'releasable-internet', name: 'RELEASABLE TO THE INTERNET', abbreviation: 'RELINT', description: 'Approved for publication on the open internet.' },
      ],
    },
    {
      id: 'releasable',
      name: 'Releasable To',
      combine: 'intersection',
      order: 3,
      prefix: 'REL ',
      valueSeparator: ', ',
      defaultValues: ['nato-nations'],
      values: [
        { id: 'nato-nations', name: 'NATO', abbreviation: 'NATO', description: 'All NATO member nations.' },
        { id: 'pfp', name: 'PFP', abbreviation: 'PFP', description: 'Partnership for Peace nations.' },
        { id: 'ico', name: 'ISAF COALITION', abbreviation: 'ICO', description: 'Coalition partner nations.' },
      ],
    },
  ],

  rules: [
    {
      id: 'nato.personal-data',
      description: 'Personal data about personnel is restricted at minimum',
      authority: 'C-M(2002)49 Enclosure E; applicable national data protection law',
      when: { entityTypes: ['person.*', 'contact.*', 'gov.*'], minConfidence: 0.6 },
      assert: { level: 'nato-restricted' },
    },
    {
      id: 'nato.credentials',
      description: 'Credentials for NATO systems are confidential at minimum',
      authority: 'C-M(2002)49 Enclosure F, INFOSEC',
      when: { entityTypes: ['secret.*'], minConfidence: 0.7 },
      assert: { level: 'nato-confidential', markings: { dissemination: ['nato-eyes-only'] } },
    },
    {
      id: 'nato.locations',
      description: 'Precise coordinates may disclose the location of installations or forces',
      authority: 'C-M(2002)49 Enclosure C',
      when: { entityTypes: ['geo.coordinates'], minConfidence: 0.7 },
      assert: { level: 'nato-restricted' },
    },
    {
      id: 'nato.operator-marked',
      description: 'An operator reviewing this document marked this for removal',
      authority: 'Operator determination during review',
      when: { entityTypes: ['manual.marked'] },
      assert: { level: 'nato-restricted', markings: {} },
    },
  ],

  mosaic: [],

  defaultLevel: 'nato-unclassified',

  banner: {
    segmentSeparator: '//',
    portionDelimiters: ['(', ')'],
    bannerUsesFullName: true,
    uppercase: true,
  },
};
