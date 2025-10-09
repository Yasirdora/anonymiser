/**
 * A four-tier commercial classification scheme.
 *
 * The shape most organisations converge on independently. Included so that a
 * team with no marking system at all gets something workable out of the box
 * rather than being asked to author a policy before they can redact a document.
 */

import type { ClassificationPolicy } from '../types.js';

export const corporatePolicy: ClassificationPolicy = {
  id: 'corporate',
  version: '1.0.0',
  name: 'Corporate Information Classification',
  authority: 'ISO/IEC 27001 A.5.12; ISO/IEC 27002:2022 5.12',
  description: 'A four-tier commercial scheme with need-to-know and legal-privilege caveats.',

  levels: [
    { id: 'public', name: 'PUBLIC', abbreviation: 'P', rank: 0, tone: 'neutral', description: 'Approved for unrestricted release.' },
    { id: 'internal', name: 'INTERNAL', abbreviation: 'I', rank: 10, tone: 'notice', description: 'For employees and contractors. Disclosure would cause minor harm.' },
    { id: 'confidential', name: 'CONFIDENTIAL', abbreviation: 'C', rank: 20, tone: 'warning', description: 'Need-to-know. Disclosure would cause material commercial or personal harm.' },
    { id: 'restricted', name: 'RESTRICTED', abbreviation: 'R', rank: 30, tone: 'critical', description: 'Severely limited distribution. Disclosure would cause severe or irreversible harm.' },
  ],

  groups: [
    {
      id: 'caveat',
      name: 'Handling Caveat',
      combine: 'union',
      order: 1,
      valueSeparator: '/',
      values: [
        { id: 'privileged', name: 'ATTORNEY-CLIENT PRIVILEGED', abbreviation: 'PRIV', description: 'Legal professional privilege applies; disclosure may waive it.' },
        { id: 'personal-data', name: 'PERSONAL DATA', abbreviation: 'PD', description: 'Contains data about identifiable individuals.' },
        { id: 'trade-secret', name: 'TRADE SECRET', abbreviation: 'TS', description: 'Derives commercial value from not being generally known.' },
        { id: 'material-nonpublic', name: 'MATERIAL NON-PUBLIC', abbreviation: 'MNPI', description: 'Insider information; trading on it is unlawful.' },
        {
          id: 'no-external',
          name: 'NO EXTERNAL DISTRIBUTION',
          abbreviation: 'NOEXT',
          description: 'Must not leave the organisation.',
          dominates: ['partners', 'customers'],
        },
      ],
    },
    {
      id: 'audience',
      name: 'Shareable With',
      combine: 'intersection',
      order: 2,
      prefix: 'SHARE ',
      valueSeparator: ', ',
      defaultValues: ['internal-staff'],
      values: [
        { id: 'internal-staff', name: 'STAFF', abbreviation: 'STAFF', description: 'Employees and contractors under a confidentiality obligation.' },
        { id: 'partners', name: 'PARTNERS', abbreviation: 'PTNR', description: 'Named partners under a non-disclosure agreement.' },
        { id: 'customers', name: 'CUSTOMERS', abbreviation: 'CUST', description: 'Customers under the terms of their agreement.' },
      ],
    },
  ],

  rules: [
    {
      id: 'corp.personal-data',
      description: 'Personal data about staff or customers is confidential',
      authority: 'ISO/IEC 27002:2022 5.34; applicable data protection law',
      when: { entityTypes: ['person.*', 'contact.*', 'gov.*'], minConfidence: 0.6 },
      assert: { level: 'confidential', markings: { caveat: ['personal-data'] } },
    },
    {
      id: 'corp.financial',
      description: 'Account and payment identifiers are confidential and not externally shareable',
      authority: 'PCI-DSS requirement 3; ISO/IEC 27002:2022 5.12',
      when: { entityTypes: ['financial.*'], minConfidence: 0.7 },
      assert: { level: 'confidential', markings: { caveat: ['personal-data', 'no-external'] } },
    },
    {
      id: 'corp.credentials',
      description: 'Credentials and keys are restricted regardless of what they protect',
      authority: 'ISO/IEC 27002:2022 5.17',
      when: { entityTypes: ['secret.*'], minConfidence: 0.7 },
      assert: { level: 'restricted', markings: { caveat: ['no-external'] } },
    },
    {
      id: 'corp.infrastructure',
      description: 'Internal hostnames and addresses describe the estate and are internal at minimum',
      authority: 'ISO/IEC 27002:2022 5.9',
      when: { entityTypes: ['net.hostname', 'net.ipv4', 'net.ipv6', 'net.mac'], minConfidence: 0.7 },
      assert: { level: 'internal', markings: { caveat: ['no-external'] } },
    },
    {
      id: 'corp.privilege',
      description: 'A privilege assertion in the document is honoured as a caveat',
      authority: 'Attorney-client privilege; work product doctrine',
      when: { entityTypes: ['marking.banner'], minConfidence: 0.8 },
      assert: { level: 'confidential' },
    },
    {
      id: 'corporate.operator-marked',
      description: 'An operator reviewing this document marked this for removal',
      authority: 'Operator determination during review',
      when: { entityTypes: ['manual.marked'] },
      assert: { level: 'confidential', markings: { caveat: ['no-external'] } },
    },
  ],

  mosaic: [
    {
      id: 'mosaic.employee-record',
      description: 'A name, an employee identifier, and a contact point together form an HR record',
      types: ['person.name', 'org.employee-id', 'contact.*', 'person.dob'],
      threshold: 3,
      scope: 'portion',
      assert: { level: 'confidential', markings: { caveat: ['personal-data', 'no-external'] } },
      authority: 'ISO/IEC 27002:2022 5.34',
    },
  ],

  defaultLevel: 'internal',

  banner: {
    segmentSeparator: ' // ',
    portionDelimiters: ['(', ')'],
    bannerUsesFullName: true,
    uppercase: true,
  },
};
