/**
 * Network and infrastructure identifiers.
 *
 * These are rarely personal data on their own, but in an operational document
 * they map an internal estate, and in a research dataset an IP address is a
 * quasi-identifier under GDPR. Both cases are handled by the policy layer; this
 * pack only reports what is there.
 */

import type { PatternPack, PatternRule } from '../pattern.js';
import { Confidence } from '../types.js';
import { ipv4 } from '../validators.js';

/** Ranges that carry no disclosure risk and would otherwise dominate findings. */
function isUninterestingIpv4(value: string): boolean {
  const [a, b] = value.split('.').map(Number) as [number, number, number, number];
  if (a === 0 || a === 127) return true; // this-host and loopback
  if (a === 255) return true; // broadcast
  // Documentation ranges from RFC 5737, which exist precisely to be printed.
  if (a === 192 && b === 0) return true;
  if (a === 198 && (b === 51 || b === 18 || b === 19)) return true;
  if (a === 203 && b === 0) return true;
  return false;
}

const ipv4Rule: PatternRule = {
  id: 'net.ipv4',
  type: 'net.ipv4',
  // The tail guard rejects a following digit, but must allow a full stop: an
  // address at the end of a sentence is still an address, and `(?![\d.])` was
  // silently dropping every one of them.
  pattern: /(?<![\d.])\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(?!\.?\d)/g,
  baseConfidence: Confidence.STRONG,
  description: 'an IPv4 address',
  validate(value) {
    if (!ipv4(value)) {
      return { ok: false, signal: 'structure:dotted-quad', note: 'octet out of range or has a leading zero' };
    }
    if (isUninterestingIpv4(value)) {
      return { ok: false, signal: 'structure:reserved-range', note: 'in a loopback, broadcast, or documentation range' };
    }
    return { ok: true, signal: 'structure:dotted-quad', note: 'a routable IPv4 address', weight: 0.14 };
  },
  normalize: (value) => value,
};

/**
 * IPv6, including compressed forms.
 *
 * The alternation is ordered longest-first so a full address is never truncated
 * into a shorter valid match, which would leave the tail in the output.
 */
const ipv6Rule: PatternRule = {
  id: 'net.ipv6',
  type: 'net.ipv6',
  pattern:
    /(?<![:.\w])(?:(?:[0-9A-Fa-f]{1,4}:){7}[0-9A-Fa-f]{1,4}|(?:[0-9A-Fa-f]{1,4}:){1,7}:|(?:[0-9A-Fa-f]{1,4}:){1,6}:[0-9A-Fa-f]{1,4}|(?:[0-9A-Fa-f]{1,4}:){1,5}(?::[0-9A-Fa-f]{1,4}){1,2}|(?:[0-9A-Fa-f]{1,4}:){1,4}(?::[0-9A-Fa-f]{1,4}){1,3}|(?:[0-9A-Fa-f]{1,4}:){1,3}(?::[0-9A-Fa-f]{1,4}){1,4}|(?:[0-9A-Fa-f]{1,4}:){1,2}(?::[0-9A-Fa-f]{1,4}){1,5}|[0-9A-Fa-f]{1,4}:(?::[0-9A-Fa-f]{1,4}){1,6}|:(?:(?::[0-9A-Fa-f]{1,4}){1,7}|:))(?![:\w]|\.[0-9A-Fa-f])/g,
  baseConfidence: Confidence.STRONG,
  description: 'an IPv6 address',
  validate(value) {
    if (value === '::' || value === '::1') {
      return { ok: false, signal: 'structure:reserved-range', note: 'the unspecified or loopback address' };
    }
    if (/^2001:0?db8:/i.test(value)) {
      return { ok: false, signal: 'structure:reserved-range', note: 'in the 2001:db8::/32 documentation range' };
    }
    return { ok: true, signal: 'structure:ipv6', note: 'a well-formed IPv6 address', weight: 0.1 };
  },
  normalize: (value) => value.toLowerCase(),
};

const macRule: PatternRule = {
  id: 'net.mac',
  type: 'net.mac',
  pattern: /(?<![\w:.-])(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}(?![\w:-])/g,
  baseConfidence: Confidence.STRONG,
  description: 'a MAC hardware address',
  normalize: (value) => value.toLowerCase().replace(/-/g, ':'),
};

/**
 * Internal hostnames.
 *
 * Public domains are uninteresting; the value is in `db01.corp.internal`, which
 * reveals estate structure. Restricted to suffixes that are internal by
 * definition, plus anything the caller adds through a custom rule.
 */
const internalHostname: PatternRule = {
  id: 'net.hostname.internal',
  type: 'net.hostname',
  pattern:
    /\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.){1,6}(?:internal|local|localdomain|corp|lan|intranet|home\.arpa)\b/gi,
  baseConfidence: Confidence.STRONG,
  description: 'an internal hostname',
  normalize: (value) => value.toLowerCase(),
};

/** Cloud storage locations, which are frequently the actual leak. */
const cloudResource: PatternRule = {
  id: 'net.cloud-resource',
  type: 'net.url',
  pattern:
    /\b(?:s3:\/\/[a-z0-9.-]{3,63}(?:\/[^\s"'<>]{0,512})?|gs:\/\/[a-z0-9._-]{3,222}(?:\/[^\s"'<>]{0,512})?|[a-z0-9-]{3,63}\.s3(?:[.-][a-z0-9-]{1,20})?\.amazonaws\.com|[a-z0-9-]{3,63}\.blob\.core\.windows\.net)\b/gi,
  baseConfidence: Confidence.STRONG,
  description: 'a cloud storage bucket or object location',
  normalize: (value) => value.toLowerCase(),
};

/**
 * An address the document points at.
 *
 * The rule above drops loopback, broadcast, and RFC 5737 documentation ranges,
 * which is right when a dotted quad is all the evidence there is -- those
 * addresses appear in manuals and sample configuration constantly.
 *
 * It is wrong when the document says the address is the one that did something.
 * "originated from IP address 192.0.2.45" in an incident report is a fact about
 * the incident, whatever range it happens to fall in, and the same
 * label-outranks-the-structural-check reasoning applies here as it does to a
 * labelled SSN that fails its block rules.
 */
const labelledAddress: PatternRule = {
  id: 'net.ipv4.labelled',
  type: 'net.ipv4',
  pattern:
    /(?:IP(?:v4)?(?:\s+address)?|originat(?:ed|ing)\s+from|source\s+(?:IP|address)|remote\s+(?:IP|address)|client\s+IP|host)[^\S\n]{0,4}[:#=]?[^\S\n]{0,4}(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})(?!\.?\d)/gi,
  group: 1,
  baseConfidence: Confidence.STRONG,
  description: 'an address the document identifies as the source of an event',
  validate: (value) =>
    ipv4(value)
      ? { ok: true, signal: 'structure:dotted-quad', note: 'a well-formed IPv4 address named by the document', weight: 0.14 }
      : { ok: false, signal: 'structure:dotted-quad', note: 'octet out of range or has a leading zero' },
  normalize: (value) => value,
};

/** The IPv6 counterpart of {@link labelledAddress}. */
const labelledAddress6: PatternRule = {
  id: 'net.ipv6.labelled',
  type: 'net.ipv6',
  pattern:
    /(?:IP(?:v6)?(?:\s+address)?|originat(?:ed|ing)\s+from|source\s+(?:IP|address)|remote\s+(?:IP|address)|client\s+IP)[^\S\n]{0,4}[:#=]?[^\S\n]{0,4}((?:[0-9A-Fa-f]{1,4}:){2,7}[0-9A-Fa-f]{1,4})(?![:\w]|\.[0-9A-Fa-f])/g,
  group: 1,
  baseConfidence: Confidence.STRONG,
  description: 'an IPv6 address the document identifies as the source of an event',
  normalize: (value) => value.toLowerCase(),
};

export const networkPack: PatternPack = {
  id: 'network',
  version: '1.0.0',
  rules: [labelledAddress, labelledAddress6, ipv4Rule, ipv6Rule, macRule, internalHostname, cloudResource] satisfies PatternRule[],
};

export const networkRules = {
  labelledAddress,
  labelledAddress6,
  ipv4: ipv4Rule,
  ipv6: ipv6Rule,
  mac: macRule,
  internalHostname,
  cloudResource,
};
