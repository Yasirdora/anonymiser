/**
 * Credentials, keys, and tokens.
 *
 * A leaked secret differs from leaked PII in one important way: it is
 * immediately actionable by anyone who reads it. Policies almost always place
 * these at the top of the sensitivity lattice, and the rules here are tuned for
 * recall rather than precision because the cost of a miss is unbounded.
 */

import type { PatternPack, PatternRule } from '../pattern.js';
import { Confidence } from '../types.js';
import { isPlaceholder, shannonEntropy } from '../validators.js';

/** Vendor-prefixed tokens: unambiguous, no context needed, no validation possible. */
function vendorToken(
  id: string,
  pattern: RegExp,
  description: string,
): PatternRule {
  return {
    id,
    type: 'secret.api-key',
    pattern,
    baseConfidence: Confidence.VERIFIED,
    description,
  };
}

const vendorRules: PatternRule[] = [
  vendorToken('secret.aws.access-key', /\b(?:AKIA|ASIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|APKA)[A-Z0-9]{16}\b/g, 'an AWS access key identifier'),
  vendorToken('secret.github.token', /\bgh[pousr]_[A-Za-z0-9]{36,255}\b/g, 'a GitHub personal access or app token'),
  vendorToken('secret.slack.token', /\bxox[abposr]-[A-Za-z0-9-]{10,250}\b/g, 'a Slack API token'),
  vendorToken('secret.google.api-key', /\bAIza[0-9A-Za-z_-]{35}\b/g, 'a Google API key'),
  vendorToken('secret.stripe.key', /\b[rsp]k_(?:live|test)_[A-Za-z0-9]{16,99}\b/g, 'a Stripe API key'),
  vendorToken('secret.anthropic.key', /\bsk-ant-[A-Za-z0-9_-]{16,200}\b/g, 'an Anthropic API key'),
  vendorToken('secret.openai.key', /\bsk-(?:proj-)?[A-Za-z0-9_-]{20,200}\b/g, 'an OpenAI API key'),
  vendorToken('secret.sendgrid.key', /\bSG\.[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}\b/g, 'a SendGrid API key'),
  vendorToken('secret.twilio.sid', /\bAC[a-f0-9]{32}\b/g, 'a Twilio account identifier'),
  vendorToken('secret.npm.token', /\bnpm_[A-Za-z0-9]{36}\b/g, 'an npm access token'),
];

/**
 * PEM-encoded private keys.
 *
 * The body is matched lazily and bounded so a truncated or malformed block
 * cannot make the scan quadratic over a large document.
 */
const privateKey: PatternRule = {
  id: 'secret.private-key',
  type: 'secret.private-key',
  pattern:
    /-----BEGIN (?:RSA |DSA |EC |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY(?: BLOCK)?-----[\s\S]{0,16384}?-----END (?:RSA |DSA |EC |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY(?: BLOCK)?-----/g,
  baseConfidence: Confidence.VERIFIED,
  description: 'a PEM-encoded private key block',
};

/**
 * JSON Web Tokens.
 *
 * The `eyJ` prefix is base64url for `{"`, so any match is a JSON header, and
 * the three-segment shape makes false positives essentially impossible. JWTs
 * are worth flagging even when expired: the payload is not encrypted and
 * routinely carries names, email addresses, and internal identifiers.
 */
const jwt: PatternRule = {
  id: 'secret.jwt',
  type: 'secret.jwt',
  pattern: /\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b/g,
  baseConfidence: Confidence.VERIFIED,
  description: 'a JSON Web Token, whose payload is readable by anyone holding it',
};

/**
 * Credentials assigned in configuration or code.
 *
 * The assignment shape carries most of the signal; entropy filters out the
 * placeholders that dominate committed configuration files.
 */
const assignedSecret: PatternRule = {
  id: 'secret.assignment',
  type: 'secret.password',
  pattern:
    // The label may be several words -- "AWS Secret Access Key", "API Secret
    // Key", "Database Root Password". Matching only the single-token forms
    // missed exactly the credentials that carry a vendor name in front of them,
    // which is most of the ones that appear in an incident report.
    /(?:secret[_\s-]+access[_\s-]+key|api[_\s-]+secret[_\s-]+key|secret[_\s-]+key|access[_\s-]+key(?:[_\s-]+id)?|api[_\s-]?key|apikey|access[_\s-]?token|session[_\s-]?token|auth[_\s-]?token|client[_\s-]?secret|private[_\s-]?key|pass(?:word|wd|phrase)?|pwd|bearer|secret|credentials?|token)s?["'\s]{0,4}[:=]["'\s]{0,4}([A-Za-z0-9!@#$%^&*()_+=~[\]{}|;<>?,.\/-]{8,200})/gi,
  group: 1,
  baseConfidence: Confidence.LIKELY,
  description: 'a value assigned to a password or key field',
  validate(value) {
    if (isPlaceholder(value)) {
      return { ok: false, signal: 'entropy:placeholder', note: 'a recognisable placeholder rather than a real credential' };
    }
    const entropy = shannonEntropy(value);
    if (entropy < 2.2) {
      return { ok: false, signal: 'entropy:low', note: `too repetitive to be a real credential (${entropy.toFixed(2)} bits/char)` };
    }
    return { ok: true, signal: 'entropy:sufficient', note: `entropy of ${entropy.toFixed(2)} bits per character is consistent with a real credential`, weight: 0.2 };
  },
};

/**
 * High-entropy strings with no vendor prefix.
 *
 * Deliberately weak. This exists to surface the long random-looking token that
 * no specific rule caught, in a review queue, and never to redact silently.
 */
const highEntropy: PatternRule = {
  id: 'secret.high-entropy',
  type: 'secret.api-key',
  pattern: /(?<![A-Za-z0-9_/+-])[A-Za-z0-9_/+-]{32,128}(?![A-Za-z0-9_/+-])/g,
  baseConfidence: Confidence.HINT,
  description: 'a long high-entropy string that may be a credential',
  validate(value) {
    if (isPlaceholder(value)) {
      return { ok: false, signal: 'entropy:placeholder', note: 'a recognisable placeholder' };
    }
    const entropy = shannonEntropy(value);
    // Prose and identifiers sit near 4 bits/char; random tokens sit above 4.5.
    if (entropy < 4.2) {
      return { ok: false, signal: 'entropy:low', note: `entropy of ${entropy.toFixed(2)} bits/char is in the range of ordinary text` };
    }
    if (/^[0-9a-f]+$/i.test(value) && value.length % 2 === 0) {
      return { ok: true, signal: 'entropy:hex-digest', note: 'an even-length hex string, consistent with a hash or key', weight: 0.15 };
    }
    return { ok: true, signal: 'entropy:high', note: `entropy of ${entropy.toFixed(2)} bits per character exceeds ordinary text`, weight: 0.15 };
  },
  context: {
    suppresses: ['sha256', 'sha1', 'md5', 'checksum', 'digest', 'commit', 'etag', 'integrity'],
  },
};

export const secretsPack: PatternPack = {
  id: 'secrets',
  version: '1.0.0',
  rules: [...vendorRules, privateKey, jwt, assignedSecret, highEntropy],
};

export const secretRules = { privateKey, jwt, assignedSecret, highEntropy, vendorRules };
