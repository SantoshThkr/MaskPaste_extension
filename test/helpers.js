// Fabricated credentials for tests.
//
// Every secret-shaped value is assembled at runtime from a deterministic
// pseudo-random generator, so the repository never contains a literal that
// looks like a real key. None of these values are, or were ever, real.

import { scanText } from '../extension/detector.js';

const ALNUM = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
const BASE32_UPPER = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
const BASE64URL = `${ALNUM}-_`;
const BASE64 = `${ALNUM}+/`;

/** Deterministic pseudo-random characters (same output for the same seed). */
export function fakeChars(length, seed, alphabet = ALNUM) {
  let state = seed * 7919 + 17;
  let out = '';
  for (let i = 0; i < length; i += 1) {
    state = (state * 1103515245 + 12345) % 2147483648;
    out += alphabet[Math.floor(state / 65536) % alphabet.length];
  }
  return out;
}

const b64url = (value) => Buffer.from(JSON.stringify(value)).toString('base64url');

export function fakeJwt(header = { alg: 'HS256', typ: 'JWT' }, payload = { sub: 'fixture-user' }) {
  return `${b64url(header)}.${b64url(payload)}.${fakeChars(43, 90, BASE64URL)}`;
}

/** A PEM block with a fabricated base64 body. */
export function fakePem(label = 'RSA PRIVATE KEY', lineCount = 4, newline = '\n') {
  const body = Array.from({ length: lineCount }, (_, i) => fakeChars(64, 100 + i, BASE64));
  return [`-----BEGIN ${label}-----`, ...body, `-----END ${label}-----`].join(newline);
}

export const FAKE = {
  awsAccessKeyId: `AKIA${fakeChars(16, 1, BASE32_UPPER)}`,
  githubPat: `ghp_${fakeChars(36, 2)}`,
  githubFineGrained: `github_pat_${fakeChars(22, 3)}_${fakeChars(59, 4)}`,
  gitlab: `glpat-${fakeChars(20, 5)}`,
  stripe: ['sk', 'live', fakeChars(24, 6)].join('_'),
  stripeWebhook: `whsec_${fakeChars(32, 7)}`,
  slack: ['xoxb', '1234567890', '9876543210', fakeChars(24, 8)].join('-'),
  slackWebhookPath: `T${fakeChars(8, 9, BASE32_UPPER)}/B${fakeChars(8, 10, BASE32_UPPER)}/${fakeChars(24, 11)}`,
  openaiProject: `sk-proj-${fakeChars(48, 12)}`,
  openaiLegacy: `sk-${fakeChars(20, 13)}${'T3BlbkFJ'}${fakeChars(20, 14)}`,
  anthropic: `sk-ant-api03-${fakeChars(48, 15, BASE64URL)}`,
  googleApiKey: `AIza${fakeChars(35, 16)}`,
  googleOauthSecret: `GOCSPX-${fakeChars(28, 17)}`,
  npm: `npm_${fakeChars(36, 18)}`,
  pypi: `pypi-AgEIcHlwaS5vcmc${fakeChars(60, 19)}`,
  sendgrid: `SG.${fakeChars(22, 20)}.${fakeChars(43, 21)}`,
  huggingface: `hf_${fakeChars(34, 22)}`,
  genericSk: `sk-${fakeChars(40, 23)}`,
  token: fakeChars(32, 24),
  password: `fixture-${fakeChars(10, 25)}`,
  dbPassword: `pw${fakeChars(10, 26)}`,
};

/** The matched substrings, in order, for readable assertions. */
export function matchedValues(text, result = scanText(text)) {
  return result.findings.map((f) => text.slice(f.start, f.end));
}

export function categories(text) {
  return scanText(text).findings.map((f) => f.category);
}
