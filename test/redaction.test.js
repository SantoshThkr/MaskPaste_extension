import { test, describe } from 'node:test';
import assert from 'node:assert/strict';

import { scanText, redact } from '../extension/detector.js';
import { FAKE, fakeJwt, fakePem, fakeChars, matchedValues } from './helpers.js';

const MIXED = [
  '# app config',
  `DB_PASSWORD="${FAKE.password}"`,
  `GITHUB_TOKEN=${FAKE.githubPat}`,
  'LOG_LEVEL=debug',
  '',
  `curl -H 'Authorization: Bearer ${FAKE.token}' https://api.example.com/v1/items?limit=10`,
  `DATABASE_URL=postgres://app:${FAKE.dbPassword}@db.internal:5432/app`,
  '  timeout: 30 # seconds',
].join('\n');

describe('redaction output', () => {
  test('replaces secrets with labelled placeholders and keeps everything else', () => {
    const { redacted } = scanText(MIXED);
    assert.equal(
      redacted,
      [
        '# app config',
        'DB_PASSWORD="[REDACTED_PASSWORD]"',
        'GITHUB_TOKEN=[REDACTED_GITHUB_TOKEN]',
        'LOG_LEVEL=debug',
        '',
        "curl -H 'Authorization: Bearer [REDACTED_TOKEN]' https://api.example.com/v1/items?limit=10",
        'DATABASE_URL=postgres://app:[REDACTED_PASSWORD]@db.internal:5432/app',
        '  timeout: 30 # seconds',
      ].join('\n'),
    );
  });

  test('preserves line count, blank lines, indentation and trailing newline', () => {
    const text = `\n\n    API_KEY=${FAKE.googleApiKey}\n\t\tother\n\n`;
    const { redacted } = scanText(text);
    assert.equal(redacted, '\n\n    API_KEY=[REDACTED_GOOGLE_API_KEY]\n\t\tother\n\n');
    assert.equal(redacted.split('\n').length, text.split('\n').length);
  });

  test('preserves CRLF line endings', () => {
    const text = `a: 1\r\npassword: ${FAKE.password}\r\nb: 2\r\n`;
    assert.equal(scanText(text).redacted, 'a: 1\r\npassword: [REDACTED_PASSWORD]\r\nb: 2\r\n');
  });

  test('keeps JSON valid', () => {
    const json = JSON.stringify({ user: 'svc', password: FAKE.password, nested: { api_key: FAKE.token, n: 1 } }, null, 2);
    const parsed = JSON.parse(scanText(json).redacted);
    assert.equal(parsed.password, '[REDACTED_PASSWORD]');
    assert.equal(parsed.nested.api_key, '[REDACTED_API_KEY]');
    assert.equal(parsed.nested.n, 1);
    assert.equal(parsed.user, 'svc');
  });

  test('non-ASCII text around a secret is preserved', () => {
    const text = `🔐 Contraseña → token: ${FAKE.token} ✅ 日本語`;
    assert.equal(scanText(text).redacted, '🔐 Contraseña → token: [REDACTED_TOKEN] ✅ 日本語');
  });

  test('ranges point at each placeholder in the redacted text', () => {
    const { redacted, ranges, findings } = scanText(MIXED);
    assert.equal(ranges.length, findings.length);
    ranges.forEach((range, i) => {
      assert.equal(redacted.slice(range.start, range.end), findings[i].placeholder);
      assert.equal(range.id, findings[i].id);
    });
  });
});

describe('duplicates and overlaps', () => {
  test('multiple findings are reported without duplicates', () => {
    const { findings, summary } = scanText(MIXED);
    assert.deepEqual(
      findings.map((f) => [f.line, f.category]),
      [
        [2, 'Password'],
        [3, 'GitHub token'],
        [6, 'Authorization header'],
        [7, 'Database credentials'],
      ],
    );
    assert.equal(summary.total, 4);
    assert.equal(new Set(findings.map((f) => `${f.start}:${f.end}`)).size, findings.length);
  });

  test('the same secret on two lines is two findings (one per occurrence)', () => {
    const text = `TOKEN=${FAKE.githubPat}\necho ${FAKE.githubPat}`;
    const { findings, summary } = scanText(text);
    assert.deepEqual(findings.map((f) => f.line), [1, 2]);
    assert.deepEqual(summary.categories, [{ category: 'GitHub token', count: 2 }]);
  });

  test('no two findings ever overlap', () => {
    const text = [
      `password: "${FAKE.githubPat}"`,
      `Authorization: Bearer ${fakeJwt()}`,
      `token=${FAKE.stripe}&api_key=${FAKE.googleApiKey}`,
      `https://x-access-token:${FAKE.githubPat}@github.com/org/repo.git`,
      `"private_key": "${fakePem('PRIVATE KEY', 2, '\\n')}"`,
      `--token ${FAKE.npm}`,
    ].join('\n');
    const { findings } = scanText(text);
    for (let i = 1; i < findings.length; i += 1) {
      assert.ok(findings[i - 1].end <= findings[i].start, 'findings overlap');
    }
    assert.deepEqual(
      findings.map((f) => f.category),
      ['GitHub token', 'JSON Web Token', 'Stripe secret key', 'Google API key', 'GitHub token', 'Private key', 'npm token'],
    );
  });

  test('the more specific rule wins when spans overlap', () => {
    // The assignment value, the Authorization header and the JWT rule all cover this token.
    const jwt = fakeJwt();
    const f = scanText(`headers: { authorization: "Bearer ${jwt}" }`).findings;
    assert.equal(f.length, 1);
    assert.equal(f[0].category, 'JSON Web Token');
    assert.equal(f[0].placeholder, '[REDACTED_JWT]');
  });

  test('redact() ignores overlapping or out-of-range findings instead of corrupting text', () => {
    const text = 'abcdefghij';
    const out = redact(text, [
      { id: 'a', start: 2, end: 6, placeholder: '[A]' },
      { id: 'b', start: 4, end: 8, placeholder: '[B]' }, // overlaps a
      { id: 'c', start: 8, end: 50, placeholder: '[C]' }, // out of range
      { id: 'd', start: 9, end: 9, placeholder: '[D]' }, // empty
    ]);
    assert.equal(out.text, 'ab[A]ghij');
  });
});

describe('selective redaction', () => {
  test('redact() with a subset leaves unselected findings untouched', () => {
    const { findings } = scanText(MIXED);
    const keep = findings.filter((f) => f.category !== 'Password');
    const { text } = redact(MIXED, keep);
    assert.ok(text.includes(`DB_PASSWORD="${FAKE.password}"`));
    assert.ok(text.includes('GITHUB_TOKEN=[REDACTED_GITHUB_TOKEN]'));
  });

  test('redact() with no findings returns the input', () => {
    assert.equal(redact(MIXED, []).text, MIXED);
  });
});

describe('robustness', () => {
  test('empty and non-string input', () => {
    for (const input of ['', '   ', '\n\n\n', undefined, null, 42]) {
      const result = scanText(input);
      assert.deepEqual(result.findings, []);
      assert.deepEqual(result.summary, { total: 0, high: 0, potential: 0, categories: [] });
      assert.equal(result.redacted, typeof input === 'string' ? input : '');
    }
    assert.equal(scanText('').lineCount, 0);
    assert.equal(scanText('a\nb').lineCount, 2);
  });

  test('repeated scans produce identical results', () => {
    const first = scanText(MIXED);
    for (let i = 0; i < 5; i += 1) assert.deepEqual(scanText(MIXED), first);
    // Interleaving other inputs must not leak regex state between calls.
    scanText(`${fakePem()}\n${MIXED}`);
    scanText('x'.repeat(1000));
    assert.deepEqual(scanText(MIXED), first);
  });

  test('the input string is not modified', () => {
    const original = `${MIXED}`;
    scanText(original);
    assert.equal(original, MIXED);
  });

  test('scanning the redacted output finds nothing more (idempotent)', () => {
    const everything = [
      MIXED,
      fakePem(),
      `"private_key": "${fakePem('PRIVATE KEY', 2, '\\n')}"`,
      `id_token=${fakeJwt()}`,
      `https://hooks.slack.com/services/${FAKE.slackWebhookPath}`,
      `curl -u admin:${FAKE.password} https://x.test`,
      `<password>${FAKE.password}</password>`,
      `CREATE USER app WITH PASSWORD '${FAKE.password}';`,
      `mytool --api-key=${FAKE.token}`,
      `Authorization: Basic ${Buffer.from(`u:${FAKE.password}`).toString('base64')}`,
    ].join('\n');
    const once = scanText(everything);
    assert.equal(once.findings.length, 13);
    const twice = scanText(once.redacted);
    assert.deepEqual(twice.findings, []);
    assert.equal(twice.redacted, once.redacted);
  });

  test('finds every secret in a large input quickly', () => {
    const block = `${MIXED}\n${'const value = compute(a, b); // ordinary code\n'.repeat(40)}`;
    const big = block.repeat(Math.ceil(1_000_000 / block.length));
    const started = performance.now();
    const result = scanText(big);
    const elapsed = performance.now() - started;
    assert.equal(result.findings.length, 4 * Math.ceil(1_000_000 / block.length));
    assert.ok(elapsed < 3000, `1 MB scan took ${elapsed.toFixed(0)} ms`);
  });

  test('pathological inputs do not cause catastrophic backtracking', () => {
    const n = 50_000;
    const inputs = [
      'a'.repeat(n),
      `password${'='.repeat(n)}`,
      `password: "${'x'.repeat(n)}`,
      `-----BEGIN PRIVATE KEY-----${'\n'.repeat(n)}`,
      `-----BEGIN PRIVATE KEY-----\n${'A'.repeat(n)}`,
      `${'-----BEGIN PRIVATE KEY-----'.repeat(2000)}`,
      `postgres://${'u'.repeat(n)}:${'p'.repeat(n)}`,
      `postgres://u:${'@'.repeat(n)}`,
      `eyJ${'a'.repeat(n)}.eyJ${'b'.repeat(n)}`,
      `Bearer ${'a.'.repeat(n)}`,
      `${'key: '.repeat(n)}`,
      `${'password='.repeat(n / 10)}`,
      `${'a.'.repeat(n)}password: x`,
      `-u ${':'.repeat(n)}`,
      `<password>${'<'.repeat(n)}`,
      `sk-${'a-'.repeat(n)}`,
      `xoxb-${'1-'.repeat(n)}`,
      fakeChars(n, 80, 'aA0=:;&,."\' \n'),
    ];
    for (const input of inputs) {
      const started = performance.now();
      scanText(input);
      const elapsed = performance.now() - started;
      assert.ok(elapsed < 1500, `input starting ${JSON.stringify(input.slice(0, 20))} took ${elapsed.toFixed(0)} ms`);
    }
  });

  test('matchedValues helper agrees with offsets', () => {
    assert.deepEqual(matchedValues(`a=1 password=${FAKE.password}`), [FAKE.password]);
  });
});
