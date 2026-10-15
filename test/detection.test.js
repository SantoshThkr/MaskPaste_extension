import { test, describe } from 'node:test';
import assert from 'node:assert/strict';

import { scanText, classifyKey, RULE_IDS, HIGH, POTENTIAL } from '../extension/detector.js';
import { FAKE, fakeJwt, fakePem, fakeChars, matchedValues } from './helpers.js';

function only(text) {
  const { findings } = scanText(text);
  assert.equal(findings.length, 1, `expected exactly one finding in ${JSON.stringify(text)}`);
  return { ...findings[0], value: text.slice(findings[0].start, findings[0].end) };
}

describe('provider-specific tokens', () => {
  const cases = [
    ['aws-access-key-id', 'AWS access key ID', FAKE.awsAccessKeyId],
    ['github-token', 'GitHub token', FAKE.githubPat],
    ['github-token', 'GitHub token', FAKE.githubFineGrained],
    ['gitlab-token', 'GitLab token', FAKE.gitlab],
    ['stripe-key', 'Stripe secret key', FAKE.stripe],
    ['stripe-webhook-secret', 'Stripe webhook secret', FAKE.stripeWebhook],
    ['slack-token', 'Slack token', FAKE.slack],
    ['openai-key', 'OpenAI API key', FAKE.openaiProject],
    ['openai-key', 'OpenAI API key', FAKE.openaiLegacy],
    ['anthropic-key', 'Anthropic API key', FAKE.anthropic],
    ['google-api-key', 'Google API key', FAKE.googleApiKey],
    ['google-oauth-secret', 'Google OAuth client secret', FAKE.googleOauthSecret],
    ['npm-token', 'npm token', FAKE.npm],
    ['pypi-token', 'PyPI token', FAKE.pypi],
    ['sendgrid-key', 'SendGrid API key', FAKE.sendgrid],
    ['huggingface-token', 'Hugging Face token', FAKE.huggingface],
    ['generic-sk-key', 'Secret key (sk-…)', FAKE.genericSk],
  ];

  for (const [ruleId, category, value] of cases) {
    test(`${category} (${value.slice(0, 8)}…) in prose`, () => {
      const f = only(`Here is the value ${value} from the logs.`);
      assert.equal(f.ruleId, ruleId);
      assert.equal(f.category, category);
      assert.equal(f.value, value);
    });
  }

  test('provider tokens are high confidence (except the generic sk- shape)', () => {
    for (const [ruleId, , value] of cases) {
      const f = only(value);
      assert.equal(f.confidence, ruleId === 'generic-sk-key' ? POTENTIAL : HIGH, ruleId);
    }
  });

  test('a fake API key assigned in .env is reported once, under the provider category', () => {
    const f = only(`OPENAI_API_KEY=${FAKE.openaiProject}`);
    assert.equal(f.category, 'OpenAI API key');
    assert.equal(f.placeholder, '[REDACTED_OPENAI_KEY]');
  });

  test('Slack webhook keeps the host and redacts the secret path', () => {
    const url = `https://hooks.slack.com/services/${FAKE.slackWebhookPath}`;
    const result = scanText(`SLACK_WEBHOOK_URL=${url}`);
    assert.equal(result.findings.length, 1);
    assert.equal(result.redacted, 'SLACK_WEBHOOK_URL=https://hooks.slack.com/services/[REDACTED_SLACK_WEBHOOK]');
  });

  test('near misses are not reported', () => {
    const near = [
      `ghp_${fakeChars(20, 30)}`, // too short
      `AKIA${fakeChars(12, 31, 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567')}`, // too short
      `xghp_${fakeChars(36, 32)}`, // glued to a word
      'ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx', // masked documentation value
      'sk_live_************************', // masked
      `sk-${'a'.repeat(40)}`, // no digits, no variety
      'sk-button-primary-large-hover-state-active', // CSS-ish, no digits
      `hf_${'abcdefghij'.repeat(4)}`, // no digits or uppercase
    ];
    for (const value of near) assert.deepEqual(scanText(value).findings, [], value);
  });
});

describe('bearer tokens and Authorization headers', () => {
  test('a fake bearer token in an Authorization header', () => {
    const f = only(`curl -H "Authorization: Bearer ${FAKE.token}" https://api.example.com/v1`);
    assert.equal(f.category, 'Authorization header');
    assert.equal(f.value, FAKE.token);
    assert.equal(f.confidence, HIGH);
    assert.equal(f.placeholder, '[REDACTED_TOKEN]');
  });

  test('a bearer token outside a header (log line)', () => {
    const f = only(`2026-01-01T00:00:00Z DEBUG sending bearer ${FAKE.token} to upstream`);
    assert.equal(f.category, 'Bearer token');
    assert.equal(f.value, FAKE.token);
  });

  test('JSON header object', () => {
    const f = only(`{"headers": {"Authorization": "Bearer ${FAKE.token}"}}`);
    assert.equal(f.value, FAKE.token);
  });

  test('Basic auth header is decoded and reported as credentials', () => {
    const basic = Buffer.from(`deploy:${FAKE.password}`).toString('base64');
    const f = only(`Authorization: Basic ${basic}`);
    assert.equal(f.value, basic);
    assert.equal(f.placeholder, '[REDACTED_CREDENTIALS]');
  });

  test('header token wins over its own provider rule only when no provider matches', () => {
    const f = only(`Authorization: token ${FAKE.githubPat}`);
    assert.equal(f.category, 'GitHub token');
  });
});

describe('JSON Web Tokens', () => {
  test('a JWT with a decodable header is high confidence', () => {
    const jwt = fakeJwt();
    const f = only(`id_token=${jwt}`);
    assert.equal(f.category, 'JSON Web Token');
    assert.equal(f.value, jwt);
    assert.equal(f.confidence, HIGH);
    assert.equal(f.detail, 'alg HS256');
  });

  test('a JWT inside an Authorization header is reported once, as a JWT', () => {
    const jwt = fakeJwt();
    const f = only(`Authorization: Bearer ${jwt}`);
    assert.equal(f.category, 'JSON Web Token');
    assert.equal(f.value, jwt);
  });

  test('an undecodable JWT-shaped string is a potential match', () => {
    const f = only(`eyJ${fakeChars(20, 40)}.eyJ${fakeChars(30, 41)}.${fakeChars(30, 42)}`);
    assert.equal(f.confidence, POTENTIAL);
  });
});

describe('private keys', () => {
  test('a PEM block: only the body is replaced, BEGIN/END lines stay', () => {
    const pem = fakePem('RSA PRIVATE KEY');
    const result = scanText(`key:\n${pem}\ndone`);
    assert.equal(result.findings.length, 1);
    const [f] = result.findings;
    assert.equal(f.category, 'Private key');
    assert.equal(f.line, 3);
    assert.equal(f.endLine, 6);
    assert.equal(
      result.redacted,
      'key:\n-----BEGIN RSA PRIVATE KEY-----\n[REDACTED_PRIVATE_KEY]\n-----END RSA PRIVATE KEY-----\ndone',
    );
  });

  test('other PEM labels', () => {
    for (const label of ['PRIVATE KEY', 'EC PRIVATE KEY', 'OPENSSH PRIVATE KEY', 'ENCRYPTED PRIVATE KEY', 'PGP PRIVATE KEY BLOCK']) {
      const f = only(fakePem(label));
      assert.equal(f.detail, label);
    }
  });

  test('a JSON-escaped key (service-account file) keeps its quoting and \\n escapes', () => {
    const escaped = fakePem('PRIVATE KEY', 3, '\\n');
    const text = `{"type": "service_account", "private_key": "${escaped}\\n", "client_email": "bot@example.iam.gserviceaccount.com"}`;
    const result = scanText(text);
    assert.equal(result.findings.length, 1);
    assert.equal(
      result.redacted,
      '{"type": "service_account", "private_key": "-----BEGIN PRIVATE KEY-----\\n[REDACTED_PRIVATE_KEY]\\n-----END PRIVATE KEY-----\\n", "client_email": "bot@example.iam.gserviceaccount.com"}',
    );
    assert.doesNotThrow(() => JSON.parse(result.redacted));
  });

  test('a truncated key without an END line is still redacted', () => {
    const lines = fakePem('RSA PRIVATE KEY', 3).split('\n').slice(0, 4).join('\n');
    const result = scanText(`${lines}\n`);
    assert.equal(result.findings.length, 1);
    assert.equal(result.redacted, '-----BEGIN RSA PRIVATE KEY-----\n[REDACTED_PRIVATE_KEY]\n');
  });

  test('public keys and certificates are not reported', () => {
    const cert = ['-----BEGIN CERTIFICATE-----', fakeChars(64, 50), '-----END CERTIFICATE-----'].join('\n');
    const pub = ['-----BEGIN PUBLIC KEY-----', fakeChars(64, 51), '-----END PUBLIC KEY-----'].join('\n');
    assert.deepEqual(scanText(`${cert}\n${pub}`).findings, []);
  });

  test('elided documentation keys are not reported', () => {
    assert.deepEqual(scanText('-----BEGIN PRIVATE KEY-----\nMIIEvQ...\n-----END PRIVATE KEY-----').findings, []);
  });
});

describe('password and secret assignments', () => {
  const pw = FAKE.password;
  const formats = [
    ['.env', `DB_PASSWORD=${pw}`],
    ['.env quoted', `DB_PASSWORD="${pw}"`],
    ['shell export', `export PGPASSWORD='${pw}'`],
    ['Dockerfile ENV', `ENV MYSQL_ROOT_PASSWORD=${pw}`],
    ['docker-compose list', `      - POSTGRES_PASSWORD=${pw}`],
    ['YAML', `  password: ${pw}`],
    ['YAML quoted', `  password: "${pw}"  # prod`],
    ['JSON', `{"username": "admin", "password": "${pw}"}`],
    ['escaped JSON in a log', `body="{\\"password\\":\\"${pw}\\"}"`],
    ['JavaScript', `const dbPassword = '${pw}';`],
    ['object literal', `connect({ user: 'app', password: "${pw}" })`],
    ['Python', `PASSWORD = "${pw}"`],
    ['Python annotation', `password: str = "${pw}"`],
    ['TypeScript annotation', `const password: string = "${pw}";`],
    ['Go', `password := "${pw}"`],
    ['PHP', `$password = '${pw}';`],
    ['Ruby hash', `{ 'password' => '${pw}' }`],
    ['properties', `spring.datasource.password=${pw}`],
    ['INI/TOML', `password = "${pw}"`],
    ['.NET connection string', `Server=db;Database=app;User Id=sa;Password=${pw};Encrypt=true`],
    ['query string', `https://example.com/login?user=bob&password=${pw}&next=/home`],
    ['CLI flag', `docker login --password ${pw} registry.example.com`],
    ['CLI flag with =', `mytool --db-password=${pw}`],
    ['XML', `<password>${pw}</password>`],
    ['SQL', `CREATE USER app WITH PASSWORD '${pw}';`],
    ['log line', `INFO login attempt user=bob password=${pw} ip=10.0.0.1`],
    ['prose', `Password: ${pw}`],
  ];

  for (const [name, text] of formats) {
    test(`detects a password in ${name}`, () => {
      const f = only(text);
      assert.equal(f.value, pw, text);
      assert.equal(f.category, 'Password');
      assert.equal(f.placeholder, '[REDACTED_PASSWORD]');
    });
  }

  test('secrets, tokens and API keys by variable name', () => {
    const value = fakeChars(24, 60);
    const cases = [
      [`JWT_SECRET=${value}`, 'Secret'],
      [`clientSecret: "${value}"`, 'Secret'],
      [`GITHUB_TOKEN="${value}"`, 'Token'],
      [`"access_token": "${value}"`, 'Token'],
      [`//registry.npmjs.org/:_authToken=${value}`, 'Token'],
      [`X-Api-Key: ${value}`, 'API key'],
      [`api_key = '${value}'`, 'API key'],
      [`AWS_SECRET_ACCESS_KEY=${value}`, 'Secret key'],
      [`SECRET_KEY_BASE=${value}`, 'Secret key'],
      [`DefaultEndpointsProtocol=https;AccountName=demo;AccountKey=${value}==;EndpointSuffix=core.windows.net`, 'Secret key'],
      [`https://example.com/reset?token=${value}`, 'Token'],
    ];
    for (const [text, category] of cases) {
      const f = only(text);
      assert.equal(f.category, category, text);
      assert.ok(f.value.startsWith(value), text);
    }
  });

  test('confidence: random-looking values are high, word-like values are potential', () => {
    assert.equal(only(`API_KEY=${fakeChars(24, 61)}`).confidence, HIGH);
    assert.equal(only('JWT_SECRET=supersecret').confidence, POTENTIAL);
    assert.equal(only('DB_PASSWORD=hunter2!').confidence, HIGH);
    assert.equal(only('password: postgres').confidence, POTENTIAL);
  });

  test('the finding detail is the variable name, never the value', () => {
    const f = only(`STRIPE_WEBHOOK_PASSWORD=${FAKE.password}`);
    assert.equal(f.detail, 'STRIPE_WEBHOOK_PASSWORD');
  });
});

describe('credentials in URLs and commands', () => {
  test('database connection strings: only the password is replaced', () => {
    const cases = [
      ['postgres', `postgres://app_user:${FAKE.dbPassword}@db.internal:5432/app`],
      ['postgresql', `postgresql://app_user:${FAKE.dbPassword}@db.internal/app?sslmode=require`],
      ['mysql', `mysql://root:${FAKE.dbPassword}@127.0.0.1:3306/shop`],
      ['mongodb+srv', `mongodb+srv://svc:${FAKE.dbPassword}@cluster0.abcde.mongodb.net/?retryWrites=true`],
      ['redis', `redis://:${FAKE.dbPassword}@cache:6379/0`],
      ['amqp', `amqp://guest:${FAKE.dbPassword}@rabbit:5672/`],
    ];
    for (const [scheme, url] of cases) {
      const result = scanText(`DATABASE_URL=${url}`);
      assert.equal(result.findings.length, 1, url);
      assert.equal(result.findings[0].category, 'Database credentials');
      assert.equal(result.findings[0].detail, `${scheme}://`);
      assert.equal(result.redacted, `DATABASE_URL=${url.replace(FAKE.dbPassword, '[REDACTED_PASSWORD]')}`);
    }
  });

  test('a password containing "@" is fully redacted', () => {
    const result = scanText('postgres://app:p@ss-w0rd@db.internal/app');
    assert.equal(result.redacted, 'postgres://app:[REDACTED_PASSWORD]@db.internal/app');
  });

  test('two URLs on one line stay separate', () => {
    const text = `a=postgres://u:${FAKE.dbPassword}@h1/db,mysql://v:${FAKE.password}@h2/db`;
    assert.deepEqual(matchedValues(text), [FAKE.dbPassword, FAKE.password]);
  });

  test('credentials in other URLs (git remotes)', () => {
    const f = only(`git clone https://deploy:${FAKE.dbPassword}@git.example.com/team/repo.git`);
    assert.equal(f.category, 'Credentials in URL');
  });

  test('curl -u user:password', () => {
    assert.equal(only(`curl -u admin:${FAKE.dbPassword} https://api.example.com`).value, FAKE.dbPassword);
    assert.equal(only(`curl --user 'admin:${FAKE.password}' https://x.test`).value, FAKE.password);
  });

  test('trailing sentence and Markdown punctuation is not part of a command-line value', () => {
    const pw = FAKE.dbPassword;
    assert.deepEqual(matchedValues(`Run \`curl -u admin:${pw}\`, then retry.`), [pw]);
    assert.deepEqual(matchedValues(`Then \`mysql -uroot -p${pw}\`.`), [pw]);
    assert.deepEqual(matchedValues(`Use --password ${pw}, not the default.`), [pw]);
  });

  test('mysql -pPASSWORD', () => {
    const f = only(`mysql -h db -u root -p${FAKE.dbPassword} shop < dump.sql`);
    assert.equal(f.value, FAKE.dbPassword);
    assert.equal(f.category, 'Password');
    assert.deepEqual(scanText('mysql -u root -p shop').findings, []); // -p alone prompts
    assert.deepEqual(scanText('mysql -u root -p$MYSQL_PWD shop').findings, []);
  });

  test('base64 user:password under an "auth" key (Docker config.json, .npmrc)', () => {
    const encoded = Buffer.from(`robot:${FAKE.password}`).toString('base64');
    const f = only(`{"auths": {"registry.example.com": {"auth": "${encoded}"}}}`);
    assert.equal(f.category, 'Basic auth credentials');
    assert.equal(f.value, encoded);
    assert.equal(only(`_auth=${encoded}`).value, encoded);
    assert.deepEqual(scanText('auth: true\nauth: "jwt"\nauth: { user, pass }').findings, []);
  });
});

describe('cookies', () => {
  test('a Cookie header from "Copy as cURL" is redacted as a whole', () => {
    const cookies = `_ga=GA1.1.12345.67890; session_id=${FAKE.token}; theme=dark`;
    const result = scanText(`curl 'https://app.example.com/api' -H 'accept: */*' -H 'cookie: ${cookies}' --compressed`);
    assert.equal(result.findings.length, 1);
    assert.equal(result.findings[0].category, 'Cookie header');
    assert.equal(result.findings[0].confidence, HIGH);
    assert.equal(
      result.redacted,
      "curl 'https://app.example.com/api' -H 'accept: */*' -H 'cookie: [REDACTED_COOKIES]' --compressed",
    );
  });

  test('a cookie that contains a JWT does not let the other cookies leak', () => {
    const text = `Cookie: sid=${FAKE.token}; jwt=${fakeJwt()}`;
    const result = scanText(text);
    assert.equal(result.findings.length, 1);
    assert.equal(result.redacted, 'Cookie: [REDACTED_COOKIES]');
  });

  test('Set-Cookie redacts only the value and keeps attributes', () => {
    const result = scanText(`Set-Cookie: session=${FAKE.token}; Path=/; HttpOnly; Secure`);
    assert.equal(result.redacted, 'Set-Cookie: session=[REDACTED_COOKIE]; Path=/; HttpOnly; Secure');
  });

  test('curl -b / --cookie', () => {
    const f = only(`curl -b 'sessionid=${FAKE.token}' https://x.test`);
    assert.equal(f.value, `sessionid=${FAKE.token}`);
    assert.deepEqual(scanText('git checkout -b feature/login\ncurl -b cookies.txt https://x.test').findings, []);
  });

  test('short preference cookies and code are not reported', () => {
    assert.deepEqual(scanText("document.cookie = 'theme=dark';\nconst cookie: string = req.headers.cookie;\ncookie: 'lang=en; theme=dark'").findings, []);
  });
});

describe('line and column numbers', () => {
  test('are 1-based and point at the secret', () => {
    const text = `first line\n\n  token: ${FAKE.token}\nlast`;
    const f = only(text);
    assert.equal(f.line, 3);
    assert.equal(f.column, 10);
    assert.equal(f.endLine, 3);
  });

  test('work with CRLF line endings', () => {
    const text = `a=1\r\nb=2\r\nDB_PASSWORD=${FAKE.password}\r\n`;
    const f = only(text);
    assert.equal(f.line, 3);
    assert.equal(f.column, 13);
    assert.equal(f.value, FAKE.password);
  });
});

describe('key classification', () => {
  test('sensitive names', () => {
    for (const key of [
      'password', 'DB_PASSWORD', 'dbPassword', 'PGPASSWORD', 'MYSQL_PWD', 'smtp_pass', 'passphrase',
      'secret', 'CLIENT_SECRET', 'jwtSecret', 'token', 'GITHUB_TOKEN', 'accessToken', '_authToken',
      'refresh_token', 'api_key', 'apiKey', 'APIKey', 'x-api-key', 'OPENAI_API_KEY', 'secret_key_base',
      'AWS_SECRET_ACCESS_KEY', 'privateKey', 'encryption_key', 'AccountKey', 'spring.datasource.password',
    ]) {
      assert.ok(classifyKey(key), key);
    }
  });

  test('non-sensitive names', () => {
    for (const key of [
      'key', 'primaryKey', 'publicKey', 'cacheKey', 'STORAGE_KEY', 'sortKey', 'idempotencyKey',
      'token_type', 'tokenType', 'max_tokens', 'nextToken', 'pageToken', 'eos_token', 'pad_token',
      'csrfToken', 'cancellationToken', 'password_length', 'passwordHint', 'secretName', 'TOKEN_URL',
      'AWS_ACCESS_KEY_ID', 'private_key_id', 'bypass', 'compass', 'keyboard', 'monkey',
    ]) {
      assert.equal(classifyKey(key), null, key);
    }
  });
});

describe('finding objects', () => {
  test('never contain the secret value itself', () => {
    const text = [
      `DB_PASSWORD=${FAKE.password}`,
      `token: ${FAKE.githubPat}`,
      `Authorization: Bearer ${FAKE.token}`,
      `postgres://u:${FAKE.dbPassword}@h/db`,
    ].join('\n');
    const { findings } = scanText(text);
    assert.equal(findings.length, 4);
    const serialized = JSON.stringify(findings);
    for (const secret of [FAKE.password, FAKE.githubPat, FAKE.token, FAKE.dbPassword]) {
      assert.ok(!serialized.includes(secret), 'finding metadata leaked a secret');
    }
  });

  test('every rule is exercised by this suite', async () => {
    const samples = [
      FAKE.awsAccessKeyId, FAKE.githubPat, FAKE.gitlab, FAKE.stripe, FAKE.stripeWebhook, FAKE.slack,
      `https://hooks.slack.com/services/${FAKE.slackWebhookPath}`, FAKE.openaiProject, FAKE.anthropic,
      FAKE.googleApiKey, FAKE.googleOauthSecret, FAKE.npm, FAKE.pypi, FAKE.sendgrid, FAKE.huggingface,
      fakePem(), fakeJwt(), `postgres://u:${FAKE.dbPassword}@h/db`, `curl -u a:${FAKE.dbPassword} x`,
      `Authorization: ${FAKE.token}`, `bearer ${FAKE.token}`, FAKE.genericSk,
      `ALTER USER bob IDENTIFIED BY '${FAKE.password}';`, `<secret>${FAKE.token}</secret>`,
      `password=${FAKE.password}`, `Cookie: sid=${FAKE.token}`, `curl -b 'sid=${FAKE.token}' x`,
      `mysql -uroot -p${FAKE.password}`,
    ];
    const seen = new Set(samples.flatMap((s) => scanText(s).findings.map((f) => f.ruleId)));
    assert.deepEqual([...RULE_IDS].filter((id) => !seen.has(id)), []);
  });
});
