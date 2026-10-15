/*
 * MaskPaste detection and redaction engine.
 *
 * Every export is a pure function over a string: no DOM, storage, network or
 * logging. The popup and the Node test suite import this same file.
 *
 * Detection runs in three steps:
 *   1. Each rule proposes candidate spans (start/end offsets into the text).
 *   2. Overlapping candidates are resolved by rule priority (earlier rules in
 *      RULES are more specific), so a value is reported exactly once.
 *   3. Redaction replaces each accepted span with a [REDACTED_*] placeholder
 *      and copies every other character through unchanged.
 */

export const HIGH = 'high';
export const POTENTIAL = 'potential';

// Bounds that keep scanning linear on huge single-line inputs (minified code).
const QUOTE_SEARCH_LIMIT = 4096;
const PREFIX_SCAN_LIMIT = 1000;

/* ------------------------------------------------------------------------ */
/* Value heuristics                                                          */
/* ------------------------------------------------------------------------ */

const PLACEHOLDER_WORDS = new Set([
  'password', 'passwd', 'pass', 'pwd', 'secret', 'token', 'key', 'apikey', 'api_key', 'api-key',
  'access_token', 'secret_key', 'private_key', 'value', 'string', 'changeme', 'change_me',
  'change-me', 'changeit', 'placeholder', 'example', 'sample', 'test', 'testing', 'dummy', 'demo',
  'none', 'null', 'nil', 'undefined', 'true', 'false', 'yes', 'no', 'on', 'off', 'empty',
  'default', 'required', 'optional', 'todo', 'tbd', 'fixme', 'n/a', 'na', 'redacted', 'hidden',
  'masked', 'foo', 'bar', 'baz', 'foobar', 'secret_value', 'your_secret', 'your_token',
]);

// Words that, as a bare unquoted value, almost always mean "this is code".
const CODE_WORDS = new Set([
  'string', 'number', 'boolean', 'bool', 'int', 'integer', 'float', 'double', 'str', 'bytes',
  'any', 'unknown', 'object', 'void', 'never', 'char', 'optional', 'list', 'dict', 'function',
  'new', 'await', 'async', 'this', 'self', 'typeof', 'require', 'import', 'return', 'const',
  'let', 'var', 'secretstr', 'lambda', 'yield', 'static', 'final', 'public', 'private',
]);

const SECRET_WORDS = new Set([
  'password', 'passwd', 'pwd', 'pass', 'passphrase', 'secret', 'token', 'key', 'apikey',
  'credential', 'credentials', 'auth',
]);

function distinctChars(value) {
  return new Set(value).size;
}

function entropy(value) {
  const counts = new Map();
  for (const ch of value) counts.set(ch, (counts.get(ch) || 0) + 1);
  let bits = 0;
  for (const n of counts.values()) {
    const p = n / value.length;
    bits -= p * Math.log2(p);
  }
  return bits;
}

/** True for values like ghp_xxxxxxxx… or AKIA************ that are clearly not real. */
function looksMasked(value) {
  return distinctChars(value) < 8 || /([xX*•.#])\1{4,}/.test(value);
}

/**
 * Template and environment references rather than literal values: $VAR, ${VAR},
 * $(cmd), $1, {{ var }}, %(var)s, %VAR%, #{var}, <%= … %>, @var@.
 */
function isReference(value) {
  return (
    /^\$(?:[{(A-Za-z_]|\d|env:)/.test(value) ||
    /\$\{|\{\{|\}\}|^%\(\w+\)s$|^%\w+%$|^#\{.*\}$|^<%.*%>$|^@\w[\w.]*@$/.test(value)
  );
}

export function isPlaceholder(value) {
  const v = value.trim();
  if (!v) return true;
  const lower = v.toLowerCase();
  if (PLACEHOLDER_WORDS.has(lower)) return true;
  if (/^<[^<>]*>$|^\[[^[\]]*\]$|^\{[^{}]*\}$/.test(v)) return true; // <token> [REDACTED_X] {password}
  if (/^(.)\1*$/.test(v) || /^[x*•.#_-]+$/i.test(v)) return true; // xxxx ****  ----
  if (/^your|(?:^|[\W_])(?:your|here|todo|fixme|sample)(?:$|[\W_])/.test(lower)) return true;
  return /example|placeholder|changeme|change_me|replace[_-]?me|dummy|redacted|xxxx|\*\*\*/.test(lower);
}

function looksLikePath(value) {
  return (
    /^(?:~|\.{1,2})[\\/]/.test(value) ||
    /^[A-Za-z]:\\/.test(value) ||
    (/^\/[\w.~-]+\/[\w./~-]*$/.test(value) && !/[+=]/.test(value))
  );
}

function looksLikeUrl(value) {
  return /^[a-z][a-z0-9+.-]*:\/\//i.test(value);
}

/** Human-readable text (validation messages, i18n strings) rather than a secret. */
function looksLikeProse(value) {
  if (!/\s/.test(value)) return false;
  const words = value.trim().split(/\s+/);
  return words.length >= 3 || /^[\p{L}][\p{L}'’-]*(?:\s+[\p{L}'’-]+)+[.!?:]?$/u.test(value.trim());
}

function isRandomLooking(value) {
  return value.length >= 12 && /\d/.test(value) && /[A-Za-z]/.test(value) && entropy(value) >= 3;
}

/** Opaque token check used for Authorization and Bearer values. */
function looksLikeToken(value, minLength) {
  if (value.length < minLength || isPlaceholder(value) || looksMasked(value)) return false;
  const digit = /\d/.test(value);
  const lower = /[a-z]/.test(value);
  const upper = /[A-Z]/.test(value);
  if (digit && (lower || upper)) return true;
  return value.length >= 24 && lower && upper && distinctChars(value) >= 10;
}

function decodeBase64(value) {
  try {
    const b64 = value.replace(/-/g, '+').replace(/_/g, '/');
    return atob(b64 + '==='.slice((b64.length + 3) % 4));
  } catch {
    return null;
  }
}

/* ------------------------------------------------------------------------ */
/* Key-name classification for generic assignments                          */
/* ------------------------------------------------------------------------ */

/** Split identifiers like DB_PASSWORD, apiKey, x-api-key or spring.datasource.password. */
function keyWords(key) {
  return key
    .replace(/([a-z0-9])([A-Z])/g, '$1 $2')
    .replace(/([A-Z]+)([A-Z][a-z])/g, '$1 $2')
    .toLowerCase()
    .split(/[^a-z0-9]+/)
    .filter(Boolean);
}

function hasSecretWord(value) {
  return keyWords(value).some((w) => SECRET_WORDS.has(w));
}

// "<qualifier> token" names that are not credentials (pagination, NLP vocab, CSRF…).
const NON_SECRET_TOKEN_QUALIFIERS = new Set([
  'next', 'page', 'continuation', 'pagination', 'cancellation', 'cancel', 'sync', 'resume',
  'max', 'min', 'num', 'input', 'output', 'prompt', 'completion', 'total', 'eos', 'bos', 'pad',
  'unk', 'sep', 'cls', 'mask', 'start', 'end', 'special', 'csrf', 'xsrf', 'lexer', 'parser',
  'cursor', 'stop',
]);

// "<qualifier> key" names that hold secrets. Plain "key", "primaryKey", "publicKey",
// "cacheKey", "storageKey" etc. are deliberately not on this list.
const SECRET_KEY_QUALIFIERS = new Set([
  'access', 'secret', 'private', 'signing', 'encryption', 'encrypt', 'decryption', 'decrypt',
  'master', 'account', 'client', 'app', 'license', 'licence', 'service', 'consumer', 'webhook',
  'hmac', 'jwt', 'admin', 'subscription', 'shared', 'crypto', 'cipher', 'aes', 'server',
  'deploy', 'ssh', 'gpg', 'pgp',
]);
const COMPOUND_KEY_QUALIFIER = /(?:access|secret|private|signing|encryption|master|account|license|subscription|client)$/;

const IGNORED_KEY_SUFFIXES = new Set([
  'base', 'value', 'val', 'b64', 'base64', 'hex', 'raw', 'str', 'string', 'plain', 'plaintext',
]);

const KINDS = {
  password: { category: 'Password', placeholder: 'PASSWORD' },
  secret: { category: 'Secret', placeholder: 'SECRET' },
  token: { category: 'Token', placeholder: 'TOKEN' },
  apiKey: { category: 'API key', placeholder: 'API_KEY' },
  key: { category: 'Secret key', placeholder: 'SECRET_KEY' },
  // "auth": "<base64 user:password>" in Docker config.json and .npmrc
  basicAuth: { category: 'Basic auth credentials', placeholder: 'CREDENTIALS' },
};

function isBase64Credentials(value) {
  const decoded = /^[A-Za-z0-9+/]+={0,2}$/.test(value) ? decodeBase64(value) : null;
  return Boolean(decoded && /^[^:\s]+:\S/.test(decoded));
}

/** Returns a KINDS key when the variable name suggests it holds a secret, else null. */
export function classifyKey(rawKey) {
  const words = keyWords(rawKey);
  while (words.length > 1 && IGNORED_KEY_SUFFIXES.has(words.at(-1))) words.pop();
  const last = words.at(-1);
  if (!last) return null;
  const prev = words.length > 1 ? words.at(-2) : '';

  if (/(?:password|passwd|passphrase|pwd)$/.test(last) || last === 'pass') return 'password';
  if (last.endsWith('secret')) return 'secret';
  if (last.endsWith('token')) {
    const qualifier = last === 'token' ? prev : last.slice(0, -5);
    return NON_SECRET_TOKEN_QUALIFIERS.has(qualifier) ? null : 'token';
  }
  if (last.endsWith('key')) {
    const qualifier = last === 'key' ? prev : last.slice(0, -3);
    if (qualifier.endsWith('api')) return 'apiKey';
    if (SECRET_KEY_QUALIFIERS.has(qualifier)) return 'key';
    if (last !== 'key' && COMPOUND_KEY_QUALIFIER.test(qualifier)) return 'key';
  }
  return null;
}

/**
 * Decides whether an assigned value is a literal secret.
 *   mode "quoted":  a string literal ("…", '…', <tag>…</tag>)
 *   mode "literal": an unquoted .env / shell / CLI value
 *   mode "code":    an unquoted value that may be a variable or expression
 */
function acceptValue(value, mode, info = {}) {
  if (value.length < 4 || value.length > QUOTE_SEARCH_LIMIT) return false;
  if (isPlaceholder(value) || isReference(value) || looksLikePath(value) || looksLikeUrl(value)) {
    return false;
  }
  if (mode === 'quoted') return !looksLikeProse(value);
  if (mode === 'literal') return true;

  if (/[(){}[\]<>]/.test(value)) return false; // calls, objects, generics
  if (/^[A-Za-z_$][\w$]*(?:\??\.[A-Za-z_$][\w$]*)+!?$/.test(value)) return false; // config.password
  if (/^[A-Za-z_$]+$/.test(value)) {
    // A bare identifier: treat it as a variable unless nothing suggests code.
    if (
      CODE_WORDS.has(value.toLowerCase()) ||
      hasSecretWord(value) ||
      /^[a-z]+[A-Z]/.test(value) ||
      info.trailingTerminator ||
      info.trailingCode
    ) {
      return false;
    }
  }
  return true;
}

function assignmentConfidence(value, kind) {
  if (isRandomLooking(value)) return HIGH;
  if (kind === 'password' && value.length >= 6 && /[^\p{L}]/u.test(value)) return HIGH;
  return POTENTIAL;
}

const CLOSERS = { ')': '(', ']': '[', '}': '{', '>': '<' };

/**
 * Drops sentence or Markdown punctuation glued to an unquoted value
 * (`pass`, → pass). A closing bracket is only dropped when the value has no
 * matching opener, so placeholders like <value> and [REDACTED_X] stay intact.
 */
function trimTrailingPunctuation(value) {
  let v = value;
  for (;;) {
    const last = v.at(-1);
    if (last === undefined) return v;
    if ('.,;:`'.includes(last) || (CLOSERS[last] && !v.includes(CLOSERS[last]))) v = v.slice(0, -1);
    else return v;
  }
}

function truncate(value, max = 48) {
  return value.length > max ? `${value.slice(0, max - 1)}…` : value;
}

/* ------------------------------------------------------------------------ */
/* Rule builders                                                             */
/* ------------------------------------------------------------------------ */

/**
 * A rule backed by one regular expression. `pattern` must use the g and d flags;
 * `group` selects the capture group (or list of alternatives) that holds the secret.
 * `check(value, match)` returns false to reject, true to accept, or an object of
 * overrides ({ confidence, detail, category, placeholder }).
 */
function regexRule({ id, category, placeholder, confidence = HIGH, pattern, group = 0, check }) {
  const groups = Array.isArray(group) ? group : [group];
  return {
    id,
    category,
    placeholder,
    confidence,
    *find(text) {
      for (const match of text.matchAll(pattern)) {
        const g = groups.find((i) => match[i] !== undefined);
        if (g === undefined) continue;
        const [start, end] = match.indices[g];
        const verdict = check ? check(match[g], match, start) : true;
        if (!verdict) continue;
        yield { start, end, ...(verdict === true ? {} : verdict) };
      }
    },
  };
}

/** A provider-specific token format: high confidence unless it is visibly masked. */
function providerRule(id, category, placeholder, pattern, prefix, extraCheck) {
  return regexRule({
    id,
    category,
    placeholder,
    pattern,
    check(value) {
      if (looksMasked(value) || (extraCheck && !extraCheck(value))) return false;
      const shown = value.match(prefix)?.[0];
      return shown ? { detail: `${shown}…` } : true;
    },
  });
}

/* ------------------------------------------------------------------------ */
/* Structural rules                                                          */
/* ------------------------------------------------------------------------ */

/** Skips whitespace and literal "\n" / "\r" escapes at both ends of [start, end). */
function trimSeparators(text, start, end) {
  let s = start;
  let e = end;
  for (;;) {
    if (s < e && /\s/.test(text[s])) s += 1;
    else if (s + 1 < e && text[s] === '\\' && (text[s + 1] === 'n' || text[s + 1] === 'r')) s += 2;
    else break;
  }
  for (;;) {
    if (e > s && /\s/.test(text[e - 1])) e -= 1;
    else if (e - 1 > s && text[e - 2] === '\\' && (text[e - 1] === 'n' || text[e - 1] === 'r')) e -= 2;
    else break;
  }
  return [s, e];
}

/**
 * PEM private keys. Only the base64 body is replaced, so the BEGIN/END lines
 * stay visible and JSON-escaped keys ("-----BEGIN…\nMIIE…\n-----END…") keep
 * their quoting. Unterminated (truncated) keys are redacted up to the last
 * base64 line.
 */
const privateKeyRule = {
  id: 'private-key',
  category: 'Private key',
  placeholder: 'PRIVATE_KEY',
  confidence: HIGH,
  *find(text) {
    const header = /-----BEGIN ((?:[A-Z0-9]+ ){0,3})PRIVATE KEY( BLOCK)?-----/g;
    const looseBody = /(?:[ \t]*(?:\r?\n|\\r?\\n)[ \t]*[A-Za-z0-9+/=]{4,}(?=[ \t]*(?:\r?\n|\\r?\\n|["',]|$)))+/y;
    let match;
    while ((match = header.exec(text))) {
      const label = `${match[1]}PRIVATE KEY${match[2] ?? ''}`;
      const bodyStart = header.lastIndex;
      const footer = `-----END ${label}-----`;
      const footerAt = text.indexOf(footer, bodyStart);
      let bodyEnd = footerAt;
      if (footerAt < 0) {
        looseBody.lastIndex = bodyStart;
        const loose = looseBody.exec(text);
        bodyEnd = bodyStart + (loose ? loose[0].length : 0);
      }
      const [start, end] = trimSeparators(text, bodyStart, bodyEnd);
      // Skip bodies that are already redacted or elided ("MIIE...", "[REDACTED_PRIVATE_KEY]").
      if (end > start && /[A-Za-z0-9+/=]{16,}/.test(text.slice(start, end))) {
        yield { start, end, detail: footerAt < 0 ? `${label} (no END line)` : label };
      }
      if (footerAt >= 0) header.lastIndex = footerAt + footer.length;
    }
  },
};

const jwtRule = regexRule({
  id: 'jwt',
  category: 'JSON Web Token',
  placeholder: 'JWT',
  pattern: /(?<![A-Za-z0-9_-])eyJ[A-Za-z0-9_-]{6,}\.ey[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]*(?![A-Za-z0-9_-])/dg,
  check(value) {
    try {
      const header = JSON.parse(decodeBase64(value.split('.')[0]) ?? '');
      if (header && typeof header.alg === 'string') return { detail: `alg ${truncate(header.alg, 12)}` };
    } catch {
      // Not decodable: still JWT-shaped, so report it as a potential match.
    }
    return { confidence: POTENTIAL, detail: 'JWT-shaped' };
  },
});

const DATABASE_SCHEMES = new Set([
  'postgres', 'postgresql', 'mysql', 'mariadb', 'mongodb', 'mongodb+srv', 'redis', 'rediss',
  'amqp', 'amqps', 'mssql', 'sqlserver', 'oracle', 'cockroachdb', 'clickhouse', 'couchdb',
  'neo4j', 'neo4j+s', 'cassandra', 'memcached', 'snowflake', 'db2',
]);

const urlCredentialsRule = regexRule({
  id: 'url-credentials',
  category: 'Credentials in URL',
  placeholder: 'PASSWORD',
  // scheme://user:password@host — the password may contain "@"; it ends at the last "@" before the host.
  pattern: /(?<![A-Za-z0-9+.-])([a-z][a-z0-9+.-]{1,30}):\/\/([^\s:/@'"`<>]*):([^\s/'"`<>]+)@(?=[^\s@/'"`<>])/dgi,
  group: 3,
  check(password, match) {
    if (password.length < 3 || isPlaceholder(password) || isReference(password)) return false;
    const scheme = match[1].toLowerCase();
    return DATABASE_SCHEMES.has(scheme)
      ? { category: 'Database credentials', detail: `${scheme}://` }
      : { detail: `${scheme}://` };
  },
});

const basicAuthFlagRule = regexRule({
  id: 'basic-auth-flag',
  category: 'Basic auth credentials',
  placeholder: 'PASSWORD',
  // curl -u user:pass, --user=user:pass (quoted or not)
  pattern: /(?<!\S)(?:-u|--user)(?:[ \t]+|=)(?:"([^"\n:]*):([^"\n]+)"|'([^'\n:]*):([^'\n]+)'|([^\s:'"`]+):([^\s'"`]+))/dg,
  group: [2, 4, 6],
  check(raw, match, start) {
    const user = match[1] ?? match[3] ?? match[5] ?? '';
    const password = match[6] !== undefined ? trimTrailingPunctuation(raw) : raw;
    if (/^\d+$/.test(user) && /^\d+$/.test(password)) return false; // docker -u 1000:1000
    if (password.length < 3 || isPlaceholder(password) || isReference(password)) return false;
    return { end: start + password.length, detail: '-u user:password' };
  },
});

const authorizationHeaderRule = regexRule({
  id: 'authorization-header',
  category: 'Authorization header',
  placeholder: 'TOKEN',
  pattern: /(?<![\w-])(?:proxy-)?authorization["']?[ \t]*[:=][ \t]*["']?(?:(bearer|basic|token|bot|apikey|api-key|key|sso-key|ssws)[ \t]+)?([A-Za-z0-9._~+/-]+=*)/dgi,
  group: 2,
  check(value, match) {
    const scheme = match[1] ? match[1][0].toUpperCase() + match[1].slice(1).toLowerCase() : '';
    if (scheme === 'Basic') {
      const decoded = decodeBase64(value);
      if (decoded && /^[^:\s]*:\S/.test(decoded)) {
        return { placeholder: 'CREDENTIALS', detail: 'Basic (user:password)' };
      }
    }
    if (!looksLikeToken(value, 8)) return false;
    return { detail: scheme ? `Authorization: ${scheme}` : 'Authorization' };
  },
});

/** Cookie headers (e.g. from a browser's "Copy as cURL"): the whole value is replaced. */
const cookieHeaderRule = regexRule({
  id: 'cookie-header',
  category: 'Cookie header',
  placeholder: 'COOKIES',
  pattern: /(?<![\w-])(set-)?cookie["']?[ \t]*:[ \t]*["']?([^\r\n"']+)/dgi,
  group: 2,
  check(raw, match) {
    const pairs = raw
      .split(';')
      .map((pair) => pair.trim().match(/^([^=\s]+)=(.*)$/))
      .filter(Boolean);
    if (pairs.length === 0) return false;
    const [start] = match.indices[2];
    if (match[1]) {
      // Set-Cookie: only the cookie value is secret, not Path/HttpOnly/… attributes.
      const value = pairs[0][2];
      if (value.length < 8 || isPlaceholder(value) || isReference(value)) return false;
      const valueStart = start + raw.indexOf('=') + 1;
      return {
        start: valueStart,
        end: valueStart + value.length,
        placeholder: 'COOKIE',
        confidence: looksLikeToken(value, 16) ? HIGH : POTENTIAL,
        detail: `Set-Cookie: ${truncate(pairs[0][1], 24)}`,
      };
    }
    const values = pairs.map((pair) => pair[2]);
    if (!values.some((v) => v.length >= 8 && !isPlaceholder(v) && !isReference(v))) return false;
    const trimmed = raw.replace(/[\s;]+$/, '');
    return {
      end: start + trimmed.length,
      confidence: values.some((v) => looksLikeToken(v, 16)) ? HIGH : POTENTIAL,
      detail: `${pairs.length} cookie${pairs.length === 1 ? '' : 's'}`,
    };
  },
});

/** curl -b / --cookie 'name=value; …' */
const cookieFlagRule = regexRule({
  id: 'cookie-flag',
  category: 'Cookie header',
  placeholder: 'COOKIES',
  pattern: /(?<!\S)(?:-b|--cookie)[ \t]+(?:'([^'\n]+)'|"([^"\n]+)"|([^\s'"]+))/dg,
  group: [1, 2, 3],
  check(raw) {
    const values = raw.split(';').map((pair) => pair.split('=')[1]?.trim()).filter(Boolean);
    if (!raw.includes('=') || !values.some((v) => v.length >= 8 && !isPlaceholder(v) && !isReference(v))) return false;
    return { confidence: values.some((v) => looksLikeToken(v, 16)) ? HIGH : POTENTIAL, detail: 'curl --cookie' };
  },
});

/** mysql -uroot -pPASSWORD (the password is glued to -p). */
const mysqlPasswordFlagRule = regexRule({
  id: 'mysql-password-flag',
  category: 'Password',
  placeholder: 'PASSWORD',
  pattern: /\b(?:mysql|mysqldump|mysqladmin|mysqlimport|mariadb|mariadb-dump)\b[^\n|;&]*?[ \t]-p(?:'([^'\n]+)'|"([^"\n]+)"|([^\s'"`-][^\s'"`]*))/dg,
  group: [1, 2, 3],
  check(raw, match, start) {
    const value = match[3] !== undefined ? trimTrailingPunctuation(raw) : raw;
    if (!acceptValue(value, 'literal')) return false;
    return { end: start + value.length, confidence: assignmentConfidence(value, 'password'), detail: 'mysql -p' };
  },
});

const bearerRule = regexRule({
  id: 'bearer-token',
  category: 'Bearer token',
  placeholder: 'TOKEN',
  pattern: /(?<![\w-])bearer[ \t]+([A-Za-z0-9._~+/-]{16,}=*)(?![\w.~+/=-])/dgi,
  group: 1,
  check(value) {
    if (!looksLikeToken(value, 16)) return false;
    return { confidence: isRandomLooking(value) ? HIGH : POTENTIAL, detail: 'Bearer' };
  },
});

const sqlPasswordRule = regexRule({
  id: 'sql-password',
  category: 'Password',
  placeholder: 'PASSWORD',
  // CREATE USER … WITH PASSWORD '…' / IDENTIFIED BY '…'
  pattern: /\b(?:PASSWORD|IDENTIFIED[ \t]+BY)[ \t]+(?:=[ \t]*)?'([^'\n]{1,256})'/dgi,
  group: 1,
  check(value) {
    if (!acceptValue(value, 'quoted')) return false;
    return { confidence: assignmentConfidence(value, 'password'), detail: 'SQL' };
  },
});

const xmlElementRule = regexRule({
  id: 'xml-element',
  category: 'Secret',
  placeholder: 'SECRET',
  // <password>…</password>; lowercase-first tags only, so JSX components are ignored.
  pattern: /<([a-z][\w.:-]*)(?:\s[^<>]*)?>([^<>\n]{1,512})<\/\1>/dg,
  group: 2,
  check(raw, match) {
    const tag = match[1].split(':').pop();
    const kind = classifyKey(tag);
    const value = raw.trim();
    if (!kind || !acceptValue(value, 'quoted')) return false;
    const lead = raw.length - raw.trimStart().length;
    const [start] = match.indices[2];
    return {
      ...KINDS[kind],
      start: start + lead,
      end: start + lead + value.length,
      confidence: assignmentConfidence(value, kind),
      detail: `<${truncate(tag, 32)}>`,
    };
  },
});

/* ------------------------------------------------------------------------ */
/* Generic assignments: KEY=value, key: "value", --flag value, ?token=…      */
/* ------------------------------------------------------------------------ */

function insideQuote(prefix, quote) {
  let count = 0;
  for (let i = 0; i < prefix.length; i += 1) {
    if (prefix[i] === '\\') i += 1;
    else if (prefix[i] === quote) count += 1;
  }
  return count % 2 === 1;
}

/**
 * Reads the value that starts at `pos`. Returns { start, end, quoted, after }
 * where [start, end) is the value without quotes and `after` is the index
 * just past it (including a closing quote), or null when there is no value.
 */
function readValue(text, pos, lineEnd, linePrefix, literal) {
  if (pos >= lineEnd) return null;
  const ch = text[pos];

  if (ch === '\\' && (text[pos + 1] === '"' || text[pos + 1] === "'")) {
    // Escaped JSON inside a string: {\"password\":\"…\"}
    const open = text.slice(pos, pos + 2);
    const close = text.indexOf(open, pos + 2);
    if (close < 0 || close > Math.min(lineEnd, pos + QUOTE_SEARCH_LIMIT)) return null;
    return { start: pos + 2, end: close, quoted: true, after: close + 2 };
  }

  if (ch === '"' || ch === "'" || ch === '`') {
    // An odd number of the same quote before the key means this quote *closes*
    // the string the key sits in ("Enter password: "), so there is no value.
    if (linePrefix !== null && insideQuote(linePrefix, ch)) return null;
    const limit = Math.min(lineEnd, pos + 1 + QUOTE_SEARCH_LIMIT);
    for (let i = pos + 1; i < limit; i += 1) {
      if (text[i] === '\\') i += 1;
      else if (text[i] === ch) {
        if (ch === '`' && text.slice(pos + 1, i).includes('${')) return null;
        return { start: pos + 1, end: i, quoted: true, after: i + 1 };
      }
    }
    return null;
  }

  const stop = literal
    ? /\s/g
    : // whitespace, quotes, or a separator that starts the next key (…;User Id=, &page=, , user:)
      /[\s'"`]|[&;](?=\s*[A-Za-z_][\w .[\]-]*=)|,(?=\s*["']?[A-Za-z_][\w.-]*["']?\s*[:=])/g;
  stop.lastIndex = pos;
  const hit = stop.exec(text);
  const end = hit && hit.index < lineEnd ? hit.index : lineEnd;
  return end > pos ? { start: pos, end, quoted: false, after: end } : null;
}

function lineAt(lineStarts, offset) {
  let lo = 0;
  let hi = lineStarts.length - 1;
  while (lo < hi) {
    const mid = (lo + hi + 1) >> 1;
    if (lineStarts[mid] <= offset) lo = mid;
    else hi = mid - 1;
  }
  return lo;
}

function lineBounds(text, lineStarts, offset) {
  const line = lineAt(lineStarts, offset);
  const start = lineStarts[line];
  const end = line + 1 < lineStarts.length ? lineStarts[line + 1] - 1 : text.length;
  return { start, end };
}

function evaluateAssignment(text, ctx, { key, kind, keyStart, valueStart, envStyle, flag, detail }) {
  const line = lineBounds(text, ctx.lineStarts, keyStart);
  const prefix = keyStart - line.start <= PREFIX_SCAN_LIMIT ? text.slice(line.start, keyStart) : null;
  const literal = envStyle || flag;
  const value = readValue(text, valueStart, line.end, prefix, literal);
  if (!value) return null;

  let raw = text.slice(value.start, value.end);
  let trailingTerminator = false;
  if (!value.quoted && !envStyle) {
    // Drop trailing punctuation that belongs to the surrounding code or sentence.
    // (.env values are taken verbatim: a password may legitimately end in ";".)
    const trimmed = trimTrailingPunctuation(raw);
    trailingTerminator = /[,;]/.test(raw.slice(trimmed.length));
    raw = trimmed;
  }
  const end = value.start + raw.length;
  const rest = text.slice(value.after, Math.min(line.end, value.after + 200)).trim();
  const trailingCode = rest !== '' && !/^(?:#|\/\/|--|;|,)/.test(rest);
  const mode = value.quoted ? 'quoted' : literal ? 'literal' : 'code';
  if (!acceptValue(raw, mode, { trailingTerminator, trailingCode })) return null;
  if (kind === 'basicAuth' && !isBase64Credentials(raw)) return null;

  return {
    start: value.start,
    end,
    after: value.after,
    ...KINDS[kind],
    confidence: kind === 'basicAuth' ? HIGH : assignmentConfidence(raw, kind),
    detail: detail ?? truncate(key),
  };
}

const assignmentRule = {
  id: 'assignment',
  category: 'Secret',
  placeholder: 'SECRET',
  confidence: POTENTIAL,
  *find(text, ctx) {
    // key = value, key: value, "key": "value", key := value, 'key' => 'value', $key = …
    const assign = /(?<![\w$./-])(\$?)((?:\\?["'`])?)([A-Za-z_][\w.-]*)\2[ \t]*(=>|:=|=(?![=~>])|:(?![:/=]))[ \t]*/g;
    // Type annotations between key and value: `password: str = "…"`, `token: string | null = …`
    const annotation = /[A-Za-z_][\w.]*(?:\[[^\]\n]*\])?(?:[ \t]*\|[ \t]*[A-Za-z_][\w.]*(?:\[[^\]\n]*\])?)*[ \t]+=(?![=>])[ \t]*/y;
    let match;
    while ((match = assign.exec(text))) {
      const key = match[3];
      const kind = classifyKey(key) ?? (/^_?auth$/i.test(key) ? 'basicAuth' : null);
      if (!kind) continue;
      const keyStart = match.index;
      const line = lineBounds(text, ctx.lineStarts, keyStart);
      const linePrefix = text.slice(Math.max(line.start, keyStart - PREFIX_SCAN_LIMIT), keyStart);
      const envStyle =
        /^[A-Za-z_][\w.-]*=$/.test(match[0]) &&
        /^\s*(?:(?:export|set|setx|ENV)\s+|-\s+)?$/.test(linePrefix);

      let valueStart = assign.lastIndex;
      if (match[4] === ':') {
        annotation.lastIndex = valueStart;
        const typed = annotation.exec(text);
        if (typed) valueStart += typed[0].length;
      }
      const found = evaluateAssignment(text, ctx, { key, kind, keyStart, valueStart, envStyle });
      if (found) {
        assign.lastIndex = Math.max(assign.lastIndex, found.after);
        yield found;
      }
    }

    // Command-line flags: --password <value>, --api-key=<value>
    const flag = /(?<![\w$./-])--([A-Za-z][\w-]*)(=|[ \t]+)/g;
    while ((match = flag.exec(text))) {
      const kind = classifyKey(match[1]);
      const valueStart = flag.lastIndex;
      if (!kind || (match[2] !== '=' && text[valueStart] === '-')) continue;
      const found = evaluateAssignment(text, ctx, {
        key: match[1],
        kind,
        keyStart: match.index,
        valueStart,
        flag: true,
        detail: truncate(`--${match[1]}`),
      });
      if (found) yield found;
    }
  },
};

/* ------------------------------------------------------------------------ */
/* Rule list (order = priority when matches overlap)                         */
/* ------------------------------------------------------------------------ */

const RULES = [
  // Containers first: a cookie header can hold several secrets, and must be
  // redacted as a whole rather than lose to a JWT inside it.
  cookieHeaderRule,
  cookieFlagRule,
  providerRule('aws-access-key-id', 'AWS access key ID', 'AWS_ACCESS_KEY',
    /(?<![A-Za-z0-9])(?:AKIA|ASIA|ABIA|ACCA)[A-Z2-7]{16}(?![A-Za-z0-9])/dg, /^.{4}/),
  providerRule('github-token', 'GitHub token', 'GITHUB_TOKEN',
    /(?<![A-Za-z0-9_])(?:gh[pousr]_[A-Za-z0-9]{36,251}|github_pat_[A-Za-z0-9_]{50,240})(?![A-Za-z0-9_])/dg,
    /^(?:github_pat_|gh[pousr]_)/),
  providerRule('gitlab-token', 'GitLab token', 'GITLAB_TOKEN',
    /(?<![A-Za-z0-9_-])gl(?:pat|ptt|dt|rt)-[A-Za-z0-9_-]{20,}(?![A-Za-z0-9_-])/dg, /^gl[a-z]+-/),
  providerRule('stripe-key', 'Stripe secret key', 'STRIPE_KEY',
    /(?<![A-Za-z0-9_])(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{20,247}(?![A-Za-z0-9_])/dg,
    /^[a-z]{2}_(?:live|test)_/),
  providerRule('stripe-webhook-secret', 'Stripe webhook secret', 'STRIPE_WEBHOOK_SECRET',
    /(?<![A-Za-z0-9_])whsec_[A-Za-z0-9+/]{24,}={0,2}(?![A-Za-z0-9_+/=])/dg, /^whsec_/),
  providerRule('slack-token', 'Slack token', 'SLACK_TOKEN',
    /(?<![A-Za-z0-9_-])(?:xox[abposre]|xapp)-[A-Za-z0-9]+(?:-[A-Za-z0-9]+)+(?![A-Za-z0-9_-])/dg,
    /^[a-z]+-/, (v) => v.length >= 24),
  regexRule({
    id: 'slack-webhook',
    category: 'Slack webhook URL',
    placeholder: 'SLACK_WEBHOOK',
    pattern: /https:\/\/hooks\.slack\.com\/(?:services|workflows|triggers)\/([A-Za-z0-9]+(?:\/[A-Za-z0-9]+){1,3})/dg,
    group: 1,
    check: (path) => path.length >= 24 && !looksMasked(path) && { detail: 'hooks.slack.com' },
  }),
  providerRule('openai-key', 'OpenAI API key', 'OPENAI_KEY',
    /(?<![A-Za-z0-9_-])sk-(?:(?:proj|svcacct|admin)-[A-Za-z0-9_-]{20,}|[A-Za-z0-9]{20}T3BlbkFJ[A-Za-z0-9]{20})(?![A-Za-z0-9_-])/dg,
    /^sk-(?:proj-|svcacct-|admin-)?/),
  providerRule('anthropic-key', 'Anthropic API key', 'ANTHROPIC_KEY',
    /(?<![A-Za-z0-9_-])sk-ant-[a-z]{2,10}\d{0,3}-[A-Za-z0-9_-]{20,}(?![A-Za-z0-9_-])/dg, /^sk-ant-/),
  providerRule('google-api-key', 'Google API key', 'GOOGLE_API_KEY',
    /(?<![A-Za-z0-9_-])AIza[A-Za-z0-9_-]{35}(?![A-Za-z0-9_-])/dg, /^AIza/),
  providerRule('google-oauth-secret', 'Google OAuth client secret', 'GOOGLE_CLIENT_SECRET',
    /(?<![A-Za-z0-9_-])GOCSPX-[A-Za-z0-9_-]{28}(?![A-Za-z0-9_-])/dg, /^GOCSPX-/),
  providerRule('npm-token', 'npm token', 'NPM_TOKEN',
    /(?<![A-Za-z0-9_])npm_[A-Za-z0-9]{36}(?![A-Za-z0-9_])/dg, /^npm_/),
  providerRule('pypi-token', 'PyPI token', 'PYPI_TOKEN',
    /(?<![A-Za-z0-9_-])pypi-AgE[A-Za-z0-9_-]{50,}(?![A-Za-z0-9_-])/dg, /^pypi-/),
  providerRule('sendgrid-key', 'SendGrid API key', 'SENDGRID_KEY',
    /(?<![A-Za-z0-9_-])SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}(?![A-Za-z0-9_-])/dg, /^SG\./),
  providerRule('huggingface-token', 'Hugging Face token', 'HUGGINGFACE_TOKEN',
    /(?<![A-Za-z0-9_])hf_[A-Za-z0-9]{30,}(?![A-Za-z0-9_])/dg, /^hf_/,
    (v) => /\d/.test(v) && /[a-z]/.test(v.slice(3)) && /[A-Z]/.test(v)),
  privateKeyRule,
  jwtRule,
  urlCredentialsRule,
  basicAuthFlagRule,
  mysqlPasswordFlagRule,
  authorizationHeaderRule,
  bearerRule,
  regexRule({
    id: 'generic-sk-key',
    category: 'Secret key (sk-…)',
    placeholder: 'API_KEY',
    confidence: POTENTIAL,
    pattern: /(?<![A-Za-z0-9_-])sk-[A-Za-z0-9][A-Za-z0-9_-]{31,}(?![A-Za-z0-9_-])/dg,
    check: (v) => /\d/.test(v) && /[A-Za-z]/.test(v.slice(3)) && !looksMasked(v) && { detail: 'sk-…' },
  }),
  sqlPasswordRule,
  xmlElementRule,
  assignmentRule,
];

export const RULE_IDS = RULES.map((rule) => rule.id);

/* ------------------------------------------------------------------------ */
/* Scanning and redaction                                                    */
/* ------------------------------------------------------------------------ */

function buildLineStarts(text) {
  const starts = [0];
  for (let i = text.indexOf('\n'); i !== -1; i = text.indexOf('\n', i + 1)) starts.push(i + 1);
  return starts;
}

/**
 * Keeps the highest-priority candidate wherever spans overlap. Candidates are
 * visited by priority, then position, then length (longest first), so the
 * outcome never depends on the order rules happened to emit them.
 */
function resolveOverlaps(candidates) {
  const ordered = candidates.slice().sort(
    (a, b) => a.priority - b.priority || a.start - b.start || b.end - b.start - (a.end - a.start),
  );
  const accepted = []; // kept sorted by start
  for (const candidate of ordered) {
    let lo = 0;
    let hi = accepted.length;
    while (lo < hi) {
      const mid = (lo + hi) >> 1;
      if (accepted[mid].start < candidate.start) lo = mid + 1;
      else hi = mid;
    }
    const prev = accepted[lo - 1];
    const next = accepted[lo];
    if ((prev && prev.end > candidate.start) || (next && next.start < candidate.end)) continue;
    accepted.splice(lo, 0, candidate);
  }
  return accepted;
}

/**
 * Builds the redacted text for the given findings. Returns the text plus the
 * [start, end) ranges of each placeholder inside it (for highlighting).
 * Findings that overlap an earlier one are ignored.
 */
export function redact(input, findings) {
  const text = typeof input === 'string' ? input : '';
  const ordered = [...findings].sort((a, b) => a.start - b.start || a.end - b.end);
  let out = '';
  let cursor = 0;
  const ranges = [];
  for (const finding of ordered) {
    if (finding.start < cursor || finding.end > text.length || finding.end <= finding.start) continue;
    out += text.slice(cursor, finding.start);
    ranges.push({ start: out.length, end: out.length + finding.placeholder.length, id: finding.id });
    out += finding.placeholder;
    cursor = finding.end;
  }
  out += text.slice(cursor);
  return { text: out, ranges };
}

function summarize(findings) {
  const counts = new Map();
  for (const f of findings) counts.set(f.category, (counts.get(f.category) || 0) + 1);
  const categories = [...counts]
    .map(([category, count]) => ({ category, count }))
    .sort((a, b) => b.count - a.count || a.category.localeCompare(b.category));
  const high = findings.filter((f) => f.confidence === HIGH).length;
  return { total: findings.length, high, potential: findings.length - high, categories };
}

/**
 * Scans text for likely secrets. Never mutates or stores the input; findings
 * carry offsets and labels but not the secret values themselves.
 */
export function scanText(input) {
  const text = typeof input === 'string' ? input : '';
  const ctx = { lineStarts: buildLineStarts(text) };
  const candidates = [];

  RULES.forEach((rule, priority) => {
    for (const hit of rule.find(text, ctx)) {
      if (!(hit.end > hit.start)) continue;
      candidates.push({
        ruleId: rule.id,
        category: hit.category ?? rule.category,
        confidence: hit.confidence ?? rule.confidence,
        placeholder: hit.placeholder ?? rule.placeholder,
        detail: hit.detail ?? '',
        start: hit.start,
        end: hit.end,
        priority,
      });
    }
  });

  const findings = resolveOverlaps(candidates).map((c) => {
    const line = lineAt(ctx.lineStarts, c.start);
    return {
      id: `${c.ruleId}:${c.start}`,
      ruleId: c.ruleId,
      category: c.category,
      confidence: c.confidence,
      placeholder: `[REDACTED_${c.placeholder}]`,
      detail: c.detail,
      start: c.start,
      end: c.end,
      line: line + 1,
      column: c.start - ctx.lineStarts[line] + 1,
      endLine: lineAt(ctx.lineStarts, c.end - 1) + 1,
    };
  });

  const redaction = redact(text, findings);
  return {
    findings,
    redacted: redaction.text,
    ranges: redaction.ranges,
    summary: summarize(findings),
    lineCount: text ? ctx.lineStarts.length : 0,
  };
}
