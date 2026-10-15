// Static checks for the extension: manifest validity, permissions, CSP,
// file references, JavaScript syntax, and a privacy scan for APIs that could
// send, store or log pasted text.
//
// Run: npm run check             (checks ./extension)
//      node scripts/check.mjs DIR (checks another copy, e.g. a build)

import { readFileSync, readdirSync, statSync, existsSync } from 'node:fs';
import { join, extname, relative, resolve } from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const ROOT = fileURLToPath(new URL('..', import.meta.url));
const EXT = process.argv[2] ? resolve(process.argv[2]) : join(ROOT, 'extension');

const failures = [];
const pass = (message) => console.log(`  ok   ${message}`);
const fail = (message) => {
  failures.push(message);
  console.log(`  FAIL ${message}`);
};
const check = (condition, message) => (condition ? pass(message) : fail(message));

function listFiles(dir) {
  return readdirSync(dir).flatMap((name) => {
    const path = join(dir, name);
    return statSync(path).isDirectory() ? listFiles(path) : [path];
  });
}

function pngSize(path) {
  const data = readFileSync(path);
  const signature = data.subarray(0, 8).toString('hex');
  if (signature !== '89504e470d0a1a0a' || data.subarray(12, 16).toString('ascii') !== 'IHDR') return null;
  return { width: data.readUInt32BE(16), height: data.readUInt32BE(20) };
}

/* ---------------------------------------------------------------- manifest */

console.log('Manifest');
let manifest = {};
try {
  manifest = JSON.parse(readFileSync(join(EXT, 'manifest.json'), 'utf8'));
  pass('manifest.json is valid JSON');
} catch (error) {
  fail(`manifest.json does not parse: ${error.message}`);
}

check(manifest.manifest_version === 3, 'manifest_version is 3');
check(typeof manifest.name === 'string' && manifest.name.length > 0 && manifest.name.length <= 75, 'name is set (≤ 75 chars)');
check(/^\d+(\.\d+){0,3}$/.test(manifest.version ?? ''), `version "${manifest.version}" is a valid Chrome version string`);
check((manifest.description ?? '').length > 0 && manifest.description.length <= 132, 'description is set (≤ 132 chars)');

const popup = manifest.action?.default_popup;
check(Boolean(popup) && existsSync(join(EXT, popup)), `action.default_popup "${popup}" exists`);

const iconSets = [manifest.icons ?? {}, manifest.action?.default_icon ?? {}];
for (const icons of iconSets) {
  for (const [size, file] of Object.entries(icons)) {
    const path = join(EXT, file);
    const dims = existsSync(path) ? pngSize(path) : null;
    check(dims && dims.width === Number(size) && dims.height === Number(size), `icon ${file} is a ${size}×${size} PNG`);
  }
}

// MaskPaste needs nothing beyond its action popup.
const FORBIDDEN_KEYS = [
  'permissions', 'optional_permissions', 'host_permissions', 'optional_host_permissions',
  'content_scripts', 'background', 'web_accessible_resources', 'externally_connectable',
  'chrome_url_overrides', 'devtools_page', 'options_page', 'options_ui', 'oauth2',
  'declarative_net_request', 'side_panel', 'commands', 'omnibox', 'update_url',
];
for (const key of FORBIDDEN_KEYS) check(!(key in manifest), `no "${key}"`);

const csp = manifest.content_security_policy?.extension_pages ?? '';
const directives = Object.fromEntries(
  csp.split(';').map((d) => d.trim().split(/\s+/)).filter((d) => d[0]).map(([name, ...values]) => [name, values]),
);
check(directives['default-src']?.join(' ') === "'none'", "CSP default-src is 'none' (blocks fetch/XHR/WebSocket and remote resources)");
check(directives['script-src']?.join(' ') === "'self'", "CSP script-src is 'self' only");
check(!directives['connect-src'], 'CSP does not re-open connect-src');
check(!/unsafe-|https?:|\*|data:|blob:/.test(csp), 'CSP has no unsafe-*, remote, wildcard, data: or blob: sources');

/* ------------------------------------------------------------------- files */

console.log('\nFiles');
const files = listFiles(EXT);
const allowed = new Set(['.js', '.html', '.css', '.json', '.png']);
for (const file of files) check(allowed.has(extname(file)), `${relative(ROOT, file)} is an expected file type`);
const totalBytes = files.reduce((sum, f) => sum + statSync(f).size, 0);
check(totalBytes < 250_000, `extension size is ${(totalBytes / 1024).toFixed(1)} KB`);

const html = readFileSync(join(EXT, popup ?? 'popup.html'), 'utf8');
for (const [, ref] of html.matchAll(/\b(?:src|href)="([^"]+)"/g)) {
  check(!/^[a-z]+:/i.test(ref) && existsSync(join(EXT, ref)), `popup references local file "${ref}"`);
}
check(!/<script(?![^>]*\bsrc=)[^>]*>/i.test(html), 'popup.html has no inline <script> blocks');
check(!/\son[a-z]+\s*=/i.test(html), 'popup.html has no inline event handlers');
check(!/\sstyle\s*=/i.test(html), 'popup.html has no inline style attributes (CSP would block them)');
check(/<textarea[^>]*spellcheck="false"/.test(html), 'textarea disables spellcheck (cloud spellcheck services never see pasted text)');

/* ------------------------------------------------------------------ syntax */

console.log('\nJavaScript syntax');
for (const file of files.filter((f) => extname(f) === '.js')) {
  const result = spawnSync(process.execPath, ['--check', file], { encoding: 'utf8' });
  check(result.status === 0, `${relative(ROOT, file)} parses${result.status ? `: ${result.stderr.trim()}` : ''}`);
}

/* ----------------------------------------------------------------- privacy */

console.log('\nPrivacy scan (extension/)');
const PRIVACY_RULES = [
  [/\bfetch\s*\(/, 'fetch()'],
  [/\bXMLHttpRequest\b/, 'XMLHttpRequest'],
  [/\bWebSocket\b/, 'WebSocket'],
  [/\bEventSource\b/, 'EventSource'],
  [/\bsendBeacon\b/, 'navigator.sendBeacon'],
  [/\bimportScripts\b/, 'importScripts'],
  [/\bchrome\.(?:storage|tabs|scripting|runtime\.sendMessage|runtime\.connect)\b/, 'chrome.* storage/tab/messaging APIs'],
  [/\b(?:localStorage|sessionStorage|indexedDB|caches)\b/, 'web storage'],
  [/\bdocument\.cookie\b/, 'document.cookie'],
  [/\bconsole\.\w+\s*\(/, 'console logging'],
  [/\beval\s*\(|\bnew\s+Function\s*\(/, 'eval / new Function'],
  [/\.(?:innerHTML|outerHTML)\s*=|insertAdjacentHTML|document\.write/, 'HTML string injection'],
  [/\bclipboard\.read/, 'clipboard reading'],
  [/https?:\/\//, 'hard-coded http(s) URL'],
];
for (const file of files.filter((f) => ['.js', '.html'].includes(extname(f)))) {
  const lines = readFileSync(file, 'utf8').split('\n');
  const hits = [];
  lines.forEach((line, i) => {
    const code = line.trim();
    if (code.startsWith('//') || code.startsWith('*') || code.startsWith('/*')) return; // comments
    for (const [pattern, name] of PRIVACY_RULES) if (pattern.test(line)) hits.push(`${name} (line ${i + 1})`);
  });
  check(hits.length === 0, `${relative(ROOT, file)}: no network, storage, logging or eval APIs${hits.length ? ` — found ${hits.join(', ')}` : ''}`);
}

const clipboardWrites = files
  .filter((f) => extname(f) === '.js')
  .flatMap((f) => [...readFileSync(f, 'utf8').matchAll(/clipboard\.writeText|execCommand\(\s*'copy'/g)].map(() => f));
check(
  clipboardWrites.every((f) => f.endsWith('popup.js')),
  'clipboard writes happen only in popup.js (inside the Copy button handler)',
);

console.log(failures.length ? `\n${failures.length} check(s) failed.` : '\nAll checks passed.');
process.exit(failures.length ? 1 : 0);
