// End-to-end smoke test in a real Chromium.
//
// Loads ./extension unpacked into a throwaway headless profile, opens the
// extension's popup page, drives the UI over the Chrome DevTools Protocol, and
// checks privacy properties: no network requests, nothing stored, CSP blocks
// fetch, nothing logged.
//
// Needs Chromium or Chrome for Testing: branded Google Chrome ignores
// --load-extension since version 137. Auto-detects Playwright's cached builds,
// or set CHROME_PATH.
//
// Usage: npm run test:browser [-- --screenshots <dir>]
// No npm dependencies: uses Node's built-in WebSocket (Node 22+).

import { spawn } from 'node:child_process';
import { mkdtempSync, rmSync, existsSync, readdirSync, realpathSync, writeFileSync, mkdirSync } from 'node:fs';
import { tmpdir, homedir } from 'node:os';
import { join, resolve } from 'node:path';
import { createHash } from 'node:crypto';
import { fileURLToPath } from 'node:url';

import { scanText } from '../extension/detector.js';
import { FAKE, fakePem, fakeJwt } from '../test/helpers.js';

const EXT_DIR = realpathSync(fileURLToPath(new URL('../extension', import.meta.url)));
const screenshotArg = process.argv.indexOf('--screenshots');
const SCREENSHOT_DIR = screenshotArg > 0 ? resolve(process.argv[screenshotArg + 1]) : null;

/* ------------------------------------------------------------ find Chrome */

function findChrome() {
  if (process.env.CHROME_PATH) return process.env.CHROME_PATH;
  const caches = [
    join(homedir(), 'Library/Caches/ms-playwright'),
    join(homedir(), '.cache/ms-playwright'),
    join(process.env.LOCALAPPDATA ?? '', 'ms-playwright'),
  ];
  const inside = [
    'chrome-mac-arm64/Google Chrome for Testing.app/Contents/MacOS/Google Chrome for Testing',
    'chrome-mac-x64/Google Chrome for Testing.app/Contents/MacOS/Google Chrome for Testing',
    'chrome-mac/Google Chrome for Testing.app/Contents/MacOS/Google Chrome for Testing',
    'chrome-mac/Chromium.app/Contents/MacOS/Chromium',
    'chrome-linux64/chrome',
    'chrome-linux/chrome',
    'chrome-win64/chrome.exe',
    'chrome-win/chrome.exe',
  ];
  for (const cache of caches) {
    if (!existsSync(cache)) continue;
    const builds = readdirSync(cache)
      .filter((name) => /^chromium-\d+$/.test(name))
      .sort((a, b) => Number(b.split('-')[1]) - Number(a.split('-')[1]));
    for (const build of builds) {
      for (const rel of inside) if (existsSync(join(cache, build, rel))) return join(cache, build, rel);
    }
  }
  return [
    '/Applications/Chromium.app/Contents/MacOS/Chromium',
    '/Applications/Google Chrome for Testing.app/Contents/MacOS/Google Chrome for Testing',
    '/usr/bin/chromium',
    '/usr/bin/chromium-browser',
  ].find(existsSync);
}

/** Chrome derives an unpacked extension's ID from the SHA-256 of its path. */
function extensionIdFor(path) {
  const hex = createHash('sha256').update(path).digest('hex').slice(0, 32);
  return [...hex].map((c) => String.fromCharCode(97 + parseInt(c, 16))).join('');
}

/* ------------------------------------------------------------- CDP client */

class Cdp {
  constructor(url) {
    this.ws = new WebSocket(url);
    this.nextId = 0;
    this.pending = new Map();
    this.listeners = new Set();
  }

  open() {
    return new Promise((resolveOpen, rejectOpen) => {
      this.ws.addEventListener('open', resolveOpen, { once: true });
      this.ws.addEventListener('error', rejectOpen, { once: true });
      this.ws.addEventListener('message', (event) => {
        const msg = JSON.parse(event.data);
        if (msg.id && this.pending.has(msg.id)) {
          const { ok, fail: reject, method } = this.pending.get(msg.id);
          this.pending.delete(msg.id);
          if (msg.error) reject(new Error(`${method}: ${msg.error.message}`));
          else ok(msg.result);
        } else if (msg.method) {
          for (const listener of this.listeners) listener(msg);
        }
      });
    });
  }

  send(method, params = {}, sessionId) {
    const id = ++this.nextId;
    this.ws.send(JSON.stringify({ id, method, params, ...(sessionId ? { sessionId } : {}) }));
    return new Promise((ok, reject) => this.pending.set(id, { ok, fail: reject, method }));
  }

  on(listener) {
    this.listeners.add(listener);
  }
}

/* ------------------------------------------------------------------ setup */

const results = [];
function check(condition, message, extra = '') {
  results.push({ ok: Boolean(condition), message });
  console.log(`  ${condition ? 'ok  ' : 'FAIL'} ${message}${!condition && extra ? ` (${extra})` : ''}`);
}

const chromePath = findChrome();
if (!chromePath) {
  console.error('No Chromium / Chrome for Testing found. Install one (e.g. `npx playwright install chromium`) or set CHROME_PATH.');
  process.exit(1);
}

const profile = mkdtempSync(join(tmpdir(), 'maskpaste-smoke-'));
const chrome = spawn(chromePath, [
  '--headless=new',
  '--remote-debugging-port=0',
  `--user-data-dir=${profile}`,
  '--no-first-run',
  '--no-default-browser-check',
  '--disable-background-networking',
  '--disable-component-update',
  '--disable-sync',
  `--disable-extensions-except=${EXT_DIR}`,
  `--load-extension=${EXT_DIR}`,
  'about:blank',
]);

const chromeExited = new Promise((resolveExit) => chrome.once('exit', resolveExit));
let cleanedUp = false;
function removeProfile() {
  try {
    rmSync(profile, { recursive: true, force: true, maxRetries: 5, retryDelay: 200 });
  } catch {
    console.warn(`Could not remove the temporary profile at ${profile}`);
  }
}
async function cleanup() {
  if (cleanedUp) return;
  cleanedUp = true;
  chrome.kill('SIGKILL');
  await Promise.race([chromeExited, new Promise((r) => setTimeout(r, 5000))]);
  removeProfile();
}
process.on('exit', () => {
  if (!cleanedUp) {
    chrome.kill('SIGKILL');
    removeProfile();
  }
});

const browserUrl = await new Promise((resolveUrl, rejectUrl) => {
  let stderr = '';
  const timer = setTimeout(() => rejectUrl(new Error(`Chrome did not start:\n${stderr}`)), 20_000);
  chrome.stderr.on('data', (chunk) => {
    stderr += chunk;
    const match = stderr.match(/DevTools listening on (ws:\/\/\S+)/);
    if (match) {
      clearTimeout(timer);
      resolveUrl(match[1]);
    }
  });
  chrome.on('exit', (code) => rejectUrl(new Error(`Chrome exited with ${code}:\n${stderr}`)));
});

const cdp = new Cdp(browserUrl);
await cdp.open();
const version = await cdp.send('Browser.getVersion');
console.log(`Browser: ${version.product} (${chromePath})`);

const extensionId = extensionIdFor(EXT_DIR);
const origin = `chrome-extension://${extensionId}`;
const { targetId } = await cdp.send('Target.createTarget', { url: 'about:blank' });
const { sessionId } = await cdp.send('Target.attachToTarget', { targetId, flatten: true });
const send = (method, params) => cdp.send(method, params, sessionId);

const requests = [];
const consoleMessages = [];
const exceptions = [];
const failedLoads = new Map();
cdp.on((msg) => {
  if (msg.sessionId !== sessionId) return;
  if (msg.method === 'Network.requestWillBeSent') requests.push(msg.params.request.url);
  if (msg.method === 'Network.loadingFailed') failedLoads.set(msg.params.requestId, msg.params);
  if (msg.method === 'Runtime.consoleAPICalled') consoleMessages.push(msg.params.type);
  if (msg.method === 'Runtime.exceptionThrown') exceptions.push(msg.params.exceptionDetails.text);
});

await send('Page.enable');
await send('Runtime.enable');
await send('Network.enable');
await send('Emulation.setFocusEmulationEnabled', { enabled: true });
// 600px is the tallest an extension popup can be; content beyond it scrolls.
await send('Emulation.setDeviceMetricsOverride', { width: 460, height: 600, deviceScaleFactor: 2, mobile: false });
await send('Emulation.setEmulatedMedia', { features: [{ name: 'prefers-color-scheme', value: 'light' }] });

const loaded = new Promise((resolveLoad) => {
  const listener = (msg) => {
    if (msg.sessionId === sessionId && msg.method === 'Page.loadEventFired') {
      cdp.listeners.delete(listener);
      resolveLoad();
    }
  };
  cdp.on(listener);
});
const nav = await send('Page.navigate', { url: `${origin}/popup.html` });
if (nav.errorText) {
  console.error(`Could not open the extension popup (${nav.errorText}). Did the extension fail to load?`);
  process.exit(1);
}
await loaded;

async function evaluate(expression, { gesture = false } = {}) {
  const { result, exceptionDetails } = await send('Runtime.evaluate', {
    expression,
    awaitPromise: true,
    returnByValue: true,
    userGesture: gesture,
  });
  if (exceptionDetails) throw new Error(`${exceptionDetails.text} ${exceptionDetails.exception?.description ?? ''}`);
  return result.value;
}

async function waitFor(expression, timeout = 3000) {
  const deadline = Date.now() + timeout;
  while (Date.now() < deadline) {
    if (await evaluate(expression)) return true;
    await new Promise((r) => setTimeout(r, 50));
  }
  return false;
}

const click = (id) => evaluate(`document.getElementById(${JSON.stringify(id)}).click()`, { gesture: true });
const text = (id) => evaluate(`document.getElementById(${JSON.stringify(id)}).textContent.trim()`);
const visible = (id) => evaluate(`!document.getElementById(${JSON.stringify(id)}).closest('[hidden]')`);
const setInput = (value) =>
  evaluate(`(() => { const i = document.getElementById('input'); i.value = ${JSON.stringify(value)};
    i.dispatchEvent(new Event('input', { bubbles: true })); })()`);
const inputValue = () => evaluate("document.getElementById('input').value");

/** Saves what the 600px popup shows, and with `full` the whole scrollable page. */
async function screenshot(name, { full = false } = {}) {
  if (!SCREENSHOT_DIR) return;
  mkdirSync(SCREENSHOT_DIR, { recursive: true });
  await evaluate('window.scrollTo(0, 0)');
  await new Promise((r) => setTimeout(r, 300)); // let colour transitions finish
  const height = full ? await evaluate('Math.ceil(document.body.getBoundingClientRect().height)') : 600;
  const { data } = await send('Page.captureScreenshot', {
    format: 'png',
    ...(full ? { clip: { x: 0, y: 0, width: 460, height, scale: 1 }, captureBeyondViewport: true } : {}),
  });
  writeFileSync(join(SCREENSHOT_DIR, `${name}.png`), Buffer.from(data, 'base64'));
}

/* ------------------------------------------------------------------ tests */

const SAMPLE = [
  '# .env pasted from a bug report',
  `DB_PASSWORD="${FAKE.password}"`,
  `GITHUB_TOKEN=${FAKE.githubPat}`,
  'LOG_LEVEL=debug',
  `curl -H 'Authorization: Bearer ${FAKE.token}' https://api.example.com/v1/items`,
  `DATABASE_URL=postgres://app:${FAKE.dbPassword}@db.internal:5432/app`,
  `id_token=${fakeJwt()}`,
  'const total = items.reduce((sum, item) => sum + item.price, 0);',
  '',
  fakePem('RSA PRIVATE KEY', 3),
].join('\n');
const expected = scanText(SAMPLE);

try {
  console.log('\nLoad');
  check((await evaluate('document.title')) === 'MaskPaste', 'extension popup page loads from chrome-extension://');
  check((await evaluate('document.activeElement.id')) === 'input', 'text area is focused on open (ready to paste)');
  check((await visible('empty')) && !(await visible('results')), 'empty state is shown before the first scan');
  const shortcut = process.platform === 'darwin' ? '⌘↵' : 'Ctrl+↵';
  check((await text('shortcut')) === shortcut, `scan shortcut hint matches the platform (${shortcut})`);
  await screenshot('1-empty-light');

  console.log('\nEmpty input');
  await click('scan');
  check((await text('status')).startsWith('Nothing to scan'), 'scanning empty input shows a helpful message');

  console.log('\nScan');
  await setInput(SAMPLE);
  await click('scan');
  check(await visible('results'), 'results appear after Scan');
  const items = await evaluate("document.querySelectorAll('#findings li').length");
  check(items === expected.findings.length, `${items} findings listed (detector reports ${expected.findings.length})`);
  check(
    (await text('summary-title')) === `${expected.summary.total} possible secrets found`,
    'summary shows the finding count',
  );
  const chips = await evaluate("[...document.querySelectorAll('#categories li')].map((li) => li.textContent)");
  check(chips.length === expected.summary.categories.length, `category chips: ${chips.join(', ')}`);
  const lines = await evaluate("[...document.querySelectorAll('.locate')].map((b) => b.textContent)");
  check(lines.join('|') === 'Line 2|Line 3|Line 5|Line 6|Line 7|Lines 11–13', `line numbers: ${lines.join(', ')}`);
  check((await evaluate("document.getElementById('preview').textContent")) === expected.redacted, 'redacted preview matches the detector output');
  check((await inputValue()) === SAMPLE, 'original input is unchanged after scanning');
  const preview = await evaluate("document.getElementById('preview').textContent");
  check(
    [FAKE.password, FAKE.githubPat, FAKE.token, FAKE.dbPassword].every((s) => !preview.includes(s)),
    'no secret value appears in the preview',
  );
  const copyBox = await evaluate("(() => { const r = document.getElementById('copy').getBoundingClientRect(); return [r.top, r.bottom, innerHeight]; })()");
  check(copyBox[0] >= 0 && copyBox[1] <= copyBox[2], 'Copy button is visible without scrolling in a 600px popup');
  await screenshot('2-results-light');
  await screenshot('2-results-light-full', { full: true });

  console.log('\nReview');
  await evaluate("document.querySelector('#findings input').click()", { gesture: true });
  check(
    (await evaluate("document.getElementById('preview').textContent")).includes(`DB_PASSWORD="${FAKE.password}"`),
    'unchecking a finding keeps that value in the preview',
  );
  check((await text('redaction-count')) === `${expected.findings.length - 1} of ${expected.findings.length} findings redacted`, 'redaction count updates');
  await evaluate("document.querySelector('#findings input').click()", { gesture: true });

  const last = expected.findings.at(-1);
  await evaluate("[...document.querySelectorAll('.locate')].at(-1).click()", { gesture: true });
  const selection = await evaluate("(() => { const i = document.getElementById('input'); return [document.activeElement === i, i.selectionStart, i.selectionEnd, i.scrollTop]; })()");
  check(selection[0] && selection[1] === last.start && selection[2] === last.end, 'locate button selects the secret in the input');
  check(selection[3] > 0, `text area scrolls to the selection (scrollTop ${selection[3]})`);

  console.log('\nCopy');
  await click('copy');
  check(await waitFor("document.getElementById('status').textContent.startsWith('Copied')"), 'copy reports success (no clipboard permission requested)');
  await cdp.send('Browser.grantPermissions', { origin, permissions: ['clipboardReadWrite', 'clipboardSanitizedWrite'] });
  const clipboard = await evaluate('navigator.clipboard.readText()', { gesture: true }).catch((e) => `read failed: ${e.message}`);
  check(clipboard === expected.redacted, 'clipboard holds exactly the redacted text', clipboard.slice(0, 60));
  await cdp.send('Browser.resetPermissions');

  console.log('\nStale results');
  await setInput(`${SAMPLE}\nextra`);
  check(
    (await evaluate("document.getElementById('copy').disabled && document.getElementById('replace').disabled")) &&
      (await text('status')).startsWith('The text changed'),
    'editing after a scan disables Copy/Replace and asks for a rescan',
  );
  await setInput(SAMPLE);
  check(!(await evaluate("document.getElementById('copy').disabled")), 'restoring the scanned text re-enables Copy');

  console.log('\nReplace and undo');
  await click('replace');
  check((await inputValue()) === expected.redacted, 'Replace input swaps in the redacted text');
  check((await text('summary-title')) === 'No secrets found', 'rescan of the redacted text is clean');
  await screenshot('3-replaced-light');
  await evaluate("document.querySelector('#status .link-btn').click()", { gesture: true });
  check((await inputValue()) === SAMPLE, 'Undo restores the original text');

  console.log('\nClear and undo');
  await click('clear');
  check((await inputValue()) === '' && (await visible('empty')), 'Clear empties the input and resets results');
  await evaluate("document.querySelector('#status .link-btn').click()", { gesture: true });
  check((await inputValue()) === SAMPLE, 'Undo after Clear restores the text');

  console.log('\nKeyboard');
  await click('clear');
  await setInput(SAMPLE);
  await evaluate("document.getElementById('input').focus()");
  for (const type of ['keyDown', 'keyUp']) {
    await send('Input.dispatchKeyEvent', { type, key: 'Enter', code: 'Enter', windowsVirtualKeyCode: 13, modifiers: 2 });
  }
  check(await visible('results'), 'Ctrl+Enter in the text area runs a scan');
  const focusable = await evaluate(
    "[...document.querySelectorAll('button, input, textarea, [tabindex]')].filter((e) => !e.closest('[hidden]') && !e.disabled).every((e) => e.tabIndex >= 0)",
  );
  check(focusable, 'all visible controls are keyboard-focusable');

  console.log('\nPrivacy');
  check(
    requests.every((url) => url.startsWith(`${origin}/`)),
    `only extension files were requested (${requests.length} requests)`,
    requests.filter((u) => !u.startsWith(origin)).join(', '),
  );
  check(
    (await evaluate('localStorage.length + sessionStorage.length')) === 0,
    'localStorage and sessionStorage are empty',
  );
  check((await evaluate('indexedDB.databases().then((dbs) => dbs.length)')) === 0, 'no IndexedDB databases');
  check((await evaluate("typeof chrome.storage === 'undefined'")) === true, 'chrome.storage is unavailable (no permission)');
  check(consoleMessages.length === 0, 'nothing was logged to the console');
  check(exceptions.length === 0, 'no uncaught exceptions', exceptions.join('; '));
  const probe = await evaluate(
    "fetch('https://example.com/maskpaste-csp-probe').then(() => 'sent', (e) => 'blocked: ' + e.message)",
  );
  check(probe.startsWith('blocked'), `CSP blocks network access from the popup (${probe})`);
  await new Promise((r) => setTimeout(r, 200)); // let any network events arrive
  const blocked = [...failedLoads.values()].find((f) => f.blockedReason);
  const dispatched = requests.some((url) => url.includes('maskpaste-csp-probe'));
  check(
    !dispatched || blocked?.blockedReason === 'csp',
    `the probe never reached the network (${dispatched ? `blocked: ${blocked?.blockedReason}` : 'not dispatched'})`,
  );

  if (SCREENSHOT_DIR) {
    await send('Emulation.setEmulatedMedia', { features: [{ name: 'prefers-color-scheme', value: 'dark' }] });
    await click('scan');
    await screenshot('4-results-dark');
    console.log(`\nScreenshots written to ${SCREENSHOT_DIR}`);
  }
} catch (error) {
  check(false, `unexpected error: ${error.message}`);
} finally {
  await cdp.send('Browser.close').catch(() => {});
  await cleanup();
}

const failed = results.filter((r) => !r.ok).length;
console.log(failed ? `\n${failed} of ${results.length} browser checks failed.` : `\nAll ${results.length} browser checks passed.`);
process.exit(failed ? 1 : 0);
