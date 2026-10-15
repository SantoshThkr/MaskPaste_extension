# MaskPaste

**Catch secrets before you share.**

MaskPaste is a small Chrome extension (Manifest V3). You paste text into its popup, it finds likely secrets such as API keys, tokens, passwords, private keys and credentials in connection strings, and it gives you a redacted copy to share. Everything runs inside the popup. There is no backend, no AI model and no network access.

## The problem

Developers paste code, terminal output, `.env` files, config and stack traces into AI chats, GitHub issues, forums and bug reports all the time. Those pastes regularly carry a live API key, a database password, a session cookie from "Copy as cURL", or a private key. Once a secret is posted, you have to assume it is compromised and rotate it.

MaskPaste adds a quick check before you share, and it does that without sending your text anywhere.

## Features

- **Manual paste workflow.** Click the toolbar icon, paste, then press **Scan text** (or ⌘/Ctrl + Enter).
- **Local detection** with deterministic rules and regular expressions (see [How detection works](#how-detection-works)).
- **Results:** a finding count, high-confidence vs. potential badges, category chips, and per-finding line numbers.
- **Review before you copy.** Each finding has a checkbox, so you can keep a value that isn't secret. The redacted preview updates live, with each placeholder highlighted.
- **Locate:** clicking a finding's line number selects that value in your input.
- **Copy redacted text** puts the redacted version on the clipboard. It only happens when you click.
- **Your original text is never changed** unless you click **Replace input**, which can be undone. **Clear** can be undone too.
- **Stale-result protection:** if you edit the text after a scan, Copy and Replace are disabled until you scan again.
- Empty, clean, error and "text changed" states. Keyboard accessible with visible focus rings. Light and dark themes.

## Example

Input (all values are fabricated):

```text
# config pasted into a chat
DB_PASSWORD="pw-for-docs-7Qx2"
GITHUB_TOKEN=ghp_EXAMPLEonlyNOTaREALtoken000000000000
curl -H "Authorization: Bearer docsOnly0000fakeToken1234" https://api.example.com/v1/me
DATABASE_URL=postgres://app:not-a-real-pw-1@db.internal:5432/app
id_token=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJkb2NzLWV4YW1wbGUifQ.not-a-real-signature
API_KEY=${API_KEY}
LOG_LEVEL=debug
```

Redacted output (produced by the detector, not edited by hand):

```text
# config pasted into a chat
DB_PASSWORD="[REDACTED_PASSWORD]"
GITHUB_TOKEN=[REDACTED_GITHUB_TOKEN]
curl -H "Authorization: Bearer [REDACTED_TOKEN]" https://api.example.com/v1/me
DATABASE_URL=postgres://app:[REDACTED_PASSWORD]@db.internal:5432/app
id_token=[REDACTED_JWT]
API_KEY=${API_KEY}
LOG_LEVEL=debug
```

Findings: line 2 Password, line 3 GitHub token, line 4 Authorization header, line 5 Database credentials, line 6 JSON Web Token. All five are high confidence. `${API_KEY}` is a reference, not a secret, so it is left alone. Quotes, the username, host and port, and every other line are preserved.

## How detection works

All detection lives in [`extension/detector.js`](extension/detector.js). It is a pure module with no DOM, storage, network or logging, and the popup and the tests import the same file.

1. **Rules propose candidate spans.** Each rule returns start/end offsets for the part that is secret, so only the value is replaced and the surrounding syntax stays intact.
2. **Overlaps are resolved deterministically.** Rules are ordered by priority. Where spans overlap, the earlier (more specific) rule wins. Ties go to position, then to the longer match. Each value is reported once. For example, a JWT inside `Authorization: Bearer …` is reported as a JWT, not three times.
3. **Redaction** replaces each accepted span with `[REDACTED_<TYPE>]` and copies every other character through unchanged, including line breaks, CRLF, indentation and non-ASCII text. Scanning the redacted output again finds nothing.

### What it detects

| Category | What it matches | Confidence |
| --- | --- | --- |
| Provider tokens | AWS access key IDs (`AKIA…`, `ASIA…`), GitHub (`ghp_`, `gho_`, `ghu_`, `ghs_`, `ghr_`, `github_pat_`), GitLab (`glpat-` …), Stripe (`sk_`/`rk_` live and test, `whsec_`), Slack tokens (`xoxb-` …, `xapp-`) and webhook URLs, OpenAI (`sk-proj-` …), Anthropic (`sk-ant-`), Google API keys (`AIza…`) and OAuth client secrets (`GOCSPX-`), npm (`npm_`), PyPI (`pypi-AgE…`), SendGrid (`SG.…`), Hugging Face (`hf_`) | High |
| Generic `sk-` keys | `sk-` followed by 32+ characters including digits (unknown provider) | Potential |
| Private keys | PEM `-----BEGIN … PRIVATE KEY-----` blocks (RSA, EC, DSA, OpenSSH, PKCS#8, encrypted, PGP), including JSON-escaped keys and truncated keys with no END line. Only the body is replaced. | High |
| JSON Web Tokens | `eyJ….eyJ….sig`. High if the header decodes to JSON with an `alg`, otherwise Potential. | High / Potential |
| Authorization headers | `Authorization: Bearer/Token/Basic/… <value>`. Basic credentials are decoded to confirm `user:password`. | High |
| Bearer tokens | `Bearer <token>` anywhere, e.g. in logs | High / Potential |
| Cookies | `Cookie:` headers and `curl -b` (whole value), `Set-Cookie` (value only) | High / Potential |
| Credentials in URLs | `scheme://user:password@host`. Only the password is replaced. Database schemes (Postgres, MySQL, MongoDB, Redis, AMQP, MSSQL, …) are labelled *Database credentials*. | High |
| Command-line credentials | `curl -u user:pass`, `mysql -pPASSWORD`, `--password …`, `--api-key=…` | High / Potential |
| Sensitive assignments | `KEY=value`, `key: value`, `"key": "value"`, `key := …`, `'key' => …`, `<password>…</password>`, `?token=…`, `;Password=…;`, SQL `PASSWORD '…'` / `IDENTIFIED BY '…'`, base64 `auth` values (Docker `config.json`, `.npmrc`) | High / Potential |

**How assignments are judged.** MaskPaste looks at the variable name and the value, not just the value:

- **Name.** The last word of the name must be a password, secret or token word, e.g. `DB_PASSWORD`, `clientSecret`, `GITHUB_TOKEN`, `x-api-key`, `AWS_SECRET_ACCESS_KEY`. Names like `token_type`, `max_tokens`, `nextToken`, `eos_token`, `csrfToken`, `publicKey`, `primaryKey`, `cacheKey`, `password_length` and plain `key` are ignored.
- **Value.** Placeholders (`changeme`, `your_api_key_here`, `<token>`, `xxxx`, `***`, `example`), references (`$VAR`, `${VAR}`, `$(cmd)`, `{{ var }}`, `process.env.X`, `os.environ[...]`), function calls, type annotations (`password: string`), file paths, plain URLs and prose (`"Password must be 8 characters"`) are skipped. In code, a bare identifier such as `password: hashedPassword` is treated as a variable, not a literal.
- **Confidence.** *High* when the value looks random (12+ characters, letters and digits, enough entropy), or when it is a non-trivial password with digits or symbols. Otherwise *Potential*, meaning worth a look.

## Privacy architecture

Privacy is enforced by the browser and checked by tests. It is not just a promise in this README.

- **No network access.** The manifest's Content Security Policy is `default-src 'none'; script-src 'self'; …`. Chrome itself blocks `fetch`, XHR, WebSocket and remote images, scripts and styles from the popup. The browser smoke test verifies this: a probe `fetch` fails and never reaches the network, and the only requests made are for the extension's own files.
- **No storage.** The extension has no `storage` permission and uses no `localStorage`, `sessionStorage`, IndexedDB or cookies. Text lives only in the popup's memory and is discarded when the popup closes. The smoke test checks that all storage is empty after use.
- **No logging, analytics, telemetry or ads.** The code contains no `console` calls. Errors are deliberately not logged because they could contain fragments of the input.
- **No website access.** No content scripts, no host permissions, no access to tabs.
- **Spellcheck is off on the text area**, so Chrome's spell-checking, including the optional cloud-based Enhanced Spell Check, does not process pasted text.
- **Findings don't carry secrets.** Finding objects hold offsets and labels (such as the variable name), never the secret value. A unit test enforces this.
- **Clipboard writes only on click.** The only clipboard access is `navigator.clipboard.writeText` (or `execCommand('copy')` as a fallback) inside the Copy button handler. MaskPaste never reads the clipboard: you paste with ⌘/Ctrl + V yourself.

What MaskPaste cannot control: other extensions you have installed, clipboard managers that record what you copy (they will see the redacted text you copy, and they already saw the original when you copied it), and your operating system.

### Permissions

The manifest requests **no permissions at all**.

| Manifest entry | Why |
| --- | --- |
| `action.default_popup` | The toolbar button opens the popup. This is the whole UI. |
| `icons` / `action.default_icon` | Toolbar and extensions-page icons. |
| `content_security_policy.extension_pages` | Tightens Chrome's default policy so the popup cannot make network requests or load anything remote. |
| `permissions`, `host_permissions`, `content_scripts`, `background` | **Not present.** Copying from a popup after a click works without `clipboardWrite` (verified in Chrome for Testing 153), and nothing else needs privileges. |

`npm run check` fails if any of these are added or the CSP is loosened.

## Tech stack

- Vanilla JavaScript (ES modules), HTML and CSS, Chrome Manifest V3. No framework and no build step: the `extension/` folder is what Chrome loads.
- Node.js's built-in test runner (`node:test`) for development.
- **Zero npm dependencies**, runtime or development. `npm install` is not needed.

```text
extension/            ← the unpacked extension (load this folder in Chrome)
  manifest.json
  popup.html / popup.css / popup.js   UI
  detector.js                         detection + redaction engine (pure)
  icons/
test/                 ← unit tests (node:test) with fabricated fixtures
scripts/
  check.mjs           manifest, CSP, permission, syntax and privacy checks
  browser-smoke.mjs   end-to-end test in headless Chromium over CDP
  generate-icons.mjs  renders the PNG icons (no dependencies)
```

## Prerequisites

- **Google Chrome** (any recent version with Manifest V3 support) to use the extension.
- **Node.js 22 or newer**, only to run the tests and checks.
- Optional, for `npm run test:browser`: **Chrome for Testing or Chromium**. Branded Google Chrome 137+ ignores the `--load-extension` flag that automated tests rely on. The script finds Playwright's cached builds automatically (e.g. after `npx playwright install chromium`), or you can set `CHROME_PATH`.

## Install (load unpacked)

MaskPaste is not published on the Chrome Web Store. To run it locally:

1. Download or clone this repository.
2. Open `chrome://extensions` in Chrome.
3. Turn on **Developer mode** (top-right toggle).
4. Click **Load unpacked** and select the **`extension`** folder inside this repository, not the repository root.
5. Optional: pin MaskPaste from the puzzle-piece (Extensions) menu so its icon stays in the toolbar.

After changing any file, click the reload icon on the MaskPaste card in `chrome://extensions`.

## Usage

1. Click the MaskPaste icon. The text area is focused and ready.
2. Paste your code, logs or config (⌘/Ctrl + V).
3. Click **Scan text** or press ⌘/Ctrl + Enter.
4. Review the summary and findings. Click **Line N** to select a finding in your text, and uncheck anything that isn't actually secret.
5. Check the **Redacted preview**, then click **Copy redacted text** and paste it where you meant to share.
6. Optionally click **Replace input** to swap your text for the redacted version (**Undo** is available).

The popup keeps nothing: closing it discards the text. Line numbers always refer to your original text.

## Tests and checks

```bash
npm test               # unit tests: detection, false positives, redaction, robustness
npm run check          # manifest, permissions, CSP, file references, syntax, privacy scan
npm run verify         # both of the above
npm run test:browser   # end-to-end in headless Chromium (see Prerequisites)
npm run test:browser -- --screenshots ./shots   # also save popup screenshots
```

At the time of writing: **117 unit tests pass**, **all static checks pass**, and **37 browser checks pass** in headless Chrome for Testing 153 on macOS.

The unit tests cover every rule with fabricated values, near misses, a realistic React component, Express/TypeScript/Python code, templated config, tokenizer config, i18n strings, shell sessions, ordinary URLs and prose (no findings, output unchanged), overlap and duplicate handling, line breaks and CRLF, JSON validity after redaction, empty and non-string input, repeated scans, idempotence, a 1 MB input, and pathological inputs that would trigger catastrophic regex backtracking.

The browser test loads the unpacked extension in a throwaway profile and opens its popup page. It then drives the scan, review, locate, copy (and reads the clipboard back), stale-result, replace/undo, clear/undo and keyboard flows, and checks the network, storage, console and CSP behaviour.

Test credentials are generated at runtime from a deterministic pseudo-random helper ([`test/helpers.js`](test/helpers.js)), so the repository contains no real or real-looking secrets.

## Limitations

MaskPaste uses pattern matching. **It will not catch every secret**, and the popup says so.

- **Missed by design or by nature:** secrets without a recognizable prefix *and* without a telling variable name (for example a bare 40-character string, or an AWS secret key on its own), secrets split across lines, encoded or obfuscated values, secrets in screenshots, and providers that aren't in the rule list.
- **Generic high-entropy strings are not flagged** (hashes, UUIDs, base64 blobs, integrity hashes), because that would bury real findings in noise.
- **Some real secrets are skipped as placeholders or references:** values containing `example`, `changeme`, `your…`, `xxxx`, values that start like a variable reference (`$NAME`, `${…}`, `$(…)`, `$1`), and passphrases containing spaces that read like a sentence.
- **Unquoted, letters-only values in code** (`token: abc`) are treated as variable names. Quoted values are always treated as literals.
- **Possible false positives:** single-word translations under password keys (`"password": "Passwort"`), storage-key constants named like secrets, test or demo credentials, and Google API keys that are intentionally public (e.g. Firebase web config). Uncheck these before copying.
- **Cookie headers are redacted whole,** including harmless cookies.
- **Private keys** keep their BEGIN/END lines and the body becomes one placeholder line, so the redacted output can have fewer lines than the input.
- **Size limit:** up to 1,000,000 characters per scan.
- **Browser coverage:** verified automatically in headless Chrome for Testing 153 by opening the extension's `popup.html` as a page. Not tested by clicking the toolbar icon in a regular Chrome window, and not tested in Edge, Brave or other Chromium browsers.

## Reporting false positives (or misses)

Please include:

- a **minimal, fabricated** sample that reproduces it. Never paste a real secret into an issue; replace it with random characters of the same shape.
- what MaskPaste reported (category, confidence, line) and what you expected.

If you can, add the sample as a failing test in [`test/false-positives.test.js`](test/false-positives.test.js) (for false positives) or [`test/detection.test.js`](test/detection.test.js) (for misses).

## Making changes safely

- Detection rules live in `RULES` in [`extension/detector.js`](extension/detector.js). **Order is priority** for overlapping matches: put specific formats before generic ones, and containers such as cookie headers first.
- Every rule needs a positive test, and a test fails if any rule ID goes unexercised. Add negative cases for anything that could fire on ordinary code.
- Build fixtures with `fakeChars()` in [`test/helpers.js`](test/helpers.js). Do not commit real or real-looking credentials.
- If a test exposes a weakness, fix the detector rather than loosening the test.
- Keep the extension permission-free. `npm run check` fails on new permissions, host access, content scripts, a background worker, a loosened CSP, or network, storage, logging and `eval`-style APIs in `extension/`.
- Run `npm run verify` before committing, and `npm run test:browser` after UI changes.
- After `npm run icons` (which regenerates the PNGs), reload the extension in `chrome://extensions`.

## Project status

**v0.1.0, a working local build.** The core workflow, detection engine, redaction, tests and checks are complete. It is not published on the Chrome Web Store, and no license has been chosen yet.

### Possible future work (not implemented)

- User-defined patterns and an allowlist for known false positives.
- More provider formats (Azure SAS signatures, Twilio, Discord, Datadog, …).
- A Firefox build.
- An optional warning when pasting into specific sites. This would need page permissions, so it is intentionally out of scope for now.
