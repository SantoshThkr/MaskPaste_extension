// MaskPaste popup controller.
//
// Privacy notes: the pasted text only ever lives in this page's memory. It is
// never written to chrome.storage/localStorage, never logged, and never sent
// anywhere (the manifest's CSP also blocks all network access). Closing the
// popup discards it.

import { scanText, redact } from './detector.js';

const MAX_CHARS = 1_000_000;

const $ = (id) => document.getElementById(id);
const ui = {
  input: $('input'),
  meta: $('input-meta'),
  scan: $('scan'),
  clear: $('clear'),
  shortcut: $('shortcut'),
  status: $('status'),
  announcer: $('announcer'),
  empty: $('empty'),
  results: $('results'),
  summary: $('summary'),
  summaryCount: $('summary-count'),
  summaryTitle: $('summary-title'),
  summarySub: $('summary-sub'),
  categories: $('categories'),
  details: $('details'),
  findings: $('findings'),
  preview: $('preview'),
  redactionCount: $('redaction-count'),
  actions: $('result-actions'),
  copy: $('copy'),
  replace: $('replace'),
};

/** The last scan: { text, result, excluded: Set<finding id> } or null. */
let scan = null;
/** Text that the Undo button would restore, or null. */
let undoText = null;
let copyResetTimer = 0;

const plural = (n, one, many = `${one}s`) => `${n.toLocaleString()} ${n === 1 ? one : many}`;
// userAgentData reports "macOS"; navigator.platform reports "MacIntel".
const isMac = /mac|iphone|ipad/i.test(navigator.userAgentData?.platform ?? navigator.platform ?? '');

function el(tag, className, text) {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (text !== undefined) node.textContent = text;
  return node;
}

/* ---------------------------------------------------------------- status */

function setStatus(kind, message, { undo = false } = {}) {
  undoText = undo ? undoText : null;
  if (!message) {
    ui.status.hidden = true;
    ui.status.replaceChildren();
    return;
  }
  ui.status.dataset.kind = kind;
  const children = [el('span', '', message)];
  if (undo) {
    const button = el('button', 'link-btn', 'Undo');
    button.type = 'button';
    button.addEventListener('click', undoLast);
    children.push(button);
  }
  ui.status.replaceChildren(...children);
  ui.status.hidden = false;
}

function announce(message) {
  ui.announcer.textContent = '';
  // A separate tick makes screen readers re-announce identical messages.
  requestAnimationFrame(() => {
    ui.announcer.textContent = message;
  });
}

/* ------------------------------------------------------------------ input */

function updateMeta() {
  const text = ui.input.value;
  ui.meta.textContent = text
    ? `${plural(text.split('\n').length, 'line')} · ${plural(text.length, 'character')}`
    : 'Empty';
}

function isStale() {
  return Boolean(scan) && ui.input.value !== scan.text;
}

function onInput() {
  updateMeta();
  if (undoText !== null) setStatus(null);
  if (!scan) return;
  const stale = isStale();
  renderStale(stale);
  if (stale) setStatus('warning', 'The text changed after the scan. Scan again to update the results.');
  else setStatus(null);
}

/* ------------------------------------------------------------------- scan */

function runScan() {
  const text = ui.input.value;
  if (!text.trim()) {
    scan = null;
    render();
    setStatus('warning', 'Nothing to scan yet. Paste some text first.');
    ui.input.focus();
    return;
  }
  if (text.length > MAX_CHARS) {
    setStatus(
      'error',
      `That's ${plural(text.length, 'character')}. MaskPaste scans up to ${MAX_CHARS.toLocaleString()} at a time, so split the text and scan each part.`,
    );
    return;
  }
  try {
    scan = { text, result: scanText(text), excluded: new Set() };
  } catch {
    // Deliberately not logged: error details could include fragments of the input.
    scan = null;
    render();
    setStatus('error', 'Something went wrong while scanning. Your text was not changed.');
    return;
  }
  setStatus(null);
  render();
  const { total } = scan.result.summary;
  announce(total ? `Scan complete. ${plural(total, 'possible secret')} found.` : 'Scan complete. No secrets found.');
}

/* ----------------------------------------------------------------- render */

function render() {
  ui.empty.hidden = Boolean(scan);
  ui.results.hidden = !scan;
  ui.actions.hidden = !scan || scan.result.summary.total === 0;
  clearTimeout(copyResetTimer);
  ui.copy.textContent = 'Copy redacted text';
  if (!scan) return;

  const { summary, findings } = scan.result;
  const found = summary.total > 0;
  ui.summary.dataset.state = found ? 'found' : 'clean';
  ui.summaryCount.textContent = found ? String(summary.total) : '✓';
  ui.summaryTitle.textContent = found ? `${plural(summary.total, 'possible secret')} found` : 'No secrets found';
  const lines = plural(scan.result.lineCount, 'line');
  ui.summarySub.textContent = found
    ? [summary.high && `${summary.high} high confidence`, summary.potential && `${summary.potential} potential`, `${lines} checked`]
        .filter(Boolean)
        .join(' · ')
    : `Checked ${lines} against MaskPaste's patterns. Pattern matching can miss things, so skim before sharing.`;

  ui.categories.replaceChildren(
    ...summary.categories.map(({ category, count }) => {
      const chip = el('li', 'chip', category);
      if (count > 1) chip.append(' ', el('span', '', `×${count}`));
      return chip;
    }),
  );

  ui.details.hidden = !found;
  ui.findings.replaceChildren(...findings.map(renderFinding));
  renderPreview();
  renderStale(isStale());
}

function renderFinding(finding, index) {
  const item = el('li', 'finding');
  item.dataset.id = finding.id;

  const checkbox = el('input');
  checkbox.type = 'checkbox';
  checkbox.id = `finding-${index}`;
  checkbox.checked = !scan.excluded.has(finding.id);
  checkbox.addEventListener('change', () => {
    if (checkbox.checked) scan.excluded.delete(finding.id);
    else scan.excluded.add(finding.id);
    item.classList.toggle('excluded', !checkbox.checked);
    renderPreview();
  });

  const label = el('label');
  label.htmlFor = checkbox.id;
  const title = el('span', 'finding-title', finding.category);
  const high = finding.confidence === 'high';
  title.append(el('span', `badge badge-${high ? 'high' : 'potential'}`, high ? 'High' : 'Potential'));
  label.append(title);
  if (finding.detail) label.append(el('span', 'finding-detail', finding.detail));
  label.title = 'Checked findings are replaced in the redacted text';

  const where =
    finding.endLine > finding.line ? `Lines ${finding.line}–${finding.endLine}` : `Line ${finding.line}`;
  const locate = el('button', 'locate', where);
  locate.type = 'button';
  locate.title = `${where}, column ${finding.column}: select it in the input`;
  locate.setAttribute('aria-label', `Show ${where.toLowerCase()} in the input`);
  locate.addEventListener('click', () => selectInInput(finding));

  item.append(checkbox, label, locate);
  return item;
}

function selectedFindings() {
  return scan.result.findings.filter((f) => !scan.excluded.has(f.id));
}

function renderPreview() {
  const { text, ranges } = redact(scan.text, selectedFindings());
  const parts = [];
  let cursor = 0;
  for (const range of ranges) {
    if (range.start > cursor) parts.push(text.slice(cursor, range.start));
    parts.push(el('mark', '', text.slice(range.start, range.end)));
    cursor = range.end;
  }
  parts.push(text.slice(cursor));
  ui.preview.replaceChildren(...parts);

  const total = scan.result.findings.length;
  ui.redactionCount.textContent = `${ranges.length} of ${plural(total, 'finding')} redacted`;
}

function renderStale(stale) {
  ui.results.classList.toggle('stale', stale);
  ui.copy.disabled = stale;
  ui.replace.disabled = stale;
  for (const control of ui.findings.querySelectorAll('input, button')) control.disabled = stale;
}

/* ---------------------------------------------------------------- actions */

/**
 * Vertical pixel offset of a character inside the text area, measured with an
 * off-screen mirror that wraps text exactly like the text area does.
 */
function offsetTopOf(area, index) {
  const style = getComputedStyle(area);
  const mirror = el('div', 'offscreen');
  for (const prop of [
    'fontFamily', 'fontSize', 'fontWeight', 'lineHeight', 'letterSpacing', 'tabSize',
    'paddingTop', 'paddingRight', 'paddingBottom', 'paddingLeft', 'borderTopWidth',
    'borderRightWidth', 'borderBottomWidth', 'borderLeftWidth', 'boxSizing',
  ]) {
    mirror.style[prop] = style[prop];
  }
  mirror.style.width = `${area.clientWidth + parseFloat(style.borderLeftWidth) + parseFloat(style.borderRightWidth)}px`;
  mirror.style.height = 'auto';
  mirror.style.whiteSpace = 'pre-wrap';
  mirror.style.overflowWrap = 'break-word';
  const marker = el('span', '', '​');
  mirror.append(area.value.slice(0, index), marker);
  document.body.append(mirror);
  const top = marker.offsetTop;
  mirror.remove();
  return top;
}

function selectInInput(finding) {
  if (isStale()) return;
  const area = ui.input;
  area.focus();
  area.setSelectionRange(finding.start, finding.end);
  const top = offsetTopOf(area, finding.start);
  area.scrollTop = Math.max(0, top - area.clientHeight / 3);
}

function legacyCopy(text) {
  const area = el('textarea', 'offscreen');
  area.value = text;
  area.setAttribute('readonly', '');
  area.setAttribute('aria-hidden', 'true');
  document.body.append(area);
  area.select();
  let copied = false;
  try {
    copied = document.execCommand('copy');
  } catch {
    copied = false;
  }
  area.remove();
  return copied;
}

async function copyRedacted() {
  if (!scan || isStale()) return;
  const { text, ranges } = redact(scan.text, selectedFindings());
  let copied = false;
  try {
    await navigator.clipboard.writeText(text);
    copied = true;
  } catch {
    copied = legacyCopy(text);
  }
  if (!copied) {
    setStatus('error', `Couldn't copy automatically. Select the redacted preview and press ${isMac ? '⌘C' : 'Ctrl+C'}.`);
    return;
  }
  setStatus(
    ranges.length ? 'success' : 'warning',
    ranges.length
      ? `Copied the redacted text (${plural(ranges.length, 'value')} replaced).`
      : 'Copied, but nothing was redacted: every finding is unchecked.',
  );
  ui.copy.textContent = 'Copied ✓';
  clearTimeout(copyResetTimer);
  copyResetTimer = setTimeout(() => {
    ui.copy.textContent = 'Copy redacted text';
  }, 1600);
}

function replaceInput() {
  if (!scan || isStale()) return;
  const original = ui.input.value;
  ui.input.value = redact(scan.text, selectedFindings()).text;
  updateMeta();
  runScan();
  undoText = original;
  setStatus('success', 'Input replaced with the redacted text.', { undo: true });
}

function clearInput() {
  const original = ui.input.value;
  ui.input.value = '';
  scan = null;
  updateMeta();
  render();
  if (original) {
    undoText = original;
    setStatus('info', 'Input cleared.', { undo: true });
  } else {
    setStatus(null);
  }
  ui.input.focus();
}

function undoLast() {
  if (undoText === null) return;
  ui.input.value = undoText;
  undoText = null;
  updateMeta();
  setStatus(null);
  runScan();
  ui.input.focus();
}

/* ------------------------------------------------------------------- init */

ui.shortcut.textContent = isMac ? '⌘↵' : 'Ctrl+↵';
ui.scan.setAttribute('aria-keyshortcuts', isMac ? 'Meta+Enter' : 'Control+Enter');
ui.scan.addEventListener('click', runScan);
ui.clear.addEventListener('click', clearInput);
ui.copy.addEventListener('click', copyRedacted);
ui.replace.addEventListener('click', replaceInput);
ui.input.addEventListener('input', onInput);
ui.input.addEventListener('keydown', (event) => {
  if (event.key === 'Enter' && (event.metaKey || event.ctrlKey)) {
    event.preventDefault();
    runScan();
  }
});

updateMeta();
render();
ui.input.focus();
