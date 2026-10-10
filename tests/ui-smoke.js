/* ============================================================
   UI smoke test - runs the real page wiring with a fake DOM.
   ------------------------------------------------------------
   Run with:   node tests/ui-smoke.js
   Verifies that clicking "Analyse Email" produces a populated
   results panel (score, findings, recommendations) without
   throwing any errors. Uses a tiny hand-made DOM stub - no
   libraries.
   ============================================================ */

'use strict';

const path = require('path');
const ROOT = path.join(__dirname, '..');

// --- Minimal fake DOM ----------------------------------------
function makeElement(tag) {
  return {
    tagName: tag,
    children: [],
    style: {},
    handlers: {},
    value: '',
    textContent: '',
    innerHTML: '',
    className: '',
    type: '',
    hidden: false,
    addEventListener(type, fn) { this.handlers[type] = fn; },
    appendChild(child) { this.children.push(child); },
    focus() { this.focused = true; },
    setCustomValidity() {},
    reportValidity() { return true; },
    scrollIntoView() { this.scrolled = true; },
    click(evt) { if (this.handlers.click) { this.handlers.click(evt || {}); } }
  };
}

const dom = new Map();
[
  'email-input', 'analyse-btn', 'clear-btn', 'sample-select', 'results',
  'sample-grid', 'score-number', 'gauge-arc', 'classification-badge',
  'result-title', 'result-explainer', 'findings-summary', 'findings-list',
  'no-findings', 'recommendations', 'auth-note'
].forEach(function (id) { dom.set(id, makeElement('div')); });

global.document = {
  readyState: 'complete',
  getElementById: function (id) { return dom.get(id) || null; },
  createElement: function (tag) { return makeElement(tag); },
  addEventListener: function () {}
};

require(path.join(ROOT, 'examples.js')); // defines SAMPLE_EMAILS
require(path.join(ROOT, 'script.js'));   // boots initUI automatically

const input = dom.get('email-input');
const analyseBtn = dom.get('analyse-btn');
const sampleSelect = dom.get('sample-select');

let passed = 0;
let failed = 0;
function check(cond, msg) {
  if (cond) { passed++; console.log('  \u2714 ' + msg); }
  else { failed++; console.log('  \u2718 FAIL: ' + msg); }
}

// 1. Dropdown was populated
check(sampleSelect.children.length === globalThis.SAMPLE_EMAILS.length, 'dropdown populated with all samples');

// 2. Selecting a sample fills the text box
sampleSelect.value = 'legit';
sampleSelect.handlers.change();
check(input.value.length > 50 && input.value.indexOf('Marcus') !== -1, 'selecting a sample fills the text box');

// 3. Clicking Analyse with a phish sample renders full results
input.value = globalThis.SAMPLE_EMAILS[0].text; // the obvious phishing email
analyseBtn.handlers.click();
const results = dom.get('results');
const findingsList = dom.get('findings-list');
const recs = dom.get('recommendations');
const badge = dom.get('classification-badge');
const scoreEl = dom.get('score-number');

const score = parseInt(scoreEl.textContent, 10);
check(results.hidden === false, 'results panel becomes visible');
check(!isNaN(score) && score >= 0 && score <= 100, 'score number rendered (' + score + ')');
check(badge.className.indexOf('badge-') !== -1, 'classification badge rendered');
check(findingsList.children.length >= 4, 'findings are listed (' + findingsList.children.length + ' findings)');
check(recs.children.length >= 3, 'recommendations are listed (' + recs.children.length + ' items)');
check(dom.get('no-findings').hidden === true, '"no findings" message hidden when findings exist');

// 4. Evidence text appears inside a finding
const hasEvidence = findingsList.children.some(function (li) {
  return li.children.some(function (node) {
    return node.tagName === 'dl' && node.children.length >= 2;
  });
});
check(hasEvidence, 'findings include quoted evidence from the email');

// 5. Legitimate email shows the "no strong warning signs" panel
input.value = globalThis.SAMPLE_EMAILS.find(function (s) { return s.id === 'legit'; }).text;
analyseBtn.handlers.click();
check(dom.get('no-findings').hidden === false, 'legit email shows the "no findings" notice');
check(parseInt(scoreEl.textContent, 10) <= 29, 'legit email score is low (' + scoreEl.textContent + ')');

// 6. Empty input does not crash
input.value = '';
analyseBtn.handlers.click();
check(true, 'empty input handled gracefully');

// 7. Clear resets the panel and hides results
const clearBtn = dom.get('clear-btn');
input.value = 'anything';
clearBtn.handlers.click();
check(input.value === '' && results.hidden === true, 'Clear empties the box and hides results');

console.log('\n============================================');
console.log('UI smoke test: ' + passed + ' passed, ' + failed + ' failed');
console.log('============================================');
if (failed > 0) { process.exit(1); }
