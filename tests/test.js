/* ============================================================
   Tests for the Phishing Email Analyser engine
   ------------------------------------------------------------
   Run with:   node tests/test.js     (from the project folder)
   No extra packages needed.
   ============================================================ */

'use strict';

const path = require('path');
const fs = require('fs');
const ROOT = path.join(__dirname, '..');

// Load the demo emails, then the engine.
require(path.join(ROOT, 'examples.js'));
const engine = require(path.join(ROOT, 'script.js'));
const SAMPLES = globalThis.SAMPLE_EMAILS;

let passed = 0;
let failed = 0;

function check(cond, msg) {
  if (cond) {
    passed++;
    console.log('  \u2714 ' + msg);
  } else {
    failed++;
    console.log('  \u2718 FAIL: ' + msg);
  }
}

function ids(result) {
  return result.findings.map(function (f) { return f.id; });
}

function sample(id) {
  const s = SAMPLES.filter(function (x) { return x.id === id; })[0];
  if (!s) { throw new Error('Sample not found: ' + id); }
  return s;
}

/* ----------------------------------------------------------------
   1. Every sample: sane score + explainable scoring
   ---------------------------------------------------------------- */
console.log('\n--- 1. All samples score correctly ---');
SAMPLES.forEach(function (s) {
  const r = engine.analyseEmail(s.text);
  const sum = r.findings.reduce(function (a, f) { return a + f.points; }, 0);
  check(r.score >= 0 && r.score <= 100, s.id + ': score in range (got ' + r.score + ')');
  check(r.score === Math.min(100, sum), s.id + ': score equals capped sum of points');
  const expectedKey = r.score >= 60 ? 'high' : (r.score >= 30 ? 'susp' : 'low');
  check(r.classification.key === expectedKey, s.id + ': classification matches score band');
  check(r.findings.every(function (f) { return f.why && f.points > 0; }), s.id + ': every finding has an explanation and points');
});

/* ----------------------------------------------------------------
   2. Expected findings for each demo email
   ---------------------------------------------------------------- */
console.log('\n--- 2. Known phishing sample findings ---');

let r = engine.analyseEmail(sample('obvious').text);
check(r.classification.key === 'high', 'obvious: High Risk (score ' + r.score + ')');
['urgency', 'suspension', 'password_request', 'credential_harvest', 'impersonation_language', 'lookalike_domain'].forEach(function (want) {
  check(ids(r).indexOf(want) !== -1, 'obvious detects: ' + want);
});

r = engine.analyseEmail(sample('sophisticated').text);
check(r.classification.key === 'high', 'sophisticated: High Risk (score ' + r.score + ')');
['lookalike_domain', 'misleading_link', 'reply_to_mismatch', 'spf_fail', 'dkim_fail', 'dmarc_fail', 'code_request'].forEach(function (want) {
  check(ids(r).indexOf(want) !== -1, 'sophisticated detects: ' + want);
});

r = engine.analyseEmail(sample('m365').text);
check(r.classification.key === 'high', 'm365: High Risk (score ' + r.score + ')');
['password_request', 'credential_harvest', 'suspension', 'lookalike_domain'].forEach(function (want) {
  check(ids(r).indexOf(want) !== -1, 'm365 detects: ' + want);
});

r = engine.analyseEmail(sample('parcel').text);
check(ids(r).indexOf('raw_ip_url') !== -1, 'parcel detects: raw_ip_url');
check(ids(r).indexOf('payment_request') !== -1, 'parcel detects: payment_request');
check(r.score >= 60, 'parcel: score >= 60 (got ' + r.score + ')');

r = engine.analyseEmail(sample('bec').text);
['reply_to_mismatch', 'shortened_url', 'bank_change', 'invoice_language', 'payment_request'].forEach(function (want) {
  check(ids(r).indexOf(want) !== -1, 'bec detects: ' + want);
});

/* ----------------------------------------------------------------
   3. Legitimate email must stay low
   ---------------------------------------------------------------- */
console.log('\n--- 3. Legitimate email ---');
r = engine.analyseEmail(sample('legit').text);
check(r.classification.key === 'low', 'legit: Low Risk (score ' + r.score + ')');
check(r.score <= 29, 'legit: score <= 29');
check(ids(r).filter(function (id) { return id.indexOf('_fail') !== -1; }).length === 0, 'legit: no auth failures');

/* ----------------------------------------------------------------
   4. Detector unit checks
   ---------------------------------------------------------------- */
console.log('\n--- 4. Individual detector checks ---');
function fires(text, expectedId) {
  return ids(engine.analyseEmail(text)).indexOf(expectedId) !== -1;
}

check(fires('Urgent! Act now immediately!!!', 'urgency'), 'urgency detector');
check(fires('Your account will be suspended within 24 hours', 'suspension'), 'suspension detector');
check(fires('Please enter your password to confirm your account', 'password_request'), 'password detector');
check(fires('Enter the one-time passcode to confirm it is you', 'code_request'), 'code detector');
check(fires('We ask for a gift card', 'payment_request'), 'payment detector');
check(fires('our bank details have changed, confirm your bank account', 'bank_change'), 'bank-change detector');
check(fires('Open the attached invoice', 'invoice_language'), 'invoice detector');
check(fires('Click here to verify your account', 'credential_harvest'), 'credential-harvest detector');
check(fires('Dear Valued Customer, kindly confirm your details', 'impersonation_language'), 'impersonation detector');
check(fires('enable macros to view this document', 'macros_request'), 'macro detector');
check(fires('Please review invoice.exe now', 'executable_attachment'), 'executable attachment detector');
check(fires('Download payoff.pdf.exe', 'executable_attachment'), 'double-extension detection');
check(fires('Payment link: http://10.0.0.5/payload.php', 'raw_ip_url'), 'raw IP URL detector');
check(fires('See here: https://bit.ly/xYz', 'shortened_url'), 'shortener detector');
check(fires('Login at https://account.microsoft.com.example/verify now', 'lookalike_domain'), 'lookalike domain detector');
check(fires('Go to https://login.live.com to check', 'lookalike_domain') === false, 'official live.com is NOT flagged as lookalike');
check(fires('[https://account.microsoft.com](https://microsooft-login.example/verify)', 'misleading_link'), 'misleading link detector');

// A mid-range example should be "Suspicious", not "Low".
r = engine.analyseEmail('URGENT: kindly view the invoice here https://bit.ly/abc');
check(r.classification.key === 'susp', 'mid-range example classified Suspicious (score ' + r.score + ')');

/* ----------------------------------------------------------------
   5. Header parsing + authentication integration
   ---------------------------------------------------------------- */
console.log('\n--- 5. Header parsing and authentication ---');
const hp = engine.parseEmailText('From: a@b.com\nReply-To: c@d.example\nSubject: Hey\n\nBody here');
check(hp.hasHeaders === true, 'header block detected');
check(hp.headers.from === 'a@b.com', 'From header extracted');
check(hp.body === 'Body here', 'body extracted');
check(hp.searchText.indexOf('Hey') === 0, 'subject included in search text');

const hp2 = engine.parseEmailText('Just a body with no headers.');
check(hp2.hasHeaders === false, 'missing headers: not mis-detected');

r = engine.analyseEmail([
  'From: "Support" <support@example.com>',
  'Reply-To: help@richet.example',
  'Authentication-Results: mx.example.com; spf=pass smtp.mailfrom=support@example.com; dkim=neutral; dmarc=fail',
  'Subject: Verify your account',
  '',
  'Dear Customer, click here to verify your account.'
].join('\n'));
check(ids(r).indexOf('reply_to_mismatch') !== -1, 'Reply-To mismatch detected from headers');
check(ids(r).indexOf('dmarc_fail') !== -1, 'DMARC failure detected');
check(ids(r).indexOf('spf_fail') === -1, 'SPF pass correctly not flagged');
check(r.authNote && r.authNote.indexOf('SPF: PASS') !== -1 && r.authNote.indexOf('DMARC: FAIL') !== -1, 'auth summary note is informative');

/* ----------------------------------------------------------------
   6. Privacy regression: no networking anywhere in the app
   ---------------------------------------------------------------- */
console.log('\n--- 6. Privacy: no network code allowed ---');
const forbidden = ['fetch(', 'XMLHttpRequest', 'sendBeacon', 'WebSocket', '<script src="http', '<link rel="stylesheet" href="http'];
let privacyClean = true;
['index.html', 'script.js', 'styles.css', 'examples.js'].forEach(function (name) {
  const content = fs.readFileSync(path.join(ROOT, name), 'utf8');
  forbidden.forEach(function (frag) {
    if (content.indexOf(frag) !== -1) {
      privacyClean = false;
      console.log('    \u2718 ' + name + ' contains: ' + frag);
    }
  });
});
check(privacyClean, 'no networking / tracking calls anywhere in the app files');

/* ----------------------------------------------------------------
   7. UI wiring: every element id used by script.js exists in the page
   ---------------------------------------------------------------- */
console.log('\n--- 7. Page wiring ---');
const html = fs.readFileSync(path.join(ROOT, 'index.html'), 'utf8');
const jsSource = fs.readFileSync(path.join(ROOT, 'script.js'), 'utf8');
const usedIds = [];
let idRe;
const idRegex = /getElementById\('([^']+)'\)/g;
while ((idRe = idRegex.exec(jsSource)) !== null) { usedIds.push(idRe[1]); }
const uniqueIds = usedIds.filter(function (v, i) { return usedIds.indexOf(v) === i; });
const missingIds = uniqueIds.filter(function (id) { return html.indexOf('id="' + id + '"') === -1; });
check(missingIds.length === 0, 'all element ids used by script.js exist in index.html' + (missingIds.length ? ' (missing: ' + missingIds.join(', ') + ')' : ''));

/* ---------------------------------------------------------------- */
console.log('\n============================================');
console.log('Result: ' + passed + ' passed, ' + failed + ' failed');
console.log('============================================');
if (failed > 0) { process.exit(1); }


