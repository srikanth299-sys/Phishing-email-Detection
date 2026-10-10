/* ============================================================
   Phishing Email Analyser - analysis engine + user interface
   ------------------------------------------------------------
   Plain vanilla JavaScript. No libraries. No network requests.
   Everything runs locally in the visitor's browser (and can be
   tested from the command line with:  node tests/test.js ).

   HOW SCORING WORKS (plain English):
   - The analyser runs a list of "detectors" over the pasted text.
   - Every detector that fires adds a FIXED number of points,
     defined in each detector object below.
   - The risk score is the sum of those points, capped at 100.
   - Every point is explained on screen next to the finding.
   ============================================================ */

(function () {
  'use strict';

  /* ------------------------------------------------------------------
     1. Small helpers
     ------------------------------------------------------------------ */

  // Build one regular expression from many phrases.
  // NOTE: phrases are used as regular-expression source, so you CAN
  // include metacharacters (groups, alternation, {n,m} quantifiers)
  // for flexible matching, while plain-text phrases still match
  // literally because letters match themselves.
  function phraseRegex(phrases, flags) {
    return new RegExp(phrases.join('|'), flags || 'gi');
  }

  // Find short evidence phrases in text. Returns up to `limit`
  // unique matches so the interface can show proof of each finding.
  function collectMatches(re, text, limit) {
    var seen = {};
    var out = [];
    var m;
    var max = limit || 3;
    re.lastIndex = 0; // always start from the beginning
    while ((m = re.exec(text)) !== null && out.length < max) {
      var raw = String(m[1] || m[0]).trim();
      var key = raw.toLowerCase();
      if (raw.length > 1 && raw.length <= 46 && !seen[key]) {
        seen[key] = true;
        out.push(raw);
      }
      if (m.index === re.lastIndex) { re.lastIndex += 1; } // safety for zero-width
    }
    return out;
  }

  // Extract email addresses from a string.
  function extractEmails(str) {
    var re = /[\w.+-]+@[\w.-]+\.[a-z]{2,}/gi;
    var out = [];
    var m;
    while ((m = re.exec(str)) !== null) { out.push(m[0]); }
    return out;
  }

  /* ------------------------------------------------------------------
     2. Configuration
     ------------------------------------------------------------------ */

  var MAX_SCORE = 100;

  var CLASSIFICATIONS = {
    low:  { label: 'Low Risk',   color: '#34d399', badge: 'badge-low',  blurb: 'Very few common phishing warning signs were detected. Apply normal caution, especially if the sender is unknown or the message is unexpected.' },
    susp: { label: 'Suspicious', color: '#fbbf24', badge: 'badge-suspicious', blurb: 'Several warning signs were found. Do not click links or open attachments. Verify the message using the organisation\'s official website, app or known contact details.' },
    high: { label: 'High Risk',  color: '#f87171', badge: 'badge-high', blurb: 'Many strong phishing indicators were found. Treat this email with extreme caution: do not reply, click links, or open attachments. Verify everything through official channels.' }
  };

  // Official domains that a brand really owns. If a brand name appears
  // inside a link but the domain is NOT in this list, that is a strong
  // "lookalike / impersonation" warning sign.
  var BRAND_OFFICIAL_DOMAINS = {
    microsoft:   ['microsoft.com', 'microsoft365.com', 'office.com', 'office365.com', 'outlook.com', 'live.com', 'hotmail.com', 'sharepoint.com', 'onedrive.com', 'msn.com', 'bing.com', 'skype.com', 'msauth.net', 'msftidentity.com'],
    apple:       ['apple.com', 'icloud.com', 'me.com'],
    amazon:      ['amazon.com', 'amazon.co.uk', 'amazon.in', 'amazon.de', 'amazon.fr', 'amazon.ca', 'amazon.com.au'],
    paypal:      ['paypal.com', 'paypal.me'],
    google:      ['google.com', 'gmail.com', 'youtube.com'],
    netflix:     ['netflix.com', 'netflix.net'],
    linkedin:    ['linkedin.com'],
    facebook:    ['facebook.com', 'fb.com'],
    instagram:   ['instagram.com'],
    dropbox:     ['dropbox.com', 'getdropbox.com'],
    box:         ['box.com'],
    docusign:    ['docusign.com', 'docusign.net'],
    adobe:       ['adobe.com'],
    chase:       ['chase.com'],
    'wells fargo': ['wellsfargo.com'],
    hsbc:        ['hsbc.com', 'hsbc.co.uk'],
    barclays:    ['barclays.co.uk', 'barclays.com'],
    'bank of america': ['bankofamerica.com'],
    citi:        ['citi.com', 'citibank.com'],
    'american express': ['americanexpress.com', 'amex.com'],
    stripe:      ['stripe.com'],
    intuit:      ['intuit.com', 'quickbooks.com'],
    dhl:         ['dhl.com', 'dhl.de'],
    fedex:       ['fedex.com'],
    ups:         ['ups.com'],
    usps:        ['usps.com'],
    'royal mail': ['royalmail.com'],
    evri:        ['evri.com'],
    dpd:         ['dpd.com', 'dpd.co.uk'],
    gls:         ['gls-group.com'],
    zoom:        ['zoom.us', 'zoom.com'],
    github:      ['github.com']
  };

  // Returns true when `hostname` really belongs to the given brand.
  function isOfficialDomainForBrand(hostname, brandKey) {
    var domains = BRAND_OFFICIAL_DOMAINS[brandKey] || [];
    hostname = hostname.toLowerCase();
    for (var i = 0; i < domains.length; i++) {
      var d = domains[i].toLowerCase();
      if (hostname === d || hostname.slice(-(d.length + 1)) === '.' + d) { return true; }
    }
    return false;
  }

  // Known URL shortener services.
  var SHORTENER_DOMAINS = phraseRegex([
    'bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'is.gd', 'ow.ly', 'buff.ly', 'cutt.ly',
    'shorturl.at', 'tiny.cc', 'rb.gy', 'rebrand.ly', 'bit.do', 'adf.ly', 'bl.ink',
    'soo.gd', 'snipurl.com', 'kutt.it', 's.id', 'tny.im', 'lnkd.in', 'qr.ae', 'v.gd'
  ], 'i');

  // Free / abused top-level domains, plus the reserved ".example"
  // suffix used by the demo emails in this project.
  var SUSPICIOUS_TLDS = phraseRegex([
    '\\.tk', '\\.ml', '\\.ga', '\\.cf', '\\.gq', '\\.top', '\\.xyz', '\\.click',
    '\\.zip', '\\.country', '\\.icu', '\\.buzz', '\\.loan', '\\.work', '\\.rest',
    '\\.cyou', '\\.cfd', '\\.sbs', '\\.cam', '\\.fun', '\\.lol', '\\.mom',
    '\\.example', '\\.test', '\\.invalid', '\\.fit', '\\.guru', '\\.stream', '\\.review', '\\.bid'
  ], 'i');

  // File extensions that can execute code when opened. Note: the
  // ancient DOS ".com" extension is intentionally NOT listed, because
  // it would flag every ordinary email address ending in ".com".
  var EXECUTABLE_EXTS = [
    'exe', 'scr', 'bat', 'cmd', 'pif', 'vbs', 'vbe', 'js', 'jse', 'wsf', 'wsh',
    'msi', 'msp', 'cpl', 'reg', 'hta', 'jar', 'lnk', 'docm', 'xlsm', 'pptm', 'ps1', 'iso', 'app', 'dmg'
  ];
  var EXECUTABLE_RE = new RegExp('\\b[\\w][\\w.-]*\\.(' + EXECUTABLE_EXTS.join('|') + ')\\b', 'gi');

  /* ------------------------------------------------------------------
     3. Parsing the pasted email (headers + body)
     ------------------------------------------------------------------ */

  // Names of headers that real emails are introduced with. We only
  // treat the pasted text as having a header block if the first line
  // is one of these, so a normal message body can never be mistaken
  // for headers (e.g. a subject-line style opening like "URGENT:").
  var KNOWN_HEADER_NAME = /^(from|to|cc|bcc|subject|date|reply-to|return-path|message-id|received|delivered-to|sender|authentication-results|received-spf|dkim-signature|mime-version|content-type|content-transfer-encoding|in-reply-to|references|precedence|organization|user-agent|list-unsubscribe|x-[a-z0-9.\-]+|x-ms-[a-z0-9.\-]+)$/i;

  // Decide whether the pasted text starts with email headers, split them
  // out, and return useful pieces for the detectors.
  function parseEmailText(raw) {
    var lines = String(raw || '').replace(/\r\n?/g, '\n').split('\n');
    var firstHeader = lines.length > 0 ? /^([A-Za-z][A-Za-z0-9_-]*)\s*:/.exec(lines[0]) : null;
    var startsWithHeader = !!(firstHeader && KNOWN_HEADER_NAME.test(firstHeader[1]));
    var headerLines = [];
    var bodyStart = 0;
    if (startsWithHeader) {
      for (var i = 0; i < lines.length; i++) {
        if (lines[i].trim() === '') { bodyStart = i + 1; break; }
        headerLines.push(lines[i]);
      }
      if (bodyStart === 0) { bodyStart = lines.length; } // no blank line found
    }
    var headerText = headerLines.join('\n');
    var headers = startsWithHeader ? parseHeaders(headerText) : {};
    var body = startsWithHeader ? lines.slice(bodyStart).join('\n').trim() : String(raw || '').trim();
    return {
      headers: headers,
      headerText: headerText,
      hasHeaders: startsWithHeader && headerLines.length > 0,
      body: body,
      searchText: ((headers.subject || '') + '\n' + body).trim()
    };
  }

  // Parse header lines into a simple object, joining folded lines.
  function parseHeaders(headerText) {
    var out = {};
    var current = null;
    var lines = headerText.split('\n');
    for (var i = 0; i < lines.length; i++) {
      var line = lines[i];
      var m = /^([A-Za-z][A-Za-z0-9_-]*)\s*:\s*(.*)$/.exec(line);
      if (m) {
        current = m[1].toLowerCase();
        out[current] = (out[current] ? out[current] + ' ' : '') + m[2];
      } else if (current && /^\s+/.test(line)) {
        out[current] += ' ' + line.trim();
      }
    }
    return out;
  }

  // Read SPF / DKIM / DMARC verdicts from the headers.
  // Returns { spf, dkim, dmarc, raw } where each verdict is the
  // failing result string (e.g. "fail") or null if not present.
  function parseAuthResults(headers) {
    var source = [
      (headers['authentication-results'] || ''),
      (headers['received-spf'] || '')
    ].join(' | ');
    function verdict(mech, verbs) {
      var m = new RegExp('\\b' + mech + '\\s*=\\s*([a-z]+)', 'i').exec(source);
      if (!m) { return null; }
      var val = m[1].toLowerCase();
      return verbs.indexOf(val) !== -1 ? val : null;
    }
    var FAIL = ['fail', 'hardfail', 'softfail', 'permerror', 'temperror'];
    return {
      spf:   verdict('spf', FAIL),
      dkim:  verdict('dkim', FAIL),
      dmarc: verdict('dmarc', FAIL),
      raw: source
    };
  }

  /* ------------------------------------------------------------------
     4. Text detectors
     ------------------------------------------------------------------ */
  // Each detector has: id, title, points, severity and why.
  // `run(text)` returns null (no match) or a result object with a list
  // of short evidence phrases taken straight from the email.

  var TEXT = {

    urgency: {
      id: 'urgency', title: 'Urgency or pressure tactics', points: 10, severity: 'warning',
      why: 'Urgent "act now" language is a classic social-engineering trick: scammers rush you so you skip the careful thinking that would reveal the attack.',
      re: phraseRegex([
        'urgent', 'urgently', 'immediately', 'as soon as possible', 'asap', 'action required',
        'act now', 'time sensitive', 'without delay', 'do not delay', 'right away',
        'within 24 hours', 'within 48 hours', 'within the next', 'final notice',
        'final reminder', 'last reminder', 'expires today', 'today only', 'hurry',
        'respond today', 'due today', 'respond now', 'immediate action'
      ]),
      run: function (text) {
        var matches = collectMatches(this.re, text, 3);
        return matches.length ? { matches: matches } : null;
      }
    },

    suspension: {
      id: 'suspension', title: 'Threats of account suspension or closure', points: 15, severity: 'danger',
      why: 'Messages that threaten to suspend, close, lock or limit an account invent a fake consequence to pressure you into acting fast. Real providers rarely start by threatening closure.',
      re: phraseRegex([
        'account.{0,25}(suspend|suspension|closed|lock|terminat|deactivat|disabl|restrict|limit)',
        '(suspend|suspension|closed|lock|terminat|deactivat|disabl|restrict|limit).{0,25}account',
        'lose access to your (email )?account', 'your (email )?account will be', 'unusual sign-in',
        'unusual activity', 'suspicious sign-in', 'too many failed login', 'will be permanently',
        'permanently (closed|disabled)', 'temporarily (disabled|deactivated)', 'account has been (flagged|compromised)'
      ]),
      run: function (text) {
        var matches = collectMatches(this.re, text, 3);
        return matches.length ? { matches: matches } : null;
      }
    },

    password: {
      id: 'password_request', title: 'Request for your password', points: 20, severity: 'danger',
      why: 'No legitimate organisation will ever ask you to send, enter or "confirm" your password by email or through a link they email you. Anyone who asks is trying to steal it.',
      re: phraseRegex([
        'enter your password', 'confirm your (login )?password', 'verify your password',
        'provide your password', 'send (us|me) your password', 'type your password',
        'your account password', 'update your password', 're-?enter your (login )?password',
        'password.{0,15}(verify|confirm|enter)'
      ]),
      run: function (text) {
        var matches = collectMatches(this.re, text, 3);
        return matches.length ? { matches: matches } : null;
      }
    },

    code: {
      id: 'code_request', title: 'Request for a verification / MFA code', points: 20, severity: 'danger',
      why: 'One-time codes and MFA passcodes are meant for you alone. If an email asks you to share or type a "6-digit code", the sender is trying to defeat your two-factor authentication.',
      re: phraseRegex([
        'one-time (passcode|password|code|pin)', 'otp', 'verification code', 'security code',
        'authentication code', 'two-factor', '2fa', 'mfa', 'multi-factor', '6-digit code',
        '6 digit code', 'confirm it\'s you', 'confirm it is you', 'enter the (code|pin)',
        'the (code|pin) (we|i) (sent|texted|emailed)'
      ]),
      run: function (text) {
        var matches = collectMatches(this.re, text, 3);
        return matches.length ? { matches: matches } : null;
      }
    },

    payment: {
      id: 'payment_request', title: 'Payment or gift-card request', points: 15, severity: 'danger',
      why: 'Requests for payment, "fees", gift cards or wire transfers are a signature of scams. Gift cards are untraceable, which is exactly why criminals ask for them.',
      re: phraseRegex([
        'gift card', 'giftcard', 'itunes (gift )?card', 'apple gift card', 'amazon gift card',
        'google play card', 'steam card', 'prepaid card', 'reload (card|pack)', 'wire transfer',
        'bank transfer', 'western union', 'moneygram', 'bitcoin', 'crypto', 'pay now',
        'payment is required', 'payment deadline', 'make the payment', 'immediate payment',
        'pay the (fee|charge|amount)', 'processing fee', 'customs fee', 'delivery fee',
        'redelivery fee', 'shipping fee', 'settle (your|the|this|payment)',
        'to (release|unlock) your (parcel|package|funds|prize)'
      ]),
      run: function (text) {
        var matches = collectMatches(this.re, text, 3);
        return matches.length ? { matches: matches } : null;
      }
    },

    bank: {
      id: 'bank_change', title: 'Request to change or confirm bank details', points: 20, severity: 'danger',
      why: 'Messages that say "our bank details have changed" are the classic Business Email Compromise (BEC) play: they trick you into paying a real invoice into a criminal\'s account.',
      re: phraseRegex([
        'bank details', 'banking details', 'direct deposit', 'routing number', 'iban number',
        'swift code', 'new bank account', 'changed our bank', 'our bank account',
        'changed our payment details', 'update your bank', 'confirm your bank', 'billing details',
        'payment details have changed', 'update your payment details'
      ]),
      run: function (text) {
        var matches = collectMatches(this.re, text, 3);
        return matches.length ? { matches: matches } : null;
      }
    },

    invoice: {
      id: 'invoice_language', title: 'Unexpected invoice / payment-overdue language', points: 10, severity: 'warning',
      why: 'Fake invoices are a favourite attack. If you were not expecting an invoice, treat any mention of one - especially with an attachment or link - with suspicion.',
      re: phraseRegex([
        'invoice', 'overdue', 'unpaid', 'outstanding balance', 'outstanding invoice',
        'see attached invoice', 'view invoice', 'open invoice', 'invoice attached',
        'copy of invoice', 'payment reminder', 'view the invoice', 'final demand'
      ]),
      run: function (text) {
        var matches = collectMatches(this.re, text, 3);
        return matches.length ? { matches: matches } : null;
      }
    },

    credentialHarvest: {
      id: 'credential_harvest', title: 'Credential-harvesting language', points: 20, severity: 'danger',
      why: 'Phrases like "verify your account", "confirm your identity" or "click here to update" are the bait lines of fake login pages built to copy your credentials.',
      re: phraseRegex([
        'verify your (account|identity|login|information)', 'confirm your (account|identity|login)',
        'update your (account|billing|information|credit card)', 'log in (to|with|using)',
        'sign in to (verify|confirm|update|view)', 'click here to (verify|confirm|update|reactivate|renew)',
        'reactivate your account', 'unlock your account', 'restore your account',
        'keep your account', 'maintain your account', 'secure your account', 'protect your account',
        'account has been limited', 'you must (verify|confirm|update)', 'sign in to view',
        'review your account', 'validate your account', 'to avoid (suspension|disruption|closure)'
      ]),
      run: function (text) {
        var matches = collectMatches(this.re, text, 3);
        return matches.length ? { matches: matches } : null;
      }
    },

    impersonation: {
      id: 'impersonation_language', title: 'Impersonation-style language', points: 10, severity: 'warning',
      why: 'Generic greetings such as "Dear Customer", over-formal or oddly phrased English, and mystery "security teams" are tells for messages pretending to be a company they are not from.',
      re: phraseRegex([
        'dear valued (customer|client|user|member)', 'dear (valued )?customer', 'dear user',
        'dear account holder', 'dear beneficiary', 'dear winner', 'kindly',
        '(from|by) the (security|support|helpdesk|customer service|tech) team',
        'technical support team', 'helpdesk', 'security department', 'service team',
        'do not reply to this (email|message)', 'we have been trying to reach you',
        'you have been selected', 'congratulations', 'claim your (prize|reward|winnings)',
        'unclaimed (fund|funds|inheritance)', 'your (pension|inheritance|winnings)'
      ]),
      run: function (text) {
        var matches = collectMatches(this.re, text, 3);
        return matches.length ? { matches: matches } : null;
      }
    },

    macro: {
      id: 'macros_request', title: 'Request to enable macros', points: 20, severity: 'danger',
      why: 'Enabling macros in an attached Office document can silently run malware. Legitimate organisations almost never need you to enable macros just to view a document.',
      re: phraseRegex([
        'enable macros', 'enable content', 'allow macros', 'enable editing',
        'macros have been disabled', 'to view this document', 'enable macro',
        'right-?click and edit', 'macro(s)? must be enabled'
      ]),
      run: function (text) {
        var matches = collectMatches(this.re, text, 3);
        return matches.length ? { matches: matches } : null;
      }
    }
  };

  /* ------------------------------------------------------------------
     5. URL detectors
     ------------------------------------------------------------------ */

  // Pull candidate URLs out of the raw text (http, https and www forms).
  function extractUrls(text) {
    var re = /(?:https?:\/\/|www\.)[^\s<>"')\]}]+/gi;
    var out = [];
    var m;
    while ((m = re.exec(text)) !== null) {
      var u = m[0].replace(/[.,;:!?]+$/, '');
      u = u.replace(/[)\]}>'"]+$/, '');
      if (u.indexOf('...') === -1) { out.push(u); }
    }
    return out;
  }

  // Get the hostname (eg "mail.example.com") from any URL-ish string.
  function hostnameOf(urlStr) {
    try {
      var u = urlStr.indexOf('://') === -1 ? 'https://' + urlStr : urlStr;
      return new URL(u).hostname.toLowerCase();
    } catch (e) {
      var m = /(?:https?:\/\/)?([^/:\s]+)/.exec(urlStr);
      return m ? m[1].toLowerCase() : '';
    }
  }

  var URL_DETECTORS = {

    rawIp: {
      id: 'raw_ip_url', title: 'Link uses a raw IP address', points: 20, severity: 'danger',
      why: 'Legitimate companies use real domain names (like "example.com"). A link that points at a bare IP address is a strong sign of an attacker-controlled server.',
      check: function (urls) {
        var bad = [];
        for (var i = 0; i < urls.length; i++) {
          var h = hostnameOf(urls[i]);
          if (/^\d{1,3}(\.\d{1,3}){3}$/.test(h)) { bad.push(urls[i]); }
        }
        return bad.length ? { matches: bad.slice(0, 3) } : null;
      }
    },

    shortened: {
      id: 'shortened_url', title: 'Shortened URL', points: 10, severity: 'warning',
      why: 'Short links hide the real destination. It is easy to disguise a malicious site behind bit.ly or a similar service, so treat them with suspicion inside emails.',
      check: function (urls) {
        var bad = [];
        for (var i = 0; i < urls.length; i++) {
          if (SHORTENER_DOMAINS.test(urls[i])) { bad.push(urls[i]); }
        }
        return bad.length ? { matches: bad.slice(0, 3) } : null;
      }
    },

    lookalike: {
      id: 'lookalike_domain', title: 'Impersonation / lookalike domain', points: 15, severity: 'warning',
      why: 'This link pretends to be from a well-known brand, but the real domain is NOT one the brand owns. This is the classic brand-cloning trick.',
      check: function (urls) {
        var bad = [];
        for (var i = 0; i < urls.length; i++) {
          var h = hostnameOf(urls[i]);
          if (!h) { continue; }
          var brands = Object.keys(BRAND_OFFICIAL_DOMAINS);
          for (var b = 0; b < brands.length; b++) {
            var brand = brands[b];
            var token = brand.replace(/\s+/g, '');
            if (h.indexOf(token) !== -1 && !isOfficialDomainForBrand(h, brand)) {
              bad.push({ url: urls[i], brand: brand });
            }
          }
        }
        if (!bad.length) { return null; }
        return {
          matches: bad.slice(0, 3).map(function (x) { return x.url; }),
          detail: 'Impersonated brand: ' + bad[0].brand + '.'
        };
      }
    },

    suspicious: {
      id: 'suspicious_url', title: 'Suspicious URL features', points: 15, severity: 'warning',
      why: 'This link has unusual technical features (an odd free top-level domain, an embedded port number, or "user@host" syntax) that legitimate companies almost never use.',
      check: function (urls) {
        var bad = [];
        for (var i = 0; i < urls.length; i++) {
          var u = urls[i];
          var h = hostnameOf(u);
          var reasons = [];
          if (SUSPICIOUS_TLDS.test(h)) { reasons.push('unusual top-level domain'); }
          if (/@/.test(u)) { reasons.push('contains the @ trick'); }
          if (/:\d{2,5}(\/|$)/.test(u)) { reasons.push('uses a non-standard port'); }
          if (/^http:\/\//i.test(u)) { reasons.push('not encrypted (http, not https)'); }
          if (h.split('.').length > 5) { reasons.push('very long or odd subdomain'); }
          if (reasons.length) { bad.push(u + '  -  ' + reasons.join(', ')); }
        }
        return bad.length ? { matches: bad.slice(0, 3) } : null;
      }
    },

    misleading: {
      id: 'misleading_link', title: 'Misleading link text', points: 15, severity: 'warning',
      why: 'The visible text claims to go somewhere safe, but the real link points to a different address. On a computer you can check this by hovering over a link (without clicking!).',
      check: function (fullText) {
        var bad = [];
        var m;
        // Markdown style: [shown text](real url)
        var mdRe = /\[([^\]]+)\]\(\s*(https?:\/\/[^)\s]+)\s*\)/gi;
        while ((m = mdRe.exec(fullText)) !== null) {
          if (linkTextMismatch(m[1], m[2])) { bad.push(m[1] + '  ->  ' + m[2]); }
        }
        // HTML style: <a href="real url">shown text</a>
        var aRe = /<a\s+[^>]*href\s*=\s*["']([^"']+)["'][^>]*>(.*?)<\/a>/gi;
        while ((m = aRe.exec(fullText)) !== null) {
          if (linkTextMismatch(m[2], m[1])) { bad.push(m[2] + '  ->  ' + m[1]); }
        }
        return bad.length ? {
          matches: bad.slice(0, 3),
          detail: 'The visible text of the link points to a different destination than the real address.'
        } : null;
      }
    }
  };

  // True when the text shown for a link contains a domain that is
  // different from the real destination domain.
  function linkTextMismatch(visibleText, url) {
    var u = /(?:https?:\/\/)?([\w.-]+\.[a-z]{2,})/i.exec(visibleText);
    if (!u) { return false; }
    var shown = u[1].toLowerCase().replace(/^www\./, '');
    var real = hostnameOf(url).replace(/^www\./, '');
    return shown !== real;
  }

  /* ------------------------------------------------------------------
     6. Attachment detectors
     ------------------------------------------------------------------ */

  var ATTACHMENT_DETECTORS = {

    executable: {
      id: 'executable_attachment', title: 'Executable attachment type', points: 20, severity: 'danger',
      why: 'Files with these extensions are programs (or documents that can run code). Opening an unexpected one can infect your computer with malware.',
      run: function (fullText) {
        var matches = [];
        var m;
        EXECUTABLE_RE.lastIndex = 0;
        while ((m = EXECUTABLE_RE.exec(fullText)) !== null && matches.length < 3) {
          // Skip matches that are actually part of an email address.
          if (m.index > 0 && fullText[m.index - 1] === '@') { continue; }
          matches.push(m[0]);
        }
        return matches.length ? {
          matches: matches,
          detail: 'Executable or macro-enabled file type. Never open it unless you are 100% sure it is expected.'
        } : null;
      }
    },

    unusual: {
      id: 'unusual_filename', title: 'Unusual attachment filename', points: 10, severity: 'warning',
      why: 'Attackers name malware to look like a harmless document (invoice, scan, PDF). Watch for suspicious names such as "invoice_2024.zip" or double extensions.',
      run: function (fullText) {
        var re = /\b[\w][\w.-]*\.(pdf|doc|docx|xls|xlsx|ppt|pptx|zip|rar|7z|gz|tar)\b/gi;
        var m;
        var suspicious = [];
        re.lastIndex = 0;
        while ((m = re.exec(fullText)) !== null && suspicious.length < 4) {
          if (/\b(invoice|receipt|payment|delivery|order|document|scan|notice|complaint|details|report)\b/i.test(m[0])) {
            suspicious.push(m[0]);
          }
        }
        return suspicious.length ? { matches: suspicious } : null;
      }
    }
  };

  /* ------------------------------------------------------------------
     7. Main analysis function
     ------------------------------------------------------------------
     analyseEmail(text) returns:
     {
       score: 0-100,
       classification: { key, label, color, blurb },
       findings: [ { id, title, points, severity, why, matches, detail } ],
       totalPoints: number,
       authNote: string|null
     }
     The score is simply the points of every detected finding, capped
     at 100 - fully explainable.
     ------------------------------------------------------------------ */

  function analyseEmail(raw) {
    var parts = parseEmailText(raw);
    var full = String(raw || '');
    var findings = [];
    var i;

    var textDetectorList = [
      TEXT.urgency, TEXT.suspension, TEXT.password, TEXT.code, TEXT.payment,
      TEXT.bank, TEXT.invoice, TEXT.credentialHarvest, TEXT.impersonation, TEXT.macro
    ];

    // 1. Text detectors run over the subject line + body. Emails wrap
    //    across lines, so collapse whitespace into single spaces first.
    var searchFlat = parts.searchText.replace(/\s+/g, ' ');
    for (i = 0; i < textDetectorList.length; i++) {
      var tr = textDetectorList[i].run(searchFlat);
      if (tr) { findings.push(makeFinding(textDetectorList[i], tr)); }
    }

    // 2. URL detectors run over the full raw text.
    var urls = extractUrls(full);
    if (urls.length) {
      var urlList = [URL_DETECTORS.rawIp, URL_DETECTORS.shortened, URL_DETECTORS.lookalike, URL_DETECTORS.suspicious];
      for (i = 0; i < urlList.length; i++) {
        var ur = urlList[i].check(urls);
        if (ur) { findings.push(makeFinding(urlList[i], ur, true)); }
      }
      var mir = URL_DETECTORS.misleading.check(full);
      if (mir) { findings.push(makeFinding(URL_DETECTORS.misleading, mir, true)); }
    }

    // 3. Attachment detectors run over the full raw text.
    var attList = [ATTACHMENT_DETECTORS.executable, ATTACHMENT_DETECTORS.unusual];
    for (i = 0; i < attList.length; i++) {
      var ar = attList[i].run(full);
      if (ar) { findings.push(makeFinding(attList[i], ar)); }
    }

    // 4. Header / authentication checks (only possible when headers are pasted).
    var authNote = null;
    if (parts.hasHeaders) {
      var h = parts.headers;
      var fromEmails = extractEmails(h.from || '');
      var replyEmails = extractEmails(h['reply-to'] || '');
      if (fromEmails.length && replyEmails.length &&
          fromEmails[0].toLowerCase() !== replyEmails[0].toLowerCase()) {
        findings.push({
          id: 'reply_to_mismatch', title: 'Sender / Reply-To address mismatch',
          points: 15, severity: 'warning',
          why: 'The "Reply-To" address is different from the "From" address. Attackers do this so that a reply to the email goes to THEIR mailbox instead of the real company.',
          matches: ['From: ' + fromEmails[0] + '  |  Reply-To: ' + replyEmails[0]]
        });
      }

      var auth = parseAuthResults(h);
      var authParts = [];

      if (auth.spf) {
        findings.push(authFinding('spf_fail', 'SPF check failed', auth.spf,
          'SPF failed, meaning the domain named in the email did not authorise the sending server to send on its behalf.'));
        authParts.push('SPF: FAIL');
      } else if (/spf\s*=\s*pass/i.test(auth.raw)) { authParts.push('SPF: PASS'); }

      if (auth.dkim) {
        findings.push(authFinding('dkim_fail', 'DKIM check failed', auth.dkim,
          'DKIM failed, meaning the email\'s cryptographic signature could not be verified against the claimed sender domain.'));
        authParts.push('DKIM: FAIL');
      } else if (/dkim\s*=\s*pass/i.test(auth.raw)) { authParts.push('DKIM: PASS'); }

      if (auth.dmarc) {
        findings.push(authFinding('dmarc_fail', 'DMARC check failed', auth.dmarc,
          'DMARC failed, meaning the email did not satisfy the sender domain\'s published authentication policy.'));
        authParts.push('DMARC: FAIL');
      } else if (/dmarc\s*=\s*pass/i.test(auth.raw)) { authParts.push('DMARC: PASS'); }

      if (!authParts.length) {
        authNote = 'You pasted email headers, but no SPF / DKIM / DMARC results were present in them, so sender authentication could not be assessed.';
      } else {
        authNote = 'Authentication headers found:  ' + authParts.join('   ') + '.';
      }
    } else {
      authNote = 'Tip: paste the email including its headers (From, Reply-To, Authentication-Results) to enable sender-verification checks such as SPF, DKIM and DMARC.';
    }

    // 5. Score + classification. This is the ONLY place the number
    //    is computed: add every finding's points, cap at 100.
    var total = 0;
    for (i = 0; i < findings.length; i++) { total += findings[i].points; }
    var score = Math.max(0, Math.min(MAX_SCORE, total));

    var key = score >= 60 ? 'high' : (score >= 30 ? 'susp' : 'low');
    var classification = {
      key: key,
      label: CLASSIFICATIONS[key].label,
      color: CLASSIFICATIONS[key].color,
      badge: CLASSIFICATIONS[key].badge,
      blurb: CLASSIFICATIONS[key].blurb
    };

    // Sort findings: danger first, then highest points first.
    var severityOrder = { danger: 0, warning: 1, info: 2 };
    findings.sort(function (a, b) {
      var diff = severityOrder[a.severity] - severityOrder[b.severity];
      return diff !== 0 ? diff : b.points - a.points;
    });

    return {
      score: score,
      classification: classification,
      findings: findings,
      totalPoints: total,
      authNote: authNote,
      hasHeaders: parts.hasHeaders
    };
  }

  // Wrap a detector's raw result into a full Finding object.
  function makeFinding(detector, resultObj) {
    return {
      id: detector.id,
      title: detector.title,
      points: detector.points,
      severity: detector.severity,
      why: detector.why,
      matches: resultObj.matches || [],
      detail: resultObj.detail || null
    };
  }

  // Build a Finding for a failed email-authentication check.
  function authFinding(id, title, verdict, why) {
    var points = (id === 'dkim_fail') ? 10 : 15;
    return {
      id: id, title: title, points: points, severity: 'warning',
      why: why,
      matches: ['Verification result: ' + id.replace('_fail', '').toUpperCase() + ' = ' + verdict],
      detail: 'Verdict read from the Authentication-Results or Received-SPF header of the pasted email.'
    };
  }

  /* ------------------------------------------------------------------
     8. Recommendations (plain-English next steps)
     ------------------------------------------------------------------ */

  function buildRecommendations(result) {
    var recs = [];
    var ids = result.findings.map(function (f) { return f.id; });

    recs.push({
      text: 'Do not click any links, open any attachments, download anything, or reply to the original email while you investigate it.',
      high: true
    });

    if (ids.indexOf('password_request') !== -1 || ids.indexOf('code_request') !== -1 || ids.indexOf('credential_harvest') !== -1) {
      recs.push({
        text: 'Never type your password or a verification / MFA code into a page you reached from an email link. No legitimate organisation asks for these by email. If you already did, change that password immediately, enable MFA, and tell your IT / security team.',
        high: false
      });
    }

    if (ids.indexOf('payment_request') !== -1 || ids.indexOf('bank_change') !== -1 || ids.indexOf('invoice_language') !== -1) {
      recs.push({
        text: 'If the email asks for a payment, a gift card, or says banking details have changed, do not pay anything. Contact the company using the phone number or website from its official website (never from the email) to confirm the request is real.',
        high: false
      });
    }

    if (ids.indexOf('executable_attachment') !== -1 || ids.indexOf('unusual_filename') !== -1 || ids.indexOf('macros_request') !== -1) {
      recs.push({
        text: 'Do not open the attachment and do not enable macros. If the attachment is genuinely important, the sender can resend it after you confirm with them through a known, trusted channel.',
        high: false
      });
    }

    if (ids.indexOf('spf_fail') !== -1 || ids.indexOf('dkim_fail') !== -1 || ids.indexOf('dmarc_fail') !== -1 || ids.indexOf('reply_to_mismatch') !== -1) {
      recs.push({
        text: 'This email failed to prove it came from the address it claims. Even if the message looks convincing, treat the sender as unverified.',
        high: true
      });
    }

    recs.push({
      text: 'Verify the message independently: open the organisation\'s official website or app yourself, or call their published phone number. Never use contact details or links found inside the suspicious email.',
      high: false
    });

    if (result.classification.key === 'high' || result.findings.length >= 3) {
      recs.push({
        text: 'If this is a work email, report it to your security / IT team so they can block it for others. For a personal email, use your provider\'s built-in "Report phishing" option.',
        high: false
      });
    }

    recs.push({
      text: 'If you already clicked a link or entered credentials: change the affected passwords, enable two-factor authentication, watch for unexpected account activity, and consider telling your bank if financial details were involved.',
      high: false
    });

    return recs;
  }

  /* ------------------------------------------------------------------
     9. User interface
     ------------------------------------------------------------------ */

  var MAX_EVIDENCE_PER_FINDING = 3;

  // Called once when the page finishes loading.
  function initUI() {
    var input = document.getElementById('email-input');
    var analyseBtn = document.getElementById('analyse-btn');
    var clearBtn = document.getElementById('clear-btn');
    var sampleSelect = document.getElementById('sample-select');
    var results = document.getElementById('results');
    var samples = (typeof SAMPLE_EMAILS !== 'undefined') ? SAMPLE_EMAILS : [];

    // Fill the dropdown with the demo emails.
    samples.forEach(function (s) {
      var opt = document.createElement('option');
      opt.value = s.id;
      opt.textContent = s.title;
      sampleSelect.appendChild(opt);
    });

    // Build the "Try a sample" cards further down the page.
    var grid = document.getElementById('sample-grid');
    samples.forEach(function (s) {
      var card = document.createElement('article');
      card.className = 'sample-card';

      var tag = document.createElement('span');
      tag.className = 'sample-tag ' + (s.tag === 'legit' ? 'legit' : 'phish');
      tag.textContent = s.tagText;
      card.appendChild(tag);

      var h3 = document.createElement('h3');
      h3.textContent = s.title;
      card.appendChild(h3);

      var p = document.createElement('p');
      p.textContent = s.description;
      card.appendChild(p);

      var btn = document.createElement('button');
      btn.type = 'button';
      btn.className = 'btn-mini';
      btn.textContent = 'Load sample';
      btn.addEventListener('click', function () {
        input.value = s.text;
        sampleSelect.value = s.id;
        results.hidden = true; // hide the old results
        input.focus();
      });
      card.appendChild(btn);
      grid.appendChild(card);
    });

    // Dropdown loads the chosen sample into the text box.
    sampleSelect.addEventListener('change', function () {
      var chosen = null;
      for (var i = 0; i < samples.length; i++) {
        if (samples[i].id === sampleSelect.value) { chosen = samples[i]; break; }
      }
      if (chosen) {
        input.value = chosen.text;
        results.hidden = true;
        input.focus();
      }
    });

    // The main Analyse button.
    analyseBtn.addEventListener('click', function () {
      var text = input.value;
      if (!text.trim()) {
        input.setCustomValidity('Paste an email first - or load a sample using the options above.');
        input.reportValidity();
        input.setCustomValidity('');
        return;
      }
      var result = analyseEmail(text);
      renderResults(result);
      results.hidden = false;
      results.scrollIntoView({ behavior: 'smooth', block: 'start' });
    });

    // Clear button.
    clearBtn.addEventListener('click', function () {
      input.value = '';
      sampleSelect.value = '';
      results.hidden = true;
      input.focus();
    });

    // Convenience: Ctrl/Cmd + Enter analyses the current text.
    input.addEventListener('keydown', function (e) {
      if ((e.ctrlKey || e.metaKey) && e.key === 'Enter') { analyseBtn.click(); }
    });
  }

  // Paint the analysis result into the results section.
  function renderResults(result) {
    var numberEl = document.getElementById('score-number');
    var arcEl = document.getElementById('gauge-arc');
    var badgeEl = document.getElementById('classification-badge');
    var titleEl = document.getElementById('result-title');
    var explainerEl = document.getElementById('result-explainer');
    var findingsSummaryEl = document.getElementById('findings-summary');
    var listEl = document.getElementById('findings-list');
    var noFindingsEl = document.getElementById('no-findings');
    var recEl = document.getElementById('recommendations');
    var authNoteEl = document.getElementById('auth-note');

    // Gauge: fill the arc according to the score.
    numberEl.textContent = result.score;
    numberEl.style.color = result.classification.color;
    var arcLen = 157.08;
    arcEl.style.strokeDasharray = arcLen + ' ' + arcLen;
    arcEl.style.strokeDashoffset = arcLen * (1 - result.score / 100);
    arcEl.style.stroke = result.classification.color;

    // Badge + title + explainer text.
    badgeEl.className = 'badge ' + result.classification.badge;
    badgeEl.textContent = result.classification.label;
    titleEl.textContent = result.score + ' / 100 - ' + result.classification.label;
    explainerEl.textContent = result.classification.blurb;

    // Authentication note (SPF / DKIM / DMARC status or a tip).
    if (result.authNote) {
      authNoteEl.hidden = false;
      authNoteEl.textContent = result.authNote;
    } else {
      authNoteEl.hidden = true;
    }

    // Findings list.
    listEl.innerHTML = '';
    noFindingsEl.hidden = result.findings.length > 0;
    findingsSummaryEl.textContent = result.findings.length
      ? 'Found ' + result.findings.length + ' warning sign' + (result.findings.length === 1 ? '' : 's') +
        '. Each finding shows the number of points it adds - together they total ' + result.totalPoints +
        ' point' + (result.totalPoints === 1 ? '' : 's') + ', capped at 100 for the final score.'
      : '';

    result.findings.forEach(function (f) {
      var li = document.createElement('li');
      li.className = 'finding sev-' + f.severity;

      var head = document.createElement('div');
      head.className = 'finding-head';

      var title = document.createElement('span');
      title.className = 'finding-title';
      title.textContent = f.title;
      head.appendChild(title);

      var pts = document.createElement('span');
      pts.className = 'finding-points';
      pts.textContent = '+' + f.points + (f.points === 1 ? ' point' : ' points');
      head.appendChild(pts);

      li.appendChild(head);

      var why = document.createElement('p');
      why.className = 'finding-expl';
      why.textContent = f.why;
      li.appendChild(why);

      if (f.detail) {
        var det = document.createElement('p');
        det.className = 'finding-expl';
        det.textContent = f.detail;
        li.appendChild(det);
      }

      if (f.matches && f.matches.length) {
        var dl = document.createElement('dl');
        dl.className = 'finding-evidence';
        var dt = document.createElement('dt');
        dt.textContent = 'Evidence found in the email';
        dl.appendChild(dt);
        f.matches.slice(0, MAX_EVIDENCE_PER_FINDING).forEach(function (m) {
          var dd = document.createElement('dd');
          dd.textContent = '"' + m + '"';
          dl.appendChild(dd);
        });
        li.appendChild(dl);
      }

      listEl.appendChild(li);
    });

    // Recommendations.
    recEl.innerHTML = '';
    buildRecommendations(result).forEach(function (r) {
      var li = document.createElement('li');
      li.className = 'rec-item' + (r.high ? ' rec-high' : '');
      li.textContent = r.text;
      recEl.appendChild(li);
    });
  }

  /* ------------------------------------------------------------------
     10. Export + boot
     ------------------------------------------------------------------ */

  var engine = {
    analyseEmail: analyseEmail,
    buildRecommendations: buildRecommendations,
    parseEmailText: parseEmailText,
    extractUrls: extractUrls,
    CLASSIFICATIONS: CLASSIFICATIONS
  };

  // Expose the engine so the page scripts and browser console can use it.
  var root = (typeof window !== 'undefined') ? window : globalThis;
  root.EmailAnalyser = engine;

  // Start the interface only when running inside a real browser page.
  if (typeof document !== 'undefined' && document.getElementById('email-input')) {
    if (document.readyState === 'loading') {
      document.addEventListener('DOMContentLoaded', initUI);
    } else {
      initUI();
    }
  }

  // Also allow Node.js test scripts to load this file with require().
  if (typeof module !== 'undefined' && module.exports) {
    module.exports = engine;
  }
})();












