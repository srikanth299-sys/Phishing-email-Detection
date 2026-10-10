/* ============================================================
   Phishing Email Analyser - fictional demo emails
   ------------------------------------------------------------
   IMPORTANT: Every email here is 100% made up.
   - Domains use ".example", a domain suffix that is officially
     reserved and CANNOT exist on the internet.
   - The IP address and links lead nowhere real.
   Do not use these in a real attack; they exist purely for
   education and testing.
   ============================================================ */

(function () {
  'use strict';
  var root = (typeof window !== 'undefined') ? window : globalThis;

  root.SAMPLE_EMAILS = [

    /* 1. OBVIOUS PHISHING ---------------------------------- */
    {
      id: 'obvious',
      tag: 'phish',
      tagText: 'Phishing',
      title: 'Obvious phishing',
      description: 'The classic "your account will be closed" scare tactic, full of urgency, impersonation and a fake login link.',
      text: [
        'From: "Security Department" <noreply@suspend-alert.example>',
        'To: victim@example.com',
        'Subject: URGENT: Final notice - your account will be closed',
        '',
        'Dear Valued Customer,',
        '',
        'Your account has been flagged for unusual sign-in activity. If you do not',
        'verify your identity within 24 hours, your account will be permanently',
        'suspended.',
        '',
        'CLICK HERE TO VERIFY YOUR ACCOUNT NOW:',
        'https://account-verify-microsoft.example/login',
        '',
        'Enter your password and confirm your account to keep it active. Failure to',
        'act immediately will result in permanent closure. This is the last reminder.',
        'Act now!',
        '',
        'Do not share this warning with anyone.',
        '',
        'Sincerely,',
        'Your Security Team'
      ].join('\n')
    },

    /* 2. SOPHISTICATED PHISHING ---------------------------- */
    {
      id: 'sophisticated',
      tag: 'phish',
      tagText: 'Phishing',
      title: 'Sophisticated phishing',
      description: 'A calm, well-written "unusual sign-in" alert. No spelling mistakes - the red flags are hidden in the links, headers and verification code request.',
      text: [
        'Delivered-To: jamie.rivera@example.com',
        'Received: from mail.examplecorp.com by mx.example.com with ESMTP',
        'From: Microsoft Account <no-reply@account.microsoft.com.example>',
        'To: jamie.rivera@example.com',
        'Date: Mon, 3 Mar 2025 09:12:00 -0500',
        'Subject: Security alert: new sign-in from an unrecognised device',
        'Reply-To: accounthelp@security-verify.example',
        'Authentication-Results: mx.example.com; spf=fail smtp.mailfrom=account.microsoft.com.example; dkim=fail (signature not verified) header.d=account.microsoft.com.example; dmarc=fail (policy not aligned)',
        '',
        'Hi Jamie,',
        '',
        'We noticed a new sign-in to your account from an unrecognised device in',
        'Moscow, Russia. If this was you, you do not need to do anything.',
        '',
        'If this was not you, we recommend you review your recent activity using the',
        'secure link below:',
        '',
        '[https://account.microsoft.com](https://account.microsoft.com.example/verify)',
        '',
        'To keep your account protected, you can also confirm it is you by entering',
        'the 6-digit code we have sent to your registered phone number.',
        '',
        'Thanks,',
        'Microsoft account security team'
      ].join('\n')
    },

    /* 3. FAKE MICROSOFT 365 ACCOUNT WARNING ----------------- */
    {
      id: 'm365',
      tag: 'phish',
      tagText: 'Phishing',
      title: 'Fake Microsoft 365 warning',
      description: 'A fake "mailbox almost full / quota exceeded" alert designed to harvest Microsoft 365 credentials.',
      text: [
        'From: Microsoft 365 Team <notifications@m365-quota.example>',
        'Subject: Your mailbox is almost full - action required',
        '',
        'Dear Office 365 User,',
        '',
        'Your mailbox has reached 96% of its storage quota. If you do not increase',
        'your quota soon, you will lose access to your email account for security',
        'reasons.',
        '',
        'To avoid suspension, sign in to confirm your account and update your',
        'password using the secure portal below:',
        '',
        'https://login-microsoft.account-verify.example/renew',
        '',
        'Click here to update your account now. Failure to act within 48 hours may',
        'result in your account being temporarily deactivated.',
        '',
        'Yours sincerely,',
        'Microsoft 365 Service Team'
      ].join('\n')
    },

    /* 4. FAKE PARCEL DELIVERY ------------------------------- */
    {
      id: 'parcel',
      tag: 'phish',
      tagText: 'Phishing',
      title: 'Fake parcel-delivery message',
      description: 'A fake courier notice asking you to pay a "small delivery fee" - note the link uses a raw IP address.',
      text: [
        'From: DHL Express <service@dh1-express.example>',
        'To: victim@example.com',
        'Subject: Your parcel could not be delivered - action required',
        '',
        'Dear Customer,',
        '',
        'We attempted to deliver your parcel (tracking ref DHL-882731) but the',
        'delivery address was incomplete.',
        '',
        'To reschedule delivery and avoid the parcel being returned to sender, you',
        'must pay a small redelivery fee of GBP 1.99 within 24 hours.',
        '',
        'Payment link: http://192.168.145.6:8080/delivery/confirm?order=882731',
        '',
        'Please make the payment right away so we can dispatch your parcel. If the',
        'fee is not paid, your parcel will be returned immediately.',
        '',
        'Yours faithfully,',
        'DHL Express Customer Service'
      ].join('\n')
    },

    /* 5. FAKE INVOICE / BEC --------------------------------- */
    {
      id: 'bec',
      tag: 'phish',
      tagText: 'Phishing',
      title: 'Fake invoice / BEC-style',
      description: 'A business-email-compromise (BEC) style fake invoice with a Reply-To mismatch and a request to change payment details.',
      text: [
        'From: Accounts Payable <accounts@globaltraders.example>',
        'Reply-To: okafor.ap@new-remit.example',
        'Subject: OVERDUE INVOICE #INV-8841 - please settle payment immediately',
        '',
        'Dear Finance Team,',
        '',
        'Kindly find attached the overdue invoice #INV-8841 for services rendered',
        'last month. If the outstanding balance is not settled within 24 hours, our',
        'accounts department will suspend your account with us.',
        '',
        'Please note that our bank details have changed. Confirm your bank details',
        'below to update our remittance records.',
        '',
        'View a copy of the invoice here: https://bit.ly/inv8841',
        '',
        'We require immediate payment. Kindly confirm receipt.',
        '',
        'Regards,',
        'A. Okafor',
        'Accounts Payable, Global Traders'
      ].join('\n')
    },

    /* 6. LEGITIMATE EMAIL ----------------------------------- */
    {
      id: 'legit',
      tag: 'legit',
      tagText: 'Legitimate',
      title: 'Legitimate email',
      description: 'A normal internal note from a colleague. Compare how few warning signs it shows versus the fake examples above.',
      text: [
        'From: Marcus Chen <marcus.chen@example.com>',
        'To: jamie.rivera@example.com',
        'Subject: Lunch meeting follow-up',
        '',
        'Hi Jamie,',
        '',
        'Thanks for the chat at lunch today - great to compare notes on the project',
        'plan.',
        '',
        'I have drafted the follow-up actions based on our discussion:',
        '',
        '1. Share the updated timeline with the wider team',
        '2. Book a room for Friday\'s review session',
        '3. Send the draft notes to HR for feedback',
        '',
        'No action needed from you this week. I will send the final version on',
        'Monday morning so you can review it before our stand-up.',
        '',
        'Best,',
        'Marcus'
      ].join('\n')
    }
  ];
})();

