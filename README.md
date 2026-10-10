# Phishing Email Analyser

A free, private, educational web app that helps you spot phishing warning signs in an email.

Paste an email, click **Analyse Email**, and the app:
- gives a **risk score from 0 to 100** (every point is explained — no magic numbers),
- classifies the email as **Low Risk**, **Suspicious** or **High Risk**,
- lists **every warning sign** it found with an explanation and quoted evidence from the email,
- suggests practical **next steps** for what to do.

It is built with nothing but **plain HTML, CSS and JavaScript**. There is no server, no database, no
accounts, no tracking and no external requests of any kind.

---

## Privacy — this is the important bit

**Everything runs inside your web browser, on your device.** The email text you paste is processed by the
JavaScript in the page and never leaves your computer. It is never uploaded to a server, an AI provider, an
analytics service or an external API.

You can prove this yourself:

1. Press `F12` in your browser, open the **Network** tab.
2. Paste an email and click **Analyse Email**.
3. The Network tab stays empty — nothing was sent anywhere.

Or simply disconnect your internet and try it. It still works.

---

## What's in the folder

| File | What it does |
|------|--------------|
| `index.html` | The page you open — structure and text |
| `styles.css` | All the styling (colours, layout, mobile sizing) |
| `script.js` | The analysis engine + the interface logic |
| `examples.js` | Six fully fictional demo emails for learning |
| `tests/test.js` | Automated checks for the analysis engine |
| `tests/ui-smoke.js` | Automated check that the interface works |

---

## How to run it

The simplest way (no installation needed):

1. Open the folder `phishing-email-analyser`.
2. Double-click **`index.html`**.
3. It opens in your web browser. That's it.

> If your browser shows a warning about opening a local file, use one of these free options instead:
> - Drag the whole folder onto the [Netlify Drop](https://app.netlify.com/drop) website,
> - or follow the GitHub Pages steps below.

---

## How to test it (for you, or for any future you)

There are two little test programs included — run from the command line:

```
node tests/test.js
node tests/ui-smoke.js
```

They print a list of ✔ marks. If you ever change the code, re-run them to make sure nothing broke. (No
packages need installing — this uses only what Node.js provides.)

---

## How the scoring works

There is **no hidden algorithm**. The analysis runs a list of detectors — for example
"requests your password" or "link uses a raw IP address". Every detector has a **fixed number of points**.
If it fires, those points are shown on screen next to the finding. The risk score is simply all the points
added together, capped at 100.

| Total points | Classification |
|---|---|
| 0–29 | 🟢 Low Risk |
| 30–59 | 🟡 Suspicious |
| 60–100 | 🔴 High Risk |

You can change any detector's points by editing `script.js` — search for `points: 20` etc. and adjust the
number. Re-run the tests afterwards.

---

## What this tool can and cannot do

- It is an **educational triage tool**. It finds *warning signs*; it cannot **prove** an email is malicious.
- A low score does **not** mean an email is definitely safe. A high score means *treat it with extreme care*.
- It uses simple text-pattern rules that a learner can read and improve. It can be fooled, and it can
  over-flag legitimate mail.
- **Never click links or open attachments just to test a suspicious email.**
- Always verify important messages through an organisation's official website, app, or official phone number.

---

## Hosting it free as a static site

The whole site is static, so any plain file host works. With GitHub Pages:

1. Create a free GitHub account and a new repository.
2. Upload the files (`index.html`, `styles.css`, `script.js`, `examples.js`). You can leave the `tests` folder
   out if you like — it is not needed to run the site.
3. In the repository settings, enable **GitHub Pages** and choose the main branch.
4. Done — the site gets a free `https://yourname.github.io/...` address.

Alternative one-click options: **Netlify Drop** (drag the folder onto the website) or **Cloudflare Pages**
(also drag-and-drop).

---

## Ideas for learning (when you're ready)

- Open `script.js` and find the detector lists (search for `TEXT = {`). Try adding your own phrase to a list.
- Try adding a brand to `BRAND_OFFICIAL_DOMAINS` so lookalike domains can impersonate it.
- Notice how `collectMatches` pulls quoted evidence straight out of the email for the on-screen "Evidence"
  boxes.
- Re-run `node tests/test.js` after every change to see if your change works.

Everything here is fictional and for education. Please never use these techniques against real people.