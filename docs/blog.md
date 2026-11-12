# Catching the cookies your website sets before anyone clicks Accept

A cookie banner tells visitors they have a choice. Whether the site actually respects that choice is a separate question, and the banner cannot answer it. Many sites load analytics and advertising scripts the moment a page opens and show the banner afterwards. I built Cookie Consent Auditor, an open source Python tool, to check this automatically.

## Why this matters

EU rules on cookies (Article 5(3) of the ePrivacy Directive, with GDPR defining what valid consent means) require consent before a site stores non-essential cookies on a visitor's device. Only strictly necessary cookies, such as session, security and load balancing cookies, are exempt.

That makes a Google Analytics cookie, a Meta Pixel cookie or an advertising identifier written on page load a compliance gap, even when the site shows a banner a second later. The usual causes are:

- A tag manager configured to fire on page load instead of after consent.
- A marketing pixel pasted directly into a page template.
- A third party embed that sets its own cookies.
- A consent tool that records the visitor's choice but does not block the scripts.

These problems are easy to introduce and hard to notice. A manual check in browser DevTools takes minutes per page, and every release or marketing tag change can bring the problem back.

## What the tool does

For each URL, the auditor:

1. Starts a fresh headless Chromium context with no cookies and no storage, so earlier visits cannot affect the result.
2. Loads the page, waits for the network to go idle, then waits a few more seconds so tag managers and deferred scripts can run.
3. Never clicks, scrolls or types. The consent banner is never touched, so every cookie it records was written before consent.
4. Reads every cookie in the browser, including third party cookies, with its domain, expiry, flags and source (a `Set-Cookie` header or JavaScript).
5. Classifies each cookie and gives the page a verdict.

It also records requests to known tracker hosts, which catches pixels that fire before consent even when they do not set a cookie.

## How cookies are classified

Each cookie is checked in this order:

1. **Essential signatures:** sessions, CSRF tokens, load balancers, bot protection and the cookies that consent management platforms use to store the visitor's choice.
2. **Tracker name signatures:** Google Analytics, Meta, Microsoft Clarity, Hotjar, HubSpot and others. Generic names such as `fr` or `NID` only match when the cookie domain also belongs to the vendor, which avoids flagging a first party cookie that happens to share a short name.
3. **Tracker domains:** any cookie set by a known advertising or analytics host, for example `doubleclick.net`.
4. **Functional signatures:** language, theme and chat widget cookies, reported for review because consent may still be required.
5. **A heuristic for unknown cookies:** a cookie that lasts longer than a day and holds an identifier like value is reported for review.

The built in list covers 104 tracker vendors. You can add your own with a small JSON file.

## The verdict

| Verdict | Meaning |
|---|---|
| FAIL | At least one analytics, advertising or social cookie exists before consent |
| REVIEW | No definite violation, but functional cookies, unknown persistent identifiers or tracker requests need a manual check |
| PASS | Only essential cookies, or none |
| ERROR | The page could not be loaded |

Severity per cookie: advertising is high, analytics and social are medium, and a third party cookie is raised to high.

## Try it in five minutes

```bash
pip install -r requirements.txt
python -m playwright install chromium

# Terminal 1: a local demo site with good, bad and mixed behaviour
python -m demo_site.server

# Terminal 2: audit it
python -m cookie_auditor http://127.0.0.1:8765/bad http://127.0.0.1:8765/good http://127.0.0.1:8765/mixed
```

The `/bad` page sets Google Analytics, Meta and Google Ads cookies on load and fails. The `/good` page sets only a session cookie until Accept is clicked and passes. The `/mixed` page sets an unrecognised persistent identifier and lands on review.

To audit your own sites, list them in a text file and run:

```bash
python -m cookie_auditor --file urls.txt --wait 8 --screenshots
```

## Reading the report

Each run writes three reports with the same content: a self contained HTML file for reading, Markdown for tickets and wikis, and JSON for scripts. For every cookie the report shows the verdict, category, vendor, domain, whether it is first or third party, lifetime, and the reason it was classified that way.

The **Source** column helps with the fix. A cookie created by JavaScript usually comes from a tag or script that needs to be gated behind consent. A cookie created by a `Set-Cookie` header comes from the server or from a third party response.

## How it helps

- **Developers and QA:** the exit code is 0 when no page failed, 1 when at least one page has a FAIL verdict and 2 on a scan error. A scheduled pipeline can audit production pages and fail the build when a new tracker appears before consent.
- **Privacy and security teams:** the report gives evidence per cookie, with vendor, severity and lifetime, instead of a screenshot of DevTools.
- **Agencies and consultants:** one text file with many URLs produces one report for all of them.
- **Marketing and web teams:** a tag change can be checked before and after release.

## What testing turned up

I checked the project from a clean install before publishing it, and the check found real bugs. A missing URL file crashed with a traceback and exited with code 1, the same code the tool uses for a failed audit. A CI job would have reported a privacy failure when the real problem was a typo. It now exits with code 2 and a clear message. Malformed signature files and a missing Chromium install get the same treatment.

I also ran it against a few public news sites. One homepage set 273 cookies before any interaction, 252 of them from third parties, including cookies from more than twenty advertising and analytics vendors. That scan ran from a cloud server, so the consent flow it saw may differ from what a visitor in Ireland sees. It still showed two things. The tool handles a heavy ad tech page, and the long tail of unrecognised vendors is exactly why the REVIEW verdict exists. I added signatures for the vendors that showed up in those scans, along with common consent platform cookies that had been wrongly flagged.

## Limitations

- It inspects cookies only. localStorage, sessionStorage and fingerprinting are out of scope. Requests to tracker hosts are reported as a warning, not as a cookie violation.
- Detection is signature based. A tracker missing from the list appears as unknown and is flagged only if it is persistent and identifier like.
- It scans the URLs you list and does not crawl.
- Some sites show a consent flow only to visitors in certain regions. Use the `--locale` option and run the tool from a network location that matches your audience.
- Some regulators treat certain privacy preserving first party analytics as exempt. The tool still reports analytics cookies as violations, so review those findings against the rules that apply to you.
- Sites with strong bot protection may block headless Chromium.
- Automated findings are indicators. Confirm them manually before calling a site non compliant, and note that this is not legal advice.

Only scan sites you own or have permission to test.

## Ideas for next steps

- A second pass that clicks Accept and Reject and compares the three cookie sets, to confirm that Reject really blocks trackers.
- Checking localStorage and sessionStorage.
- A small crawler for checkout, login and landing pages.

## Get the code

The project is on GitHub: [github.com/shreeshk07/cookie-consent-auditor](https://github.com/shreeshk07/cookie-consent-auditor). The README covers every option, the exit codes and how to add custom signatures. Feedback and signature contributions are welcome.

---

## LinkedIn post (short version)

Most cookie banners tell visitors they have a choice. The harder question is whether the site waits for that choice before setting analytics and advertising cookies.

I built Cookie Consent Auditor to check it automatically. It loads a page in a headless browser, never clicks the banner, records every cookie set before consent, and classifies each one against 104 known tracker vendors. Each page gets a PASS, REVIEW or FAIL verdict, plus HTML, Markdown and JSON reports.

It works as a CI gate too. The exit code is 1 when a page fails, so a new tracker appearing before consent can fail a build.

Built with Python and Playwright, with 53 tests and a local demo site so you can try it in five minutes. Link to the code and the full write up in the comments.

#CyberSecurity #Privacy #GDPR #Python #OpenSource
