# consent-tracker-scan

See what a website does **before the visitor says yes**: the cookies, the web storage and the third-party trackers that load as soon as the page opens.

```
python -m consent_tracker_scan https://your-site.ca/ --pages 5 --md report.md --json report.json
```

The site is loaded in headless Chromium (Playwright) as a first-time visitor with an empty profile. The consent banner is **never clicked** unless you ask for `--reject` (see below). The report lists:

- **every cookie**, first-party and third-party, with domain, name, expiry and flags (Secure, HttpOnly, SameSite). Values are never stored, only their length;
- **every localStorage and sessionStorage key**, including keys in iframes;
- **every third-party request**, meaning any host outside the site's registrable domain. Each one is classified with a bundled tracker list: analytics, advertising, social pixel, session replay, tag manager, embed, CDN/fonts, consent platform or **unknown**;
- **the consent banner**, if there is one, and which CMP it is: OneTrust, Cookiebot, CookieYes, Complianz, Osano, Quantcast Choice, Usercentrics, Didomi, TrustArc, or a generic cookie banner. It is detected from script URLs and DOM selectors.

Each finding gets a severity. **High**: analytics, advertising, social pixel or session replay firing before consent, or a cookie or storage key written by one of them. **Medium**: tag managers, video embeds, unknown third parties and unknown third-party cookies. **Low**: fonts, public CDNs and cookieless analytics (Cloudflare Web Analytics, Plausible, Fathom, Simple Analytics). **Info**: other first-party cookies and consent-platform cookies. Plain-English notes relate the results to Quebec Law 25 and PIPEDA. They are general information, **not legal advice**.

Why: many small-business sites in Canada have a cookie banner, but Google Analytics, the Meta pixel or Hotjar still fire before anyone clicks it. This tool shows exactly what fired, in a report you can hand to a developer.

## Install

```
pip install .
python -m playwright install chromium   # once, if Chromium is not installed yet
```

Python 3.10+. The only dependency is Playwright; everything else uses the standard library.

## Usage

```
python -m consent_tracker_scan URL [--pages N] [--delay SECONDS] [--timeout SECONDS]
                               [--wait-ms MS] [--json out.json] [--md out.md]
                               [--extra-trackers FILE] [--reject] [--quiet]
```

- `--pages N` crawls up to N same-origin pages (1-20, default 1), breadth-first from the start URL. The scanner reads robots.txt the way Google does (RFC 9309: the most specific rule wins, with `*` and `$` wildcards) and never loads a disallowed URL. Pages are fetched one at a time.
- `--delay` sets the pause between pages (default 1 s). If robots.txt sets a larger `Crawl-delay`, that value is used instead.
- `--timeout` is the page load timeout (default 30 s). `--wait-ms` is the extra time to wait after the load event, so late tags can fire (default 3000).
- `--json` and `--md` write the reports. Without either option, the Markdown report goes to stdout.
- `--reject` checks that "no" means no. After the normal scan, the start page is loaded once more in a fresh context. The tool finds the banner's reject button: first the known CMP buttons (OneTrust, Cookiebot, CookieYes, Complianz, Osano, Didomi, Usercentrics, Quantcast, TrustArc), then a visible button whose whole text is an unambiguous refusal ("Reject all", "Decline", "Only necessary", "Tout refuser", "Rechazar"...). It clicks that one button, reloads, and records what fires. The verdict is `ok` (no tracking request and no new tracking cookie), `fail` (tracking continues; exit code 1), or `no_button`. It never clicks Accept, Settings or anything else; if no clear reject button exists, nothing is clicked.
- `--extra-trackers` adds your own entries, in the same format as `consent_tracker_scan/data/trackers.json`.

**Exit codes:** `0` means no high-severity findings. `1` means at least one high-severity finding, or, with `--reject`, trackers still firing after reject. `2` means a usage error, or nothing could be scanned: bad URL, browser missing, start page blocked by robots.txt or unreachable. This makes it usable as a CI check on your own site.

From Python: `from consent_tracker_scan import scan_site; report = scan_site("https://your-site.ca/", pages=3)`.

Each page is loaded in a **fresh browser context**, so every page is seen the way a first-time visitor landing on it would see it.

`--reject` on the author's own sites, which load no tracker and therefore show no banner:

```
$ python -m consent_tracker_scan https://demarkstudio.ca/en/ --reject --quiet --md r.md
1 page(s): 0 high, 0 medium, 1 low; 1 cookie(s), 0 storage key(s), 1 third-party host(s); banner: none; after reject: no_button
$ python -m consent_tracker_scan https://demo.demarkstudio.ca/riverside-pub/site --reject --quiet --md r.md
1 page(s): 0 high, 0 medium, 1 low; 0 cookie(s), 0 storage key(s), 1 third-party host(s); banner: none; after reject: no_button
```

That is the right outcome: the only third party is cookieless Cloudflare Web Analytics (low), so there is nothing to refuse and nothing was clicked. The `ok` and `fail` verdicts are proven by the local test sites.

## Measured result

Output from the bundled demo, run on this machine. `examples/serve_demo.py` serves a small bakery site on `127.0.0.1:8401`. The site has a Cookiebot-style banner, a fake analytics tag on `localhost:8402` and a chat widget on `127.0.0.2:8403`, which Chromium treats as three different sites. Nothing leaves the machine.

```
$ python examples/serve_demo.py            # terminal 1
$ python -m consent_tracker_scan http://127.0.0.1:8401/ --pages 3 \
      --extra-trackers examples/demo-trackers.json --json report.json --md report.md
scanning http://127.0.0.1:8401/
scanning http://127.0.0.1:8401/about.html
2 page(s): 4 high, 1 medium, 0 low; 4 cookie(s), 3 storage key(s), 2 third-party host(s); banner: Cookiebot
$ echo $?
1
```

From `report.md`:

```
## Findings

- **HIGH** Demo Analytics (analytics) loaded before consent. 4 request(s) to localhost.
- **HIGH** First-party cookie _da_id set by Demo Analytics (analytics) before consent. domain 127.0.0.1, expires 2027-11-03T06:27:42Z.
- **HIGH** Third-party cookie da_uid set by Demo Analytics (analytics) before consent. domain localhost, expires 2027-09-29T06:27:42Z.
- **HIGH** localStorage key _da_last_visit written by Demo Analytics (analytics) before consent. origin http://127.0.0.1:8401.
- **MEDIUM** Unknown third party 127.0.0.2 contacted before consent. 1 request(s), types: script. Not in the tracker list; check what it is.

## Cookies (4)

| Severity | Party | Domain | Name | Expires | Flags | Tracker |
|---|---|---|---|---|---|---|
| high | first | 127.0.0.1 | _da_id | 2027-11-03T06:27:42Z | SameSite=Lax | Demo Analytics |
| high | third | localhost | da_uid | 2027-09-29T06:27:42Z | Secure SameSite=None | Demo Analytics |
| info | first | 127.0.0.1 | shop_session | session | HttpOnly SameSite=Lax |  |
| info | first | 127.0.0.1 | theme | 2027-09-29T06:27:41Z | SameSite=Lax |  |

## Pages

| URL | Status | 3rd-party requests | Banner | Error |
|---|---|---|---|---|
| http://127.0.0.1:8401/ | 200 | 3 | Cookiebot |  |
| http://127.0.0.1:8401/about.html | 200 | 2 |  |  |

Skipped because robots.txt disallows them:

- http://127.0.0.1:8401/private/orders.html
```

The tracker asked for a 2-year cookie, and the report shows the 400-day expiry Chromium actually stored. The third page was not scanned because robots.txt disallows it.

```
$ python -m pytest -q -p no:cacheprovider --import-mode=importlib consent-tracker-scan
118 passed in 54.62s
```

The tests use no internet. Local `http.server` fixtures on random ports serve a first-party site, which sets cookies by header and by JavaScript and writes storage. A fake tracker is served from a second origin (`localhost` vs `127.0.0.1`). Other fixtures serve OneTrust-like, Cookiebot-like and generic banners with click traps that prove nothing is clicked, sites that honour or ignore a reject click (and one with only an Accept button, which must never be pressed), robots.txt rules and link farms for `--pages`. Browser tests skip with the reason if Chromium cannot start.

## Tracker list

`consent_tracker_scan/data/trackers.json` has 26 entries. Each entry lists request domains (subdomains included), cookie and storage name patterns, a category and a `source` link to the vendor documentation that describes them. It covers Google Analytics/GA4, Google Tag Manager, Google Ads/DoubleClick, Meta Pixel, TikTok Pixel, LinkedIn Insight, Twitter/X, Pinterest, Snap, Microsoft UET (Bing), Hotjar, Microsoft Clarity, FullStory, Segment, Mixpanel, YouTube and Vimeo embeds, Google Fonts, Adobe Fonts, public JS CDNs and the main CMPs. The list was compiled by hand; vendors change domains, so corrections are welcome.

## Limitations

- It sees one visit, from your network location, within the wait time. Trackers that fire on scroll or click, after a delay or only for some countries (geo-targeted banners) can be missed. Run it from Canada to see what Canadians see.
- Headless Chromium identifies itself as `HeadlessChrome`, and some sites behave differently for it.
- The registrable domain uses a short built-in suffix list, not the full Public Suffix List. Unusual suffixes fall back to the last two labels.
- A cookie is linked to a tracker by its name pattern or domain, not by which script set it. A first-party cookie with a tracker-like name is reported as that tracker's.
- CMP detection relies on known selectors and script URLs. A custom banner is only found by the generic heuristic, which can miss it.
- The notes flag risk; they do not decide compliance. Consent rules depend on purpose, sensitivity and context. This is not legal advice.
- Only scan sites you own or have permission to test.

## Author

Marvin Palencia, founder of [DeMark Studio](https://demarkstudio.ca), Miramichi, New Brunswick, Canada. Portfolio: [marvin.demarkstudio.ca](https://marvin.demarkstudio.ca)

MIT License.
