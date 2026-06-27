# FormSentry 🛡️

**Security & privacy assessment for Google Forms.**

Point FormSentry at a Google Form **or at any web page**, and it will
auto‑discover the Google Forms, audit each one's *externally observable*
security posture the way a pen tester would — **without ever submitting a
response** — and roll the whole set up into a single risk summary.

It catches the misconfigurations that actually leak data in the real world, and
it classifies the personal data each form collects (in **English *and*
Hebrew**), flagging national‑ID, minors', health, and payment data specifically.

```
━━ FormSentry report ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Target : https://forms.gle/XXXXXXXX
Title  : רישום לאימוני שחייה לילדים
Risk   : HIGH

Findings (5):
  [HIGH] Collects minors' / children's data
        Question(s): “שם הילד/ה”; “גיל הילד/ה”
        → Confirm the linked responses Sheet is shared 'Restricted', set a
          retention/deletion routine, and verify a lawful basis.
  [INFO] Response summary is restricted
        The /viewanalytics endpoint is not public. Good.
```

> ⚠️ **Authorized use only.** Assess forms you own or have explicit permission to
> test. FormSentry is read‑only by design, but you are responsible for how you
> use it.

---

## Why

Google Forms is the invisible back door of a lot of small organizations. The form
*looks* harmless, but:

- "**See summary charts and text responses**" is a single toggle that turns the
  share link into a public dump of **everyone's answers**.
- The **linked responses Sheet** is frequently set to *"Anyone with the link"*.
- Forms quietly collect **children's names + ages**, **national IDs**, **health
  data**, even **payment details** — with no retention policy and no DPA.

FormSentry turns the manual checks a reviewer does by hand into one command.

## What it checks

| Check | Severity if bad | How |
|---|---|---|
| Public response summary (`/viewanalytics`) | **critical** | Endpoint returns `200` instead of redirecting to `analyticsrestricted` |
| Public quiz scores (`/viewscore`) | **high** | Endpoint returns `200` |
| Collects payment‑card data | **critical** | Question text classifier |
| Collects national‑ID / passport | **high** | Classifier (incl. `תעודת זהות`, `ת"ז`, passport) |
| Collects health / medical data | **high** | Classifier (incl. `רפואי`, `אלרגיה`) |
| Collects minors' / children's data | **high** | Classifier (incl. `ילד`, `גיל`, child/age) |
| Accepts file uploads | **medium** | Question type = file upload (lands in owner's Drive) |
| Collects phone / address / DOB / financial | **medium** | Classifier |
| Sign‑in wall / org restriction | info | Login redirect detection |
| Linked Sheet sharing reminder | low | Always — it's the #1 leak path and can't be seen externally |

## Install

No dependencies. Python 3.8+.

```bash
git clone https://github.com/MickeyAlton33/formsentry.git
cd formsentry
python3 formsentry.py --help
```

Optionally drop it on your PATH:

```bash
install -m 0755 formsentry.py /usr/local/bin/formsentry
```

## Usage

### Assess known forms

```bash
# single form (URL, forms.gle short link, or raw form id all work)
python3 formsentry.py https://forms.gle/XXXXXXXX

# several at once
python3 formsentry.py https://forms.gle/AAA https://docs.google.com/forms/d/e/ID/viewform

# from a file (one target per line; '#' comments allowed)
python3 formsentry.py -i targets.txt
```

### Discover & mass‑analyze 🔎

Don't have the form links? Point FormSentry at a page — a Linktree, a website,
any link hub — and it finds the forms for you, then assesses them all.

```bash
# scan a page for Google Forms and assess everything found
python3 formsentry.py --discover https://linktr.ee/some.org

# just list the forms it finds (no assessment)
python3 formsentry.py --discover --list-only https://example.org

# crawl the whole site one hop deep (same host), capped at 80 pages
python3 formsentry.py --discover --depth 1 --max-pages 80 https://example.org

# discover across many seed pages from a file
python3 formsentry.py --discover -i seeds.txt --md -o audit.md
```

When more than one form is assessed, a **mass‑analysis summary** is printed:
worst risk, counts by severity, which PII categories appear across the set, and
the worst offenders first.

```
╔══ MASS ANALYSIS SUMMARY ════════════════════════════
  Forms assessed : 4
  Worst risk     : HIGH
  By risk        : 2 high  2 medium
  PII seen       : email address×4, phone number×4, name×3, minors' data×2
  Needs attention (medium+):
    [HIGH] Children's swim registration
    ...
╚═════════════════════════════════════════════════════
```

### Output & CI

```bash
python3 formsentry.py https://forms.gle/XXXX --json          # JSON
python3 formsentry.py --discover https://site --md -o out.md # Markdown file

# CI gate: exit non‑zero if anything is 'high' or worse
python3 formsentry.py -i targets.txt --fail-on high
```

### Output formats

- **default** — colored terminal report (+ summary when >1 form)
- `--json` — structured JSON: `{ "reports": [...], "summary": {...}, "discovered": [...] }`
  (`summary` present when >1 form; `discovered` present with `--discover`)
- `--md` — Markdown report with a questions table (+ summary section)

### Exit codes

`0` clean / below threshold · `1` finding ≥ `--fail-on` · `2` no targets given.

## How it works

0. *(with `--discover`)* Fetches each seed page, extracts every Google Form link
   (`forms.gle`, `docs.google.com/forms/...`, legacy `goo.gl/forms`) — including
   the JSON‑escaped links inside link‑hub pages — and, with `--depth`, follows
   same‑host links to find more. De‑dupes by form id.
1. Resolves `forms.gle` short links and normalizes any input to the published
   `/forms/d/e/<id>/` form id.
2. `GET`s the public `viewform` page and parses the embedded
   `FB_PUBLIC_LOAD_DATA_` blob to enumerate questions, types, and required flags.
3. Issues non‑following `GET`s to `/viewanalytics` and `/viewscore` and reads the
   status / redirect to determine exposure.
4. Runs each question title through the bilingual PII classifier.
5. Scores findings and prints / exports the report.

It never POSTs, never authenticates, and never touches response data.

## Limitations

- It cannot see the **sharing settings of the linked Google Sheet** (no external
  signal exists) — hence the standing reminder to check it manually.
- Classification is heuristic; review the question list it prints.
- Google can change the `FB_PUBLIC_LOAD_DATA_` shape; parsing is defensive and
  degrades to "couldn't parse" rather than crashing.

## Development

```bash
python3 tests/test_classify.py    # offline unit tests, no network
```

## License

MIT © 2026 — see [LICENSE](LICENSE).
