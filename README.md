# FormSentry 🛡️

**Security & privacy assessment for Google Forms.**

Point FormSentry at any Google Form — or a `forms.gle` short link — and it audits
the form's *externally observable* security posture the way a pen tester would,
**without ever submitting a response**. It catches the misconfigurations that
actually leak data in the real world, and it classifies the personal data a form
collects (in **English *and* Hebrew**), flagging national‑ID, minors', health,
and payment data specifically.

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

```bash
# single form (URL, forms.gle short link, or raw form id all work)
python3 formsentry.py https://forms.gle/XXXXXXXX

# several at once
python3 formsentry.py https://forms.gle/AAA https://docs.google.com/forms/d/e/ID/viewform

# from a file (one target per line; '#' comments allowed)
python3 formsentry.py -i targets.txt

# machine‑readable
python3 formsentry.py https://forms.gle/XXXX --json
python3 formsentry.py https://forms.gle/XXXX --md -o report.md

# CI gate: exit non‑zero if anything is 'high' or worse
python3 formsentry.py -i targets.txt --fail-on high
```

### Output formats

- **default** — colored terminal report
- `--json` — structured JSON (array of reports), ideal for piping into `jq`
- `--md` — Markdown report with a questions table

### Exit codes

`0` clean / below threshold · `1` finding ≥ `--fail-on` · `2` no targets given.

## How it works

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
