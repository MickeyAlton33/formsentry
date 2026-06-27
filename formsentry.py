#!/usr/bin/env python3
"""
FormSentry — Google Forms security & privacy assessment tool.

Point it at any Google Form (or a forms.gle short link) and it audits the
form's *externally observable* security posture, the same way a human pen
tester would, without ever submitting data:

  * Response-summary exposure   (the classic "anyone with the link can read
                                 everyone's answers" misconfiguration)
  * Score / quiz-grade leakage  (viewscore endpoint left public)
  * Sign-in / org restrictions  (login wall, org-only forms)
  * File-upload questions        (files land in the owner's Drive)
  * Automatic PII classification of every question — English *and* Hebrew —
    flagging national-ID, minors', health, and payment data specifically.

It is read-only. It performs GET/HEAD requests against public Google
endpoints and never POSTs a response.

    USE RESPONSIBLY. Only assess forms you own or are explicitly
    authorized to assess.

Zero third-party dependencies — standard library only. Python 3.8+.
"""
from __future__ import annotations

import argparse
import dataclasses
import json
import re
import sys
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

__version__ = "1.0.0"

USER_AGENT = f"FormSentry/{__version__} (+https://github.com/MickeyAlton33/formsentry)"
TIMEOUT = 20

# --------------------------------------------------------------------------- #
# Severity model
# --------------------------------------------------------------------------- #

SEVERITY_ORDER = ["info", "low", "medium", "high", "critical"]


def sev_rank(sev: str) -> int:
    return SEVERITY_ORDER.index(sev) if sev in SEVERITY_ORDER else 0


@dataclass
class Finding:
    id: str
    severity: str          # info | low | medium | high | critical
    title: str
    detail: str
    recommendation: str = ""

    def as_dict(self) -> dict:
        return dataclasses.asdict(self)


@dataclass
class Question:
    title: str
    type: str
    required: bool
    pii: List[str] = field(default_factory=list)   # matched PII categories

    def as_dict(self) -> dict:
        return dataclasses.asdict(self)


@dataclass
class Report:
    target: str
    form_id: Optional[str]
    title: Optional[str]
    description: Optional[str]
    accessible: bool
    questions: List[Question] = field(default_factory=list)
    findings: List[Finding] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)

    @property
    def risk(self) -> str:
        if not self.findings:
            return "info"
        return max(self.findings, key=lambda f: sev_rank(f.severity)).severity

    def as_dict(self) -> dict:
        d = dataclasses.asdict(self)
        d["risk"] = self.risk
        return d


# --------------------------------------------------------------------------- #
# Google Forms question type map (reverse-engineered, stable for years)
# --------------------------------------------------------------------------- #

QTYPE = {
    0: "short_answer",
    1: "paragraph",
    2: "multiple_choice",
    3: "dropdown",
    4: "checkboxes",
    5: "linear_scale",
    6: "title",
    7: "grid",
    8: "section",
    9: "date",
    10: "time",
    11: "image",
    12: "video",
    13: "file_upload",
}

# --------------------------------------------------------------------------- #
# PII classification — keyword/regex per category, with severity.
# Hebrew and English. Ordered most-sensitive first.
# --------------------------------------------------------------------------- #

PII_RULES: List[Tuple[str, str, str]] = [
    # category, severity, regex (case-insensitive, unicode)
    ("payment_card", "critical",
     r"credit\s*card|card\s*number|cvv|כרטיס\s*אשראי|מספר\s*כרטיס|אשראי"),
    ("national_id", "high",
     r"\b(ssn|social security|national id|passport)\b|תעודת\s*זהות|תעודת\s*זה|ת\.?\s*ז\.?|דרכון|ת\"ז"),
    ("health", "high",
     r"health|medical|disease|allerg|disab|diagnos|medication|בריאות|רפואי|מחלה|אלרגי|אלרג|נכות|תרופ|רגישות"),
    ("minor", "high",
     r"child|children|kid|minor|son|daughter|pupil|date of birth|birthdate|\bage\b|ילד|ילדה|ילדי|קטין|תאריך\s*לידה|גיל\b|בן/בת\s*כמה|תלמיד"),
    ("address", "medium",
     r"(?<!e-mail\s)(?<!email\s)home\s*address|street\b|zip\s*code|postal"
     r"|כתובת(?!\s*ה?(?:מייל|אימייל|דוא))|רחוב|מיקוד|עיר\b|יישוב"),
    ("phone", "medium",
     r"phone|mobile|cell|tel\b|whatsapp|טלפון|נייד|פלאפון|וואטסאפ|וטסאפ|מס'?\s*טלפון"),
    ("dob", "medium",
     r"date of birth|birthdate|d\.?o\.?b\.?|תאריך\s*לידה"),
    ("financial", "medium",
     r"income|salary|bank\s*account|iban|הכנסה|משכורת|חשבון\s*בנק|בנק\b"),
    ("government", "medium",
     r"driver'?s?\s*licen|license\s*plate|רישיון\s*נהיגה|לוחית\s*רישוי|רכב\b"),
    ("email", "low",
     r"e-?mail|דוא\"ל|דואר\s*אלקטרוני|מייל|אימייל|כתובת\s*מייל"),
    ("full_name", "low",
     r"full name|first name|last name|surname|\bname\b|שם\s*מלא|שם\s*פרטי|שם\s*משפחה|מה\s*שמך|שמך"),
]

PII_COMPILED = [(cat, sev, re.compile(rx, re.IGNORECASE | re.UNICODE))
                for cat, sev, rx in PII_RULES]

PII_LABELS = {
    "payment_card": "payment card data",
    "national_id": "national ID / passport",
    "health": "health / medical data",
    "minor": "minors' / children's data",
    "address": "physical address",
    "phone": "phone number",
    "dob": "date of birth",
    "financial": "financial data",
    "government": "government identifiers",
    "email": "email address",
    "full_name": "name",
}


def classify_pii(text: str) -> List[str]:
    hits: List[str] = []
    for cat, _sev, rx in PII_COMPILED:
        if rx.search(text or ""):
            hits.append(cat)
    return hits


def pii_severity(cat: str) -> str:
    for c, sev, _ in PII_RULES:
        if c == cat:
            return sev
    return "low"


# --------------------------------------------------------------------------- #
# HTTP helpers
# --------------------------------------------------------------------------- #

class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """Capture redirects instead of following them."""
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


_no_redirect_opener = urllib.request.build_opener(_NoRedirect)


def http_get(url: str) -> Tuple[int, str, str]:
    """GET following redirects. Returns (status, final_url, body)."""
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT) as resp:
            body = resp.read().decode("utf-8", "replace")
            return resp.status, resp.geturl(), body
    except urllib.error.HTTPError as e:
        body = ""
        try:
            body = e.read().decode("utf-8", "replace")
        except Exception:
            pass
        return e.code, getattr(e, "url", url), body
    except urllib.error.URLError as e:
        raise RuntimeError(f"network error: {e.reason}") from e


def http_status_noredirect(url: str) -> Tuple[int, Optional[str]]:
    """HEAD-ish GET that does NOT follow redirects. Returns (status, location)."""
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    try:
        resp = _no_redirect_opener.open(req, timeout=TIMEOUT)
        return resp.status, resp.headers.get("Location")
    except urllib.error.HTTPError as e:
        if e.code in (301, 302, 303, 307, 308):
            return e.code, e.headers.get("Location")
        return e.code, None
    except urllib.error.URLError as e:
        raise RuntimeError(f"network error: {e.reason}") from e


# --------------------------------------------------------------------------- #
# Target normalization
# --------------------------------------------------------------------------- #

_RE_FORM_ID = re.compile(r"/forms/d/e/([A-Za-z0-9_-]+)")
_RE_FORM_ID_EDIT = re.compile(r"/forms/d/([A-Za-z0-9_-]+)")


def resolve_target(target: str) -> Tuple[Optional[str], str]:
    """
    Normalize any of:
        forms.gle/XXXX
        https://docs.google.com/forms/d/e/<id>/viewform
        https://docs.google.com/forms/d/<id>/edit   (won't be readable)
        <id>
    to (form_id, viewform_url). form_id is None if it can't be determined.
    """
    t = target.strip()
    if not t.startswith("http") and "/" not in t and "." not in t:
        # bare id
        return t, f"https://docs.google.com/forms/d/e/{t}/viewform"

    if "://" not in t:
        t = "https://" + t

    # forms.gle short links must be resolved with a real request
    if "forms.gle" in t or "/forms/u/" in t:
        try:
            status, final_url, _ = http_get(t)
            t = final_url
        except RuntimeError:
            pass

    m = _RE_FORM_ID.search(t)
    if m:
        fid = m.group(1)
        return fid, f"https://docs.google.com/forms/d/e/{fid}/viewform"

    m = _RE_FORM_ID_EDIT.search(t)
    if m:
        # /forms/d/<id> is the editor id, not the published /e/ id — not usable
        return None, t

    return None, t


# --------------------------------------------------------------------------- #
# Parsing FB_PUBLIC_LOAD_DATA_
# --------------------------------------------------------------------------- #

_RE_PUBLIC_DATA = re.compile(
    r"FB_PUBLIC_LOAD_DATA_\s*=\s*(\[.*?\])\s*;", re.DOTALL)


def parse_public_data(body: str) -> Optional[list]:
    m = _RE_PUBLIC_DATA.search(body)
    if not m:
        return None
    raw = m.group(1)
    try:
        return json.loads(raw)
    except json.JSONDecodeError:
        return None


def extract_questions(data: list) -> Tuple[Optional[str], Optional[str], List[Question]]:
    """Pull title, description and the question list out of FB_PUBLIC_LOAD_DATA_."""
    title = None
    description = None
    questions: List[Question] = []
    try:
        # data[1][8] is often the document title; data[3] the form title.
        if len(data) > 3 and isinstance(data[3], str):
            title = data[3]
        section = data[1]
        if isinstance(section, list):
            if len(section) > 0 and isinstance(section[0], str):
                description = section[0]
            fields = section[1] if len(section) > 1 else []
            for f in fields or []:
                if not isinstance(f, list) or len(f) < 4:
                    continue
                q_title = f[1] if len(f) > 1 else ""
                q_type = QTYPE.get(f[3] if len(f) > 3 else -1, "unknown")
                required = False
                entries = f[4] if len(f) > 4 and isinstance(f[4], list) else []
                if entries and isinstance(entries[0], list) and len(entries[0]) > 2:
                    required = bool(entries[0][2])
                # skip layout-only items
                if q_type in ("title", "section", "image", "video"):
                    continue
                q = Question(title=q_title or "(untitled)", type=q_type,
                             required=required, pii=classify_pii(q_title or ""))
                questions.append(q)
    except (IndexError, TypeError):
        pass
    return title, description, questions


# --------------------------------------------------------------------------- #
# The assessment
# --------------------------------------------------------------------------- #

def assess(target: str) -> Report:
    form_id, viewform_url = resolve_target(target)
    rep = Report(target=target, form_id=form_id, title=None,
                 description=None, accessible=False)

    if not form_id:
        rep.errors.append(
            "Could not determine a published form id (the /forms/d/e/<id>/ "
            "value). If you pasted an editor URL (/forms/d/<id>/edit), use the "
            "public 'Send'/'forms.gle' link instead.")
        return rep

    # --- Fetch the form itself ------------------------------------------- #
    try:
        status, final_url, body = http_get(viewform_url)
    except RuntimeError as e:
        rep.errors.append(str(e))
        return rep

    login_wall = "accounts.google.com" in final_url or "ServiceLogin" in body
    if login_wall:
        rep.findings.append(Finding(
            id="signin-required",
            severity="info",
            title="Form requires Google sign-in to view",
            detail="The form redirects to a Google login wall, so responses are "
                   "tied to authenticated accounts. This is good for "
                   "accountability but means it is not anonymous.",
            recommendation="No action — sign-in is generally a privacy positive."))
        rep.accessible = False
    elif status == 200:
        rep.accessible = True
        data = parse_public_data(body)
        if data:
            title, desc, questions = extract_questions(data)
            rep.title, rep.description, rep.questions = title, desc, questions
        else:
            rep.errors.append("Form page loaded but question data could not be "
                              "parsed (Google may have changed its format).")
    else:
        rep.errors.append(f"Form returned HTTP {status} ({final_url}).")
        return rep

    base = f"https://docs.google.com/forms/d/e/{form_id}"

    # --- Response-summary exposure (the big one) ------------------------- #
    try:
        a_status, a_loc = http_status_noredirect(base + "/viewanalytics")
        loc = a_loc or ""
        if a_status == 200:
            rep.findings.append(Finding(
                id="public-response-summary",
                severity="critical",
                title="Response summary is PUBLIC",
                detail="The /viewanalytics endpoint returns HTTP 200 — 'See "
                       "summary charts and text responses' is enabled, so "
                       "anyone holding the form link can read every "
                       "respondent's submitted answers.",
                recommendation="In the form: Responses → (⋮) menu → turn OFF "
                               "'See summary charts and text responses'."))
        elif "analyticsrestricted" in loc or a_status in (302, 401, 403):
            rep.findings.append(Finding(
                id="response-summary-restricted",
                severity="info",
                title="Response summary is restricted",
                detail="The /viewanalytics endpoint is not public "
                       f"(HTTP {a_status} → {loc or 'restricted'}). Good.",
                recommendation=""))
    except RuntimeError as e:
        rep.errors.append(f"viewanalytics check failed: {e}")

    # --- Quiz score exposure -------------------------------------------- #
    try:
        s_status, _ = http_status_noredirect(base + "/viewscore")
        if s_status == 200:
            rep.findings.append(Finding(
                id="public-viewscore",
                severity="high",
                title="Quiz scores endpoint is public",
                detail="The /viewscore endpoint returns HTTP 200, which can "
                       "expose graded responses / answer keys without auth.",
                recommendation="Review quiz release settings; restrict score "
                               "visibility to respondents only."))
    except RuntimeError:
        pass

    # --- PII findings from questions ------------------------------------ #
    cats: Dict[str, List[str]] = {}
    for q in rep.questions:
        for c in q.pii:
            cats.setdefault(c, []).append(q.title)
    for cat, qtitles in cats.items():
        sev = pii_severity(cat)
        if sev in ("low",):
            continue  # name/email alone aren't worth a finding
        rep.findings.append(Finding(
            id=f"pii-{cat}",
            severity=sev,
            title=f"Collects {PII_LABELS.get(cat, cat)}",
            detail="Question(s): " + "; ".join(f'“{t}”' for t in qtitles[:5])
                   + ("" if len(qtitles) <= 5 else f" (+{len(qtitles)-5} more)"),
            recommendation="Confirm the linked responses Google Sheet is shared "
                           "'Restricted', set a data-retention/deletion routine, "
                           "and verify a lawful basis for collecting this data."))

    # --- File-upload questions ------------------------------------------ #
    uploads = [q.title for q in rep.questions if q.type == "file_upload"]
    if uploads:
        rep.findings.append(Finding(
            id="file-upload",
            severity="medium",
            title="Form accepts file uploads",
            detail="Upload question(s): " + "; ".join(f'“{t}”' for t in uploads)
                   + ". Uploaded files are stored in the form owner's Google "
                     "Drive and require respondents to sign in.",
            recommendation="Review Drive sharing on the destination folder; "
                           "uploads can include scanned IDs / sensitive docs."))

    # --- Always remind about the one thing we can't see ----------------- #
    if rep.accessible:
        rep.findings.append(Finding(
            id="check-linked-sheet",
            severity="low",
            title="Manually verify the linked responses Sheet",
            detail="FormSentry cannot see the sharing settings of the Google "
                   "Sheet that backs the responses — that is the most common "
                   "real-world leak path.",
            recommendation="Open the responses Sheet → Share → confirm it is "
                           "'Restricted' (not 'Anyone with the link')."))

    return rep


# --------------------------------------------------------------------------- #
# Rendering
# --------------------------------------------------------------------------- #

class C:
    """ANSI colors (disabled when not a tty / --no-color)."""
    enabled = True

    @classmethod
    def wrap(cls, code: str, s: str) -> str:
        if not cls.enabled:
            return s
        return f"\033[{code}m{s}\033[0m"


def _c(code, s):
    return C.wrap(code, s)


SEV_COLOR = {
    "critical": "1;37;41",
    "high": "1;31",
    "medium": "1;33",
    "low": "36",
    "info": "32",
}
SEV_BADGE = {
    "critical": "CRIT",
    "high": "HIGH",
    "medium": "MED ",
    "low": "LOW ",
    "info": "INFO",
}


def render_text(rep: Report) -> str:
    out: List[str] = []
    out.append(_c("1", f"\n━━ FormSentry report ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"))
    out.append(f"Target : {rep.target}")
    if rep.form_id:
        out.append(f"Form id: {rep.form_id}")
    if rep.title:
        out.append(f"Title  : {rep.title}")
    risk = rep.risk
    out.append("Risk   : " + _c(SEV_COLOR.get(risk, "0"),
                                 f"{risk.upper()}"))

    if rep.errors:
        out.append(_c("1;31", "\nErrors:"))
        for e in rep.errors:
            out.append(f"  ! {e}")

    if rep.questions:
        out.append(_c("1", f"\nQuestions ({len(rep.questions)}):"))
        for q in rep.questions:
            tags = ""
            if q.pii:
                tags = " " + _c("33", "[" + ",".join(q.pii) + "]")
            req = _c("31", "*") if q.required else " "
            out.append(f"  {req} ({q.type}) {q.title}{tags}")

    out.append(_c("1", f"\nFindings ({len(rep.findings)}):"))
    if not rep.findings:
        out.append("  (none)")
    for f in sorted(rep.findings, key=lambda x: -sev_rank(x.severity)):
        badge = _c(SEV_COLOR.get(f.severity, "0"), f"[{SEV_BADGE[f.severity]}]")
        out.append(f"  {badge} {f.title}")
        out.append(f"        {f.detail}")
        if f.recommendation:
            out.append(_c("2", f"        → {f.recommendation}"))
    out.append("")
    return "\n".join(out)


def render_markdown(reps: List[Report]) -> str:
    out: List[str] = ["# FormSentry report\n"]
    for rep in reps:
        out.append(f"## {rep.title or rep.target}\n")
        out.append(f"- **Target:** `{rep.target}`")
        if rep.form_id:
            out.append(f"- **Form id:** `{rep.form_id}`")
        out.append(f"- **Overall risk:** **{rep.risk.upper()}**\n")
        if rep.errors:
            out.append("### Errors")
            for e in rep.errors:
                out.append(f"- {e}")
            out.append("")
        if rep.questions:
            out.append("### Questions")
            out.append("| Required | Type | Question | PII |")
            out.append("|---|---|---|---|")
            for q in rep.questions:
                safe_title = q.title.replace("|", "\\|")
                req_mark = "✅" if q.required else ""
                out.append(f"| {req_mark} | {q.type} | {safe_title} | "
                           f"{', '.join(q.pii)} |")
            out.append("")
        out.append("### Findings")
        if not rep.findings:
            out.append("_None._\n")
        for f in sorted(rep.findings, key=lambda x: -sev_rank(x.severity)):
            out.append(f"#### `{f.severity.upper()}` — {f.title}")
            out.append(f"{f.detail}")
            if f.recommendation:
                out.append(f"\n> **Fix:** {f.recommendation}")
            out.append("")
    return "\n".join(out)


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="formsentry",
        description="Security & privacy assessment for Google Forms.",
        epilog="Only assess forms you own or are authorized to assess.")
    p.add_argument("targets", nargs="*",
                   help="Google Form URL(s), forms.gle short link(s), or form id(s).")
    p.add_argument("-i", "--input", metavar="FILE",
                   help="Read targets from FILE (one per line).")
    p.add_argument("--json", action="store_true", help="Emit JSON.")
    p.add_argument("--md", "--markdown", dest="md", action="store_true",
                   help="Emit Markdown.")
    p.add_argument("-o", "--output", metavar="FILE",
                   help="Write output to FILE instead of stdout.")
    p.add_argument("--no-color", action="store_true", help="Disable ANSI colors.")
    p.add_argument("--fail-on", choices=SEVERITY_ORDER, default=None,
                   help="Exit non-zero if any finding >= this severity "
                        "(useful in CI).")
    p.add_argument("-V", "--version", action="version",
                   version=f"FormSentry {__version__}")
    return p


def gather_targets(args) -> List[str]:
    targets = list(args.targets)
    if args.input:
        with open(args.input, "r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if line and not line.startswith("#"):
                    targets.append(line)
    return targets


def main(argv: Optional[List[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    C.enabled = sys.stdout.isatty() and not args.no_color and not args.json

    targets = gather_targets(args)
    if not targets:
        build_parser().print_help()
        return 2

    reports: List[Report] = []
    for t in targets:
        try:
            reports.append(assess(t))
        except Exception as e:  # never let one bad target kill the run
            r = Report(target=t, form_id=None, title=None, description=None,
                       accessible=False)
            r.errors.append(f"unexpected error: {e}")
            reports.append(r)

    if args.json:
        text = json.dumps([r.as_dict() for r in reports], indent=2,
                          ensure_ascii=False)
    elif args.md:
        text = render_markdown(reports)
    else:
        text = "\n".join(render_text(r) for r in reports)

    if args.output:
        with open(args.output, "w", encoding="utf-8") as fh:
            fh.write(text + "\n")
        print(f"Wrote {args.output}")
    else:
        print(text)

    # exit code
    if args.fail_on:
        threshold = sev_rank(args.fail_on)
        worst = max((sev_rank(r.risk) for r in reports), default=0)
        if worst >= threshold:
            return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
