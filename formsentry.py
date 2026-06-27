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
import base64
import dataclasses
import json
import re
import sys
import urllib.error
import urllib.parse
import urllib.request
from collections import Counter
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

__version__ = "1.3.0"

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
# Discovery — find Google Form links inside arbitrary web pages
# --------------------------------------------------------------------------- #

# Matches forms.gle, goo.gl/forms (legacy), and docs.google.com/forms links.
# /forms/d/e/<id> is listed before /forms/d/<id> so the published id wins.
_RE_FORM_LINK = re.compile(
    r"https?://(?:"
    r"forms\.gle/[A-Za-z0-9_-]+"
    r"|goo\.gl/forms/[A-Za-z0-9_-]+"
    r"|docs\.google\.com/forms/d/e/[A-Za-z0-9_-]+(?:/viewform)?"
    r"|docs\.google\.com/forms/d/[A-Za-z0-9_-]+(?:/viewform)?"
    r")",
    re.IGNORECASE)

_RE_HREF = re.compile(r"""href\s*=\s*["']([^"'#]+)""", re.IGNORECASE)

_SKIP_EXT = (".jpg", ".jpeg", ".png", ".gif", ".svg", ".ico", ".webp", ".css",
             ".js", ".pdf", ".zip", ".rar", ".gz", ".mp4", ".mp3", ".woff",
             ".woff2", ".ttf", ".eot")


def _deescape(body: str) -> str:
    """Undo the JSON/HTML escaping that hides URLs in link-hub pages."""
    return (body.replace("\\/", "/")
                .replace("&amp;", "&")
                .replace("\\u003d", "=")
                .replace("\\u0026", "&"))


def extract_form_links(body: str) -> List[str]:
    """All Google Form URLs in a page, de-duplicated, order preserved."""
    seen: set = set()
    out: List[str] = []
    for m in _RE_FORM_LINK.finditer(_deescape(body)):
        u = m.group(0)
        if u not in seen:
            seen.add(u)
            out.append(u)
    return out


def extract_internal_links(body: str, base_url: str, host: str) -> List[str]:
    """Same-host http(s) anchor links worth crawling further."""
    out: List[str] = []
    seen: set = set()
    for m in _RE_HREF.finditer(body):
        href = m.group(1).strip()
        if not href or href.lower().startswith(("mailto:", "tel:", "javascript:")):
            continue
        nxt = urllib.parse.urljoin(base_url, href)
        p = urllib.parse.urlparse(nxt)
        if p.scheme not in ("http", "https"):
            continue
        if p.netloc != host:
            continue
        if nxt.lower().split("?")[0].endswith(_SKIP_EXT):
            continue
        nxt = nxt.split("#")[0]
        if nxt not in seen:
            seen.add(nxt)
            out.append(nxt)
    return out


@dataclass
class Discovered:
    form_url: str          # canonical viewform url
    form_id: Optional[str]
    source: str            # page it was found on

    def as_dict(self) -> dict:
        return dataclasses.asdict(self)


def discover(seeds: List[str], depth: int = 0, max_pages: int = 40,
             same_host: bool = True, on_log=None) -> Tuple[List[Discovered], int]:
    """
    Crawl seed pages for Google Form links. With depth>0, follow same-host
    links up to `depth` hops (bounded by max_pages). Returns (forms, pages).
    """
    def log(msg):
        if on_log:
            on_log(msg)

    queue: List[Tuple[str, int]] = [(s if "://" in s else "https://" + s, 0)
                                    for s in seeds]
    visited: set = set()
    found: List[Discovered] = []
    seen_keys: set = set()
    pages = 0

    while queue and pages < max_pages:
        url, d = queue.pop(0)
        if url in visited:
            continue
        visited.add(url)
        try:
            _status, final_url, body = http_get(url)
        except RuntimeError as e:
            log(f"  · skip {url} ({e})")
            continue
        pages += 1

        for raw in extract_form_links(body):
            fid, viewform = resolve_target(raw)
            key = fid or raw
            if key in seen_keys:
                continue
            seen_keys.add(key)
            found.append(Discovered(form_url=viewform, form_id=fid, source=url))
            log(f"  + form: {viewform}")

        if d < depth:
            host = urllib.parse.urlparse(final_url or url).netloc
            for nxt in extract_internal_links(body, final_url or url, host):
                if nxt not in visited:
                    queue.append((nxt, d + 1))

    return found, pages


# --------------------------------------------------------------------------- #
# OSINT — find Google Forms by keyword via search dorks
# --------------------------------------------------------------------------- #

# Search front-ends used to *render* a dork as a clickable query URL.
DORK_ENGINES = {
    "google": "https://www.google.com/search?q=",
    "bing": "https://www.bing.com/search?q=",
    "duckduckgo": "https://duckduckgo.com/?q=",
}


def build_dorks(keywords: str, site: Optional[str] = None) -> List[Tuple[str, Dict[str, str]]]:
    """
    Turn keywords (and optional site/org) into a set of Google-Forms dorks.
    Returns [(query, {engine: url, ...}), ...].
    """
    kw = keywords.strip()
    queries: List[str] = [
        f"site:docs.google.com/forms {kw}".strip(),
        f"inurl:forms.gle {kw}".strip(),
        f'{kw} (forms.gle OR "docs.google.com/forms")'.strip(),
    ]
    if site:
        queries.append(f"site:{site} (forms.gle OR docs.google.com/forms)")
        queries.append(f'"{kw}" site:{site}'.strip())

    out: List[Tuple[str, Dict[str, str]]] = []
    seen: set = set()
    for q in queries:
        if q in seen:
            continue
        seen.add(q)
        urls = {eng: base + urllib.parse.quote(q)
                for eng, base in DORK_ENGINES.items()}
        out.append((q, urls))
    return out


def _http_get_safe(url: str) -> str:
    try:
        _s, _u, body = http_get(url)
        return body
    except RuntimeError:
        return ""


def _decode_search_redirects(body: str) -> str:
    """Pull real URLs out of DuckDuckGo (uddg=) and Bing (ck/a u=a1) wrappers."""
    urls: List[str] = []
    for m in re.finditer(r"uddg=([^&\"']+)", body):
        urls.append(urllib.parse.unquote(m.group(1)))
    for m in re.finditer(r"u=a1([A-Za-z0-9_-]+)", body):
        b = m.group(1)
        b += "=" * ((4 - len(b) % 4) % 4)
        try:
            urls.append(base64.urlsafe_b64decode(b).decode("utf-8", "replace"))
        except Exception:
            pass
    return "\n".join(urls)


# Key-free search front-ends, tried in order. No API keys, ever.
# Mojeek returns clean, direct result URLs and does not captcha-gate scrapers,
# which makes it the workhorse; DDG-lite/Bing are best-effort fallbacks.
_SEARCH_BACKENDS = [
    ("mojeek", "https://www.mojeek.com/search?q="),
    ("ddg-lite", "https://lite.duckduckgo.com/lite/?q="),
    ("bing", "https://www.bing.com/search?count=30&q="),
]

# Hosts that are search-engine chrome / social noise, not real results.
_ENGINE_HOSTS = ("mojeek.com", "duckduckgo.com", "bing.com", "microsoft.com",
                 "google.com", "brave.com", "searx", "yahoo.com", "msn.com",
                 "facebook.com", "twitter.com", "x.com", "instagram.com",
                 "youtube.com", "linkedin.com", "pinterest.com", "wikipedia.org")


def _scrape_search(query: str) -> str:
    """Best-effort key-free search. Returns concatenated result HTML."""
    parts = []
    for _name, base in _SEARCH_BACKENDS:
        body = _http_get_safe(base + urllib.parse.quote(query))
        if body and "anomaly" not in body.lower():
            parts.append(body)
    return "\n".join(parts)


def _extract_result_urls(body: str) -> List[str]:
    """Organic result links from a search page (direct hrefs + DDG redirects)."""
    cand: List[str] = []
    for m in _RE_HREF.finditer(body):
        cand.append(m.group(1))
    cand.extend(_decode_search_redirects(body).splitlines())

    out: List[str] = []
    seen: set = set()
    for u in cand:
        u = u.strip()
        if not u.startswith("http"):
            continue
        host = urllib.parse.urlparse(u).netloc.lower()
        if any(h in host for h in _ENGINE_HOSTS):
            continue
        if u.lower().split("?")[0].endswith(_SKIP_EXT):
            continue
        u = u.split("#")[0]
        if u not in seen:
            seen.add(u)
            out.append(u)
    return out


def osint_search(keywords: str, site: Optional[str] = None, max_results: int = 40,
                 deep: bool = True, max_pages: int = 15,
                 on_log=None) -> List[Discovered]:
    """
    Hunt Google Forms by keyword — NO API KEYS. Two stages:
      1. key-free web search (Mojeek + fallbacks) for direct form links, and
      2. crawl the top organic result pages and extract forms embedded in them.
    """
    def log(msg):
        if on_log:
            on_log(msg)

    # Mojeek (the reliable backend) ignores site:/inurl: operators, so feed it
    # plain keywords plus a forms hint; keep an operator query for engines that
    # do support dorks.
    queries = [f"{keywords} google form".strip()]
    if site:
        queries.append(f"{keywords} {site}".strip())
    queries.append(f"site:docs.google.com/forms {keywords}".strip())

    found: List[Discovered] = []
    seen: set = set()
    result_pages: List[str] = []

    for q in queries:
        log(f"  · query: {q}")
        blob = _scrape_search(q)
        if not blob:
            continue
        haystack = blob + "\n" + _decode_search_redirects(blob)
        # Stage 1: direct form links sitting in the SERP itself.
        for raw in extract_form_links(haystack):
            fid, viewform = resolve_target(raw)
            k = fid or raw
            if k not in seen:
                seen.add(k)
                found.append(Discovered(viewform, fid, f"osint:{q}"))
                log(f"  + form (direct): {viewform}")
        # Collect organic result pages to crawl in stage 2.
        for u in _extract_result_urls(haystack):
            if u not in result_pages:
                result_pages.append(u)
        if len(found) >= max_results:
            return found[:max_results]

    # Stage 2: crawl the harvested result pages for embedded forms.
    if deep and result_pages:
        pages = result_pages[:max_pages]
        log(f"  · crawling {len(pages)} result page(s) for embedded forms ...")
        crawled, _n = discover(pages, depth=0, max_pages=max_pages, on_log=on_log)
        for d in crawled:
            k = d.form_id or d.form_url
            if k not in seen:
                seen.add(k)
                found.append(d)

    return found[:max_results]


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
# Aggregate summary (mass analysis)
# --------------------------------------------------------------------------- #

def compute_summary(reports: List[Report]) -> dict:
    by_risk = Counter(r.risk for r in reports)
    pii = Counter()
    for r in reports:
        cats = set()
        for q in r.questions:
            cats.update(q.pii)
        for c in cats:
            pii[c] += 1
    worst = max((r.risk for r in reports), key=sev_rank, default="info")
    flagged = [
        {"target": r.target, "title": r.title, "risk": r.risk}
        for r in sorted(reports, key=lambda x: -sev_rank(x.risk))
        if sev_rank(r.risk) >= sev_rank("medium")
    ]
    return {
        "forms_assessed": len(reports),
        "worst_risk": worst,
        "by_risk": {k: by_risk.get(k, 0) for k in reversed(SEVERITY_ORDER)
                    if by_risk.get(k, 0)},
        "pii_categories": dict(pii.most_common()),
        "flagged": flagged,
        "errored": [r.target for r in reports if r.errors and not r.accessible],
    }


def render_summary_text(s: dict) -> str:
    out = [_c("1", "\n╔══ MASS ANALYSIS SUMMARY ════════════════════════════")]
    out.append(f"  Forms assessed : {s['forms_assessed']}")
    out.append("  Worst risk     : " +
               _c(SEV_COLOR.get(s['worst_risk'], "0"), s['worst_risk'].upper()))
    if s["by_risk"]:
        parts = []
        for k, n in s["by_risk"].items():
            parts.append(_c(SEV_COLOR.get(k, "0"), f"{n} {k}"))
        out.append("  By risk        : " + "  ".join(parts))
    if s["pii_categories"]:
        out.append("  PII seen       : " + ", ".join(
            f"{PII_LABELS.get(c, c)}×{n}" for c, n in s["pii_categories"].items()))
    if s["flagged"]:
        out.append(_c("1", "\n  Needs attention (medium+):"))
        for f in s["flagged"]:
            badge = _c(SEV_COLOR.get(f["risk"], "0"), f"[{SEV_BADGE[f['risk']]}]")
            out.append(f"    {badge} {f['title'] or f['target']}")
    if s["errored"]:
        out.append(_c("2", f"\n  Unreadable: {len(s['errored'])} target(s)"))
    out.append(_c("1", "╚═════════════════════════════════════════════════════"))
    return "\n".join(out)


def render_summary_md(s: dict) -> str:
    out = ["# FormSentry — mass analysis summary\n"]
    out.append(f"- **Forms assessed:** {s['forms_assessed']}")
    out.append(f"- **Worst risk:** **{s['worst_risk'].upper()}**")
    if s["by_risk"]:
        out.append("- **By risk:** " +
                   ", ".join(f"{n} {k}" for k, n in s["by_risk"].items()))
    if s["pii_categories"]:
        out.append("- **PII categories seen (forms):** " + ", ".join(
            f"{PII_LABELS.get(c, c)} ({n})" for c, n in s["pii_categories"].items()))
    out.append("")
    if s["flagged"]:
        out.append("## Needs attention (medium+)\n")
        out.append("| Risk | Form |")
        out.append("|---|---|")
        for f in s["flagged"]:
            out.append(f"| **{f['risk'].upper()}** | {f['title'] or f['target']} |")
        out.append("")
    return "\n".join(out)


# --------------------------------------------------------------------------- #
# Examples & dork rendering
# --------------------------------------------------------------------------- #

EXAMPLES = r"""
EXAMPLES — full command chains

  Assess one form
    formsentry.py https://forms.gle/XXXXXXXX

  Assess several, fail CI if any is HIGH+
    formsentry.py https://forms.gle/AAA https://forms.gle/BBB --fail-on high

  Auto-discover forms on a page and assess them all
    formsentry.py --discover https://linktr.ee/some.org

  Crawl a whole site one hop deep, write a Markdown audit
    formsentry.py --discover --depth 1 --max-pages 80 https://example.org --md -o audit.md

  Just list the forms found on a page (no assessment)
    formsentry.py --discover --list-only https://example.org

  OSINT: hunt forms by keyword, then assess what's found
    formsentry.py --search "swimming registration tel aviv"

  OSINT scoped to an organization's domain, JSON out
    formsentry.py --search "membership" --site example.org --json -o hits.json

  OSINT: print ready-to-run search dorks (always works, zero network)
    formsentry.py --search "country club" --dorks-only

  Feed dork results back in for assessment
    formsentry.py --discover -i found_pages.txt --md -o report.md
"""


def render_dorks(keywords: str, site: Optional[str], color: bool = True) -> str:
    out = [_c("1", f"\nGoogle-Forms OSINT dorks for: “{keywords}”"
                   + (f"  (site: {site})" if site else ""))]
    for q, urls in build_dorks(keywords, site):
        out.append(_c("36", f"\n  {q}"))
        for eng in ("google", "bing", "duckduckgo"):
            out.append(f"    {eng:<11} {urls[eng]}")
    out.append(_c("2", "\n  → Open these, save the pages that contain forms to "
                       "pages.txt, then assess:"))
    out.append(_c("2", "      formsentry.py --discover -i pages.txt"))
    return "\n".join(out)


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="formsentry",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description="Security & privacy assessment for Google Forms.",
        epilog=EXAMPLES + "\nOnly assess forms you own or are authorized to assess.")
    p.add_argument("targets", nargs="*",
                   help="Google Form URL(s)/short link(s)/id(s) — or, with "
                        "--discover, web page(s) to scan for forms.")
    p.add_argument("-s", "--search", metavar="KEYWORDS",
                   help="OSINT: hunt Google Forms by keyword via search dorks, "
                        "then assess what's found.")
    p.add_argument("--site", metavar="DOMAIN",
                   help="Scope --search dorks to an organization/domain.")
    p.add_argument("--dorks-only", action="store_true",
                   help="With --search: just print ready-to-run dork URLs "
                        "(no network), then exit.")
    p.add_argument("--examples", action="store_true",
                   help="Print full command-chain examples and exit.")
    p.add_argument("-i", "--input", metavar="FILE",
                   help="Read targets from FILE (one per line).")
    p.add_argument("-d", "--discover", action="store_true",
                   help="Treat targets as web pages and auto-find Google Forms "
                        "in them (Linktree, sites, link hubs, ...).")
    p.add_argument("--depth", type=int, default=0, metavar="N",
                   help="With --discover, follow same-host links N hops deep "
                        "(default 0 = only the given page).")
    p.add_argument("--max-pages", type=int, default=40, metavar="N",
                   help="Safety cap on pages crawled during discovery (default 40).")
    p.add_argument("--list-only", action="store_true",
                   help="With --discover, only list found form URLs; do not assess.")
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

    if args.examples:
        print(EXAMPLES)
        return 0

    def log(msg):
        if not args.json:
            print(msg, file=sys.stderr)

    discovered: List[Discovered] = []

    # ---- OSINT search phase --------------------------------------------- #
    if args.search:
        if args.dorks_only:
            print(render_dorks(args.search, args.site))
            return 0
        log(f"[osint] hunting forms for: {args.search!r}"
            + (f" (site:{args.site})" if args.site else "") + " ...")
        discovered = osint_search(args.search, site=args.site, on_log=log)
        log(f"[osint] found {len(discovered)} form(s) (key-free search).")
        if not discovered:
            log("[osint] live search surfaced no forms this time "
                "(engine coverage varies).")
            log("[osint] run these dorks in your browser, then feed the "
                "result pages back with: --discover -i pages.txt")
            print(render_dorks(args.search, args.site))
            return 0

    targets = gather_targets(args)

    if not targets and not discovered:
        build_parser().print_help()
        return 2

    # ---- Discovery phase ------------------------------------------------ #
    if args.discover and targets:
        log(f"[discover] scanning {len(targets)} page(s), depth={args.depth} ...")
        found, pages = discover(targets, depth=args.depth,
                                max_pages=args.max_pages, on_log=log)
        discovered = discovered + found
        log(f"[discover] crawled {pages} page(s); found {len(found)} form(s).")

    # Forms gathered by --discover/--search become the assessment targets.
    if args.discover or args.search:
        if args.list_only:
            if args.json:
                print(json.dumps([d.as_dict() for d in discovered], indent=2,
                                 ensure_ascii=False))
            else:
                for d in discovered:
                    print(d.form_url)
            return 0
        targets = [d.form_url for d in discovered]
        if not targets:
            print("No Google Forms found.", file=sys.stderr)
            return 0

    # ---- Assessment phase ---------------------------------------------- #
    reports: List[Report] = []
    for t in targets:
        try:
            reports.append(assess(t))
        except Exception as e:  # never let one bad target kill the run
            r = Report(target=t, form_id=None, title=None, description=None,
                       accessible=False)
            r.errors.append(f"unexpected error: {e}")
            reports.append(r)

    summary = compute_summary(reports) if len(reports) > 1 else None

    if args.json:
        payload = {"reports": [r.as_dict() for r in reports]}
        if summary:
            payload["summary"] = summary
        if discovered:
            payload["discovered"] = [d.as_dict() for d in discovered]
        text = json.dumps(payload, indent=2, ensure_ascii=False)
    elif args.md:
        text = ((render_summary_md(summary) + "\n") if summary else "") \
            + render_markdown(reports)
    else:
        body = "\n".join(render_text(r) for r in reports)
        text = body + ("\n" + render_summary_text(summary) if summary else "")
        text += _c("2",
                   "\n\nNext steps (full chains):"
                   "\n  org-wide hunt : formsentry.py --search \"<org name>\" "
                   "--site <domain>"
                   "\n  page discover : formsentry.py --discover --depth 1 <url>"
                   "\n  CI gate       : formsentry.py -i targets.txt --fail-on high"
                   "\n  all examples  : formsentry.py --examples")

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
