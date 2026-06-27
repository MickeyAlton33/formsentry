"""Offline unit tests for FormSentry's classifier and parser (no network)."""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import formsentry as fs  # noqa: E402


def test_minor_detection_hebrew():
    assert "minor" in fs.classify_pii("שם הילד/ה")
    assert "minor" in fs.classify_pii("גיל הילד/ה")


def test_minor_detection_english():
    assert "minor" in fs.classify_pii("Child's name")
    assert "minor" in fs.classify_pii("Child's age")


def test_generic_age_is_dob_not_minor():
    # an applicant's age must NOT be flagged as minors' data
    assert "minor" not in fs.classify_pii("מה גילך?")
    assert "dob" in fs.classify_pii("מה גילך?")
    assert "minor" not in fs.classify_pii("What is your age?")
    assert "dob" in fs.classify_pii("Date of birth")


def test_child_age_still_minor():
    # but a child's age/name still is
    assert "minor" in fs.classify_pii("גיל הילד/ה")
    assert "minor" in fs.classify_pii("Child's age")


def test_national_id():
    assert "national_id" in fs.classify_pii("תעודת זהות")
    assert "national_id" in fs.classify_pii('מספר ת"ז')
    assert "national_id" in fs.classify_pii("Passport number")


def test_health():
    assert "health" in fs.classify_pii("רגישויות / אלרגיות")
    assert "health" in fs.classify_pii("Any medical conditions?")


def test_payment_is_critical():
    cats = fs.classify_pii("מספר כרטיס אשראי")
    assert "payment_card" in cats
    assert fs.pii_severity("payment_card") == "critical"


def test_email_address_not_physical_address():
    # "כתובת המייל" must classify as email, NOT physical address
    cats = fs.classify_pii("מה כתובת המייל שלך?")
    assert "email" in cats
    assert "address" not in cats


def test_physical_address_still_detected():
    assert "address" in fs.classify_pii("מה הכתובת שלך?")
    assert "address" in fs.classify_pii("Home address")


def test_phone():
    assert "phone" in fs.classify_pii("מספר טלפון נייד")
    assert "phone" in fs.classify_pii("Mobile phone")


def test_resolve_bare_id():
    fid, url = fs.resolve_target("1FAIpQLScABC_def")
    assert fid == "1FAIpQLScABC_def"
    assert url.endswith("/viewform")


def test_resolve_full_url():
    fid, url = fs.resolve_target(
        "https://docs.google.com/forms/d/e/ABC123/viewform?usp=send_form")
    assert fid == "ABC123"


def test_severity_ordering():
    assert fs.sev_rank("critical") > fs.sev_rank("high") > fs.sev_rank("medium")
    assert fs.sev_rank("medium") > fs.sev_rank("low") > fs.sev_rank("info")


def test_parse_public_data_minimal():
    body = 'var FB_PUBLIC_LOAD_DATA_ = [null,["My description",' \
           '[[123,"שם הילד/ה",null,0,[[456,null,1]]]]],"docpath","My Title"];</script>'
    data = fs.parse_public_data(body)
    assert data is not None
    title, desc, questions = fs.extract_questions(data)
    assert title == "My Title"
    assert desc == "My description"
    assert len(questions) == 1
    assert questions[0].required is True
    assert "minor" in questions[0].pii


def test_extract_form_links_variants():
    body = '''
      <a href="https://forms.gle/AbC123">x</a>
      "url":"https:\\/\\/docs.google.com\\/forms\\/d\\/e\\/IDENT456\\/viewform"
      <iframe src="https://docs.google.com/forms/d/e/IDENT456/viewform?embedded=true">
      legacy https://goo.gl/forms/Zz9
    '''
    links = fs.extract_form_links(body)
    assert any("forms.gle/AbC123" in u for u in links)
    assert any("IDENT456" in u for u in links)
    assert any("goo.gl/forms/Zz9" in u for u in links)


def test_extract_form_links_dedup():
    body = ("https://forms.gle/SAME https://forms.gle/SAME "
            "https://forms.gle/SAME")
    assert len(fs.extract_form_links(body)) == 1


def test_extract_internal_links_same_host_only():
    body = ('<a href="/about">a</a><a href="https://other.com/x">b</a>'
            '<a href="https://site.com/contact">c</a>'
            '<a href="/logo.png">img</a>')
    links = fs.extract_internal_links(body, "https://site.com/", "site.com")
    assert "https://site.com/about" in links
    assert "https://site.com/contact" in links
    assert all("other.com" not in u for u in links)   # off-host excluded
    assert all(not u.endswith(".png") for u in links)  # assets excluded


def test_compute_summary():
    r1 = fs.Report(target="a", form_id="a", title="A", description=None,
                   accessible=True)
    r1.findings.append(fs.Finding("x", "high", "t", "d"))
    r1.questions.append(fs.Question("child name", "short_answer", True, ["minor"]))
    r2 = fs.Report(target="b", form_id="b", title="B", description=None,
                   accessible=True)
    r2.findings.append(fs.Finding("y", "medium", "t", "d"))
    r2.questions.append(fs.Question("phone", "short_answer", True, ["phone"]))
    s = fs.compute_summary([r1, r2])
    assert s["forms_assessed"] == 2
    assert s["worst_risk"] == "high"
    assert s["by_risk"]["high"] == 1 and s["by_risk"]["medium"] == 1
    assert s["pii_categories"]["minor"] == 1
    assert len(s["flagged"]) == 2


def test_build_dorks():
    dorks = fs.build_dorks("swimming", site="example.org")
    queries = [q for q, _ in dorks]
    assert any("site:docs.google.com/forms swimming" == q for q in queries)
    assert any("inurl:forms.gle swimming" == q for q in queries)
    assert any("site:example.org" in q for q in queries)
    # each query renders to all three engines
    for _q, urls in dorks:
        assert set(urls) == {"google", "bing", "duckduckgo"}
        assert all(v.startswith("https://") for v in urls.values())


def test_build_dorks_no_site():
    dorks = fs.build_dorks("gym membership")
    assert all("site:example" not in q for q, _ in dorks)
    assert len(dorks) >= 2


def test_decode_search_redirects_ddg():
    body = '<a href="/l/?uddg=https%3A%2F%2Fforms.gle%2FAbc123&rut=x">r</a>'
    decoded = fs._decode_search_redirects(body)
    assert "https://forms.gle/Abc123" in decoded


def test_decode_then_extract():
    import base64 as _b64
    target = "https://docs.google.com/forms/d/e/ZZZ999/viewform"
    enc = _b64.urlsafe_b64encode(target.encode()).decode().rstrip("=")
    body = f'<a href="https://www.bing.com/ck/a?x&u=a1{enc}&y">hit</a>'
    decoded = fs._decode_search_redirects(body)
    links = fs.extract_form_links(decoded)
    assert any("ZZZ999" in u for u in links)


def test_parse_selection():
    assert fs._parse_selection("", 4) == [0, 1, 2, 3]
    assert fs._parse_selection("all", 4) == [0, 1, 2, 3]
    assert fs._parse_selection("1,3", 4) == [0, 2]
    assert fs._parse_selection("1-3", 4) == [0, 1, 2]
    assert fs._parse_selection("2 4", 4) == [1, 3]
    assert fs._parse_selection("9", 4) == []          # out of range dropped


def test_extract_result_urls_filters_engines():
    body = ('<a href="https://activitymessenger.com/blog/x">r</a>'
            '<a href="https://www.mojeek.com/about">nav</a>'
            '<a href="https://facebook.com/share">soc</a>'
            '<a href="https://club.example.org/register">good</a>'
            '<a href="https://cdn.example.org/logo.png">img</a>')
    urls = fs._extract_result_urls(body)
    assert "https://activitymessenger.com/blog/x" in urls
    assert "https://club.example.org/register" in urls
    assert all("mojeek.com" not in u for u in urls)
    assert all("facebook.com" not in u for u in urls)
    assert all(not u.endswith(".png") for u in urls)


if __name__ == "__main__":
    import traceback
    failed = 0
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            try:
                fn()
                print(f"PASS {name}")
            except Exception:
                failed += 1
                print(f"FAIL {name}")
                traceback.print_exc()
    sys.exit(1 if failed else 0)
