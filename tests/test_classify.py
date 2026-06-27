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
