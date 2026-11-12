"""End to end tests: a real headless Chromium scans the local demo site."""

import pytest

from cookie_auditor.scanner import Scanner
from demo_site import server

PORT = 8799


@pytest.fixture(scope="module")
def scanner():
    try:
        s = Scanner(wait=0.5, timeout=15)
        s.__enter__()
    except Exception as exc:  # Chromium not installed
        pytest.skip(f"Chromium unavailable: {exc}")
    yield s
    s.__exit__(None, None, None)


@pytest.fixture(scope="module")
def demo():
    srv = server.start(PORT)
    yield f"http://127.0.0.1:{PORT}"
    srv.shutdown()


def test_bad_page_fails(scanner, demo):
    r = scanner.scan(demo + "/bad")
    assert r.verdict == "FAIL"
    names = {c.name for c in r.cookies}
    assert {"_ga", "_gid", "_fbp", "_gcl_au", "PHPSESSID"} <= names
    # Five tracker cookies (_ga, _ga_ABC123XYZ, _gid, _fbp, _gcl_au); PHPSESSID is essential.
    assert r.summary["violations"] == 5
    assert "Google Analytics" in r.summary["violating_vendors"]
    assert r.consent_banner_detected


def test_cookie_source_is_recorded(scanner, demo):
    r = scanner.scan(demo + "/bad")
    by_name = {c.name: c for c in r.cookies}
    assert by_name["PHPSESSID"].source == "http"
    assert by_name["PHPSESSID"].http_only
    assert by_name["_ga"].source == "javascript"


def test_good_page_passes(scanner, demo):
    r = scanner.scan(demo + "/good")
    assert r.verdict == "PASS"
    assert [c.name for c in r.cookies] == ["PHPSESSID"]


def test_mixed_page_needs_review(scanner, demo):
    r = scanner.scan(demo + "/mixed")
    assert r.verdict == "REVIEW"
    assert r.summary["violations"] == 0
    assert r.summary["review"] == 1


def test_unreachable_host_reports_error(scanner):
    r = scanner.scan("http://127.0.0.1:1/")
    assert r.verdict == "ERROR"
    assert r.error
