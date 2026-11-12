import pytest

from cookie_auditor.classifier import Classifier, registrable_domain
from cookie_auditor.models import Cookie, ScanResult


def make_cookie(name, domain="example.com", value="x", lifetime=None, third_party=False):
    return Cookie(
        name=name,
        value_preview=value,
        domain=domain,
        path="/",
        expires=None,
        lifetime_days=lifetime,
        http_only=False,
        secure=False,
        same_site="Lax",
        source="javascript",
        third_party=third_party,
    )


@pytest.fixture
def clf():
    return Classifier()


@pytest.mark.parametrize(
    "name,category,vendor",
    [
        ("_ga", "analytics", "Google Analytics"),
        ("_ga_ABC123XYZ", "analytics", "Google Analytics 4"),
        ("_gid", "analytics", "Google Analytics"),
        ("_fbp", "advertising", "Meta (Facebook)"),
        ("_gcl_au", "advertising", "Google Ads conversion linker"),
        ("_hjSessionUser_12345", "analytics", "Hotjar"),
        ("_clck", "analytics", "Microsoft Clarity"),
        ("_uetsid", "advertising", "Microsoft Advertising (UET)"),
        ("_ttp", "advertising", "TikTok"),
        ("hubspotutk", "analytics", "HubSpot"),
        ("PHPSESSID", "essential", "PHP"),
        ("JSESSIONID", "essential", "Java servlet"),
        ("XSRF-TOKEN", "essential", "CSRF protection"),
        ("__cf_bm", "essential", "Cloudflare"),
        ("OptanonConsent", "essential", "OneTrust"),
        ("CookieConsent", "essential", "Cookiebot"),
        ("usnatUUID", "essential", "Sourcepoint"),
        ("_chartbeat2", "analytics", "Chartbeat"),
        ("IMRID", "analytics", "Nielsen"),
        ("cX_P", "advertising", "Cxense"),
    ],
)
def test_known_cookie_names(clf, name, category, vendor):
    c = clf.classify_cookie(make_cookie(name))
    assert c.category == category
    assert c.vendor == vendor


def test_violation_verdicts(clf):
    assert clf.classify_cookie(make_cookie("_ga")).verdict == "violation"
    assert clf.classify_cookie(make_cookie("PHPSESSID")).verdict == "ok"


def test_generic_name_needs_tracker_domain(clf):
    # "fr" is only a Meta cookie when it lives on a Meta domain.
    first_party = clf.classify_cookie(make_cookie("fr", domain="example.com"))
    assert first_party.category != "advertising"
    meta = clf.classify_cookie(make_cookie("fr", domain=".facebook.com", third_party=True))
    assert meta.category == "advertising"
    assert meta.verdict == "violation"


def test_cookie_on_tracker_domain_is_flagged(clf):
    c = clf.classify_cookie(make_cookie("anything", domain=".doubleclick.net", third_party=True))
    assert c.category == "advertising"
    assert c.confidence == "medium"


def test_third_party_raises_severity(clf):
    first = clf.classify_cookie(make_cookie("_ga"))
    third = clf.classify_cookie(make_cookie("_ga", domain=".google-analytics.com", third_party=True))
    assert first.severity == "medium"
    assert third.severity == "high"


def test_unknown_persistent_identifier_is_review(clf):
    c = clf.classify_cookie(make_cookie("visitor_token", value="7f3a9c1e5b2d48a6b0c4e8d2", lifetime=365))
    assert c.category == "unknown"
    assert c.verdict == "review"


def test_unknown_short_lived_is_info(clf):
    c = clf.classify_cookie(make_cookie("flash_msg", value="hi"))
    assert c.verdict == "info"


def test_strict_mode_promotes_review_to_violation():
    strict = Classifier(strict=True)
    c = strict.classify_cookie(make_cookie("visitor_token", value="7f3a9c1e5b2d48a6b0c4e8d2", lifetime=365))
    assert c.verdict == "violation"


def test_finalize_verdicts(clf):
    fail = ScanResult(url="u", cookies=[make_cookie("_ga"), make_cookie("PHPSESSID")])
    assert clf.finalize(fail).verdict == "FAIL"
    assert fail.summary["violations"] == 1

    ok = ScanResult(url="u", cookies=[make_cookie("PHPSESSID")])
    assert clf.finalize(ok).verdict == "PASS"

    review = ScanResult(url="u", cookies=[make_cookie("visitor_token", value="7f3a9c1e5b2d48a6b0c4e8d2", lifetime=365)])
    assert clf.finalize(review).verdict == "REVIEW"

    empty = ScanResult(url="u")
    assert clf.finalize(empty).verdict == "PASS"


def test_custom_signatures():
    clf = Classifier(
        {
            "tracker_cookies": [{"pattern": "acme_uid", "vendor": "Acme", "category": "advertising"}],
            "essential_cookies": [{"pattern": "app_state", "vendor": "MyApp"}],
        }
    )
    assert clf.classify_cookie(make_cookie("acme_uid")).vendor == "Acme"
    assert clf.classify_cookie(make_cookie("app_state")).verdict == "ok"


@pytest.mark.parametrize(
    "host,expected",
    [
        ("www.example.com", "example.com"),
        ("shop.example.co.uk", "example.co.uk"),
        ("example.com", "example.com"),
        ("localhost", "localhost"),
        ("127.0.0.1", "127.0.0.1"),
        (".google-analytics.com", "google-analytics.com"),
    ],
)
def test_registrable_domain(host, expected):
    assert registrable_domain(host) == expected


def test_new_ad_tech_domains(clf):
    for domain, vendor in [(".stackadapt.com", "StackAdapt"), ("sync.srv.stackadapt.com", "StackAdapt"), (".rlcdn.com", "LiveRamp"), (".3lift.com", "TripleLift")]:
        c = clf.classify_cookie(make_cookie("uid", domain=domain, third_party=True))
        assert c.vendor == vendor and c.verdict == "violation", domain


def test_domain_suffix_does_not_overmatch(clf):
    # "return.com" must not match the "turn.com" style suffix rules, and "notmedia.net" must not match "media.net".
    assert clf.match_domain("notmedia.net") is None
    assert clf.match_domain("sub.media.net")[1] == "Media.net"
