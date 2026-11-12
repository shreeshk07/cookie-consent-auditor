"""CLI behaviour: argument errors must exit with 2, never a traceback or exit code 1."""

import json

import pytest

from cookie_auditor.cli import main
from demo_site import server

PORT = 8798


def test_no_urls(capsys):
    assert main([]) == 2
    assert "No URLs given" in capsys.readouterr().err


def test_bad_format(capsys):
    assert main(["example.com", "--format", "pdf"]) == 2
    assert "Unknown format" in capsys.readouterr().err


def test_missing_url_file(capsys, tmp_path):
    assert main(["--file", str(tmp_path / "nope.txt")]) == 2
    assert "Could not read URL file" in capsys.readouterr().err


def test_missing_signatures_file(capsys, tmp_path):
    assert main(["example.com", "--signatures", str(tmp_path / "nope.json")]) == 2
    assert "Could not load signatures file" in capsys.readouterr().err


@pytest.mark.parametrize(
    "content",
    ["{bad json", "[]", '{"tracker_cookies": [{"pattern": "("}]}', '{"tracker_cookies": [{"vendor": "x"}]}'],
)
def test_malformed_signatures(capsys, tmp_path, content):
    f = tmp_path / "sig.json"
    f.write_text(content)
    assert main(["example.com", "--signatures", str(f)]) == 2
    assert "Could not load signatures file" in capsys.readouterr().err


@pytest.fixture(scope="module")
def demo():
    srv = server.start(PORT)
    yield f"http://127.0.0.1:{PORT}"
    srv.shutdown()


def test_exit_codes_and_reports(demo, tmp_path, capsys):
    out = tmp_path / "out"
    assert main([demo + "/good", "--wait", "0.5", "-o", str(out), "--quiet"]) == 0
    assert main([demo + "/bad", "--wait", "0.5", "-o", str(out), "--quiet"]) == 1
    assert main(["http://127.0.0.1:1/", "--wait", "0.5", "-o", str(out), "--quiet"]) == 2
    assert {p.suffix for p in out.iterdir()} >= {".json", ".md", ".html"}


def test_strict_turns_review_into_fail(demo, tmp_path):
    out = tmp_path / "out"
    assert main([demo + "/mixed", "--wait", "0.5", "-o", str(out), "--quiet"]) == 0
    assert main([demo + "/mixed", "--wait", "0.5", "-o", str(out), "--quiet", "--strict"]) == 1


def test_url_file_and_custom_signature(demo, tmp_path):
    urls = tmp_path / "urls.txt"
    urls.write_text(f"# comment\n{demo}/mixed\n\n{demo}/mixed\n")  # duplicate is scanned once
    sig = tmp_path / "sig.json"
    sig.write_text(json.dumps({"tracker_cookies": [{"pattern": "visitor_token", "vendor": "Acme", "category": "advertising"}]}))
    out = tmp_path / "out"
    assert main(["--file", str(urls), "--signatures", str(sig), "--wait", "0.5", "-o", str(out), "--format", "json", "--quiet"]) == 1
    data = json.loads(next(out.glob("*.json")).read_text())
    assert len(data["results"]) == 1
    assert data["results"][0]["summary"]["violating_vendors"] == ["Acme"]
