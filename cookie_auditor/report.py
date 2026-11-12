"""Report writers: console summary, JSON, Markdown and self contained HTML."""

from __future__ import annotations

import html
import json
import re
from datetime import datetime, timezone
from pathlib import Path

from .models import ScanResult

VERDICT_TEXT = {
    "PASS": "No non-essential cookies were set before consent.",
    "REVIEW": "No definite violations, but some items need manual review.",
    "FAIL": "Non-essential cookies were set before any consent interaction.",
    "ERROR": "The page could not be scanned.",
}

CATEGORY_ORDER = ["advertising", "analytics", "social", "functional", "unknown", "essential"]


def _sorted_cookies(result: ScanResult):
    sev = {"high": 0, "medium": 1, "low": 2, "info": 3}
    cat = {c: i for i, c in enumerate(CATEGORY_ORDER)}
    return sorted(result.cookies, key=lambda c: (sev.get(c.severity, 9), cat.get(c.category, 9), c.name.lower()))


def _lifetime(c) -> str:
    return "session" if c.lifetime_days is None else f"{c.lifetime_days:g} d"


def slugify(text: str) -> str:
    return re.sub(r"[^a-zA-Z0-9]+", "_", text).strip("_") or "report"


# ---------------------------------------------------------------------------
# Console
# ---------------------------------------------------------------------------
def console_summary(result: ScanResult) -> str:
    lines = [f"[{result.verdict}] {result.url}"]
    if result.error:
        lines.append(f"    error: {result.error}")
        return "\n".join(lines)
    s = result.summary
    banner = result.consent_banner_hint or "none detected"
    lines.append(
        f"    cookies: {s['total_cookies']}  violations: {s['violations']}  "
        f"review: {s['review']}  third party: {s['third_party_cookies']}  banner: {banner}"
    )
    if s["violating_vendors"]:
        lines.append("    vendors setting cookies before consent: " + ", ".join(s["violating_vendors"]))
    if s["tracker_requests"]:
        lines.append(
            f"    requests to tracker hosts before consent: {s['tracker_requests']} "
            f"({', '.join(s['tracker_request_vendors'])})"
        )
    for c in _sorted_cookies(result):
        if c.verdict in ("violation", "review"):
            flag = "VIOLATION" if c.verdict == "violation" else "review"
            vendor = f" ({c.vendor})" if c.vendor else ""
            lines.append(f"      {flag:9} {c.severity:6} {c.category:11} {c.name} on {c.domain}{vendor}")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# JSON
# ---------------------------------------------------------------------------
def write_json(results: list[ScanResult], path: Path) -> None:
    payload = {
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "results": [r.to_dict() for r in results],
    }
    path.write_text(json.dumps(payload, indent=2), encoding="utf-8")


# ---------------------------------------------------------------------------
# Markdown
# ---------------------------------------------------------------------------
def _md_escape(text: str) -> str:
    return str(text).replace("|", "\\|").replace("\n", " ")


def render_markdown(results: list[ScanResult]) -> str:
    out = ["# Cookie Consent Audit", "", f"Generated: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}", ""]
    out += ["## Overview", "", "| URL | Verdict | Cookies | Violations | Review | Tracker requests |", "|---|---|---|---|---|---|"]
    for r in results:
        s = r.summary or {}
        out.append(
            f"| {_md_escape(r.url)} | {r.verdict} | {s.get('total_cookies', '')} | "
            f"{s.get('violations', '')} | {s.get('review', '')} | {s.get('tracker_requests', '')} |"
        )
    out.append("")
    for r in results:
        out += [f"## {r.url}", "", f"**Verdict: {r.verdict}.** {VERDICT_TEXT[r.verdict]}", ""]
        if r.error:
            out += [f"Error: `{r.error}`", ""]
            continue
        out += [
            f"- Final URL: {r.final_url}",
            f"- Scanned at: {r.scanned_at} ({r.duration_s}s)",
            f"- Consent banner: {r.consent_banner_hint or 'not detected'}",
            "",
        ]
        if r.cookies:
            out += [
                "| Verdict | Severity | Category | Cookie | Domain | Vendor | Party | Source | Lifetime |",
                "|---|---|---|---|---|---|---|---|---|",
            ]
            for c in _sorted_cookies(r):
                out.append(
                    f"| {c.verdict} | {c.severity} | {c.category} | `{_md_escape(c.name)}` | {_md_escape(c.domain)} | "
                    f"{_md_escape(c.vendor)} | {'third' if c.third_party else 'first'} | {c.source} | {_lifetime(c)} |"
                )
            out.append("")
        else:
            out += ["No cookies were set before consent.", ""]
        if r.tracker_requests:
            out += ["Requests to tracker hosts before consent:", ""]
            for t in r.tracker_requests[:50]:
                out.append(f"- {t.vendor} ({t.category}): `{_md_escape(t.host)}`")
            out.append("")
    return "\n".join(out)


# ---------------------------------------------------------------------------
# HTML
# ---------------------------------------------------------------------------
_CSS = """
:root{--bg:#f6f7f9;--card:#fff;--text:#1b1f24;--muted:#5b6672;--line:#e2e6ea;
--pass:#1a7f37;--review:#9a6700;--fail:#cf222e;--error:#6e7781}
@media (prefers-color-scheme:dark){:root{--bg:#0f1317;--card:#171c22;--text:#e6eaee;--muted:#98a3ae;--line:#2a323b}}
*{box-sizing:border-box}body{margin:0;padding:24px;background:var(--bg);color:var(--text);
font:14px/1.5 system-ui,-apple-system,Segoe UI,sans-serif}
h1{font-size:22px;margin:0 0 4px}h2{font-size:16px;margin:0 0 8px;word-break:break-all}
.muted{color:var(--muted)}.card{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:16px;margin:16px 0}
.badge{display:inline-block;padding:2px 10px;border-radius:999px;color:#fff;font-weight:600;font-size:12px}
.PASS{background:var(--pass)}.REVIEW{background:var(--review)}.FAIL{background:var(--fail)}.ERROR{background:var(--error)}
table{border-collapse:collapse;width:100%;font-size:13px}th,td{text-align:left;padding:6px 8px;border-bottom:1px solid var(--line);vertical-align:top}
th{color:var(--muted);font-weight:600}.wrap{overflow-x:auto}code{font-family:ui-monospace,Menlo,Consolas,monospace;font-size:12px}
.violation{color:var(--fail);font-weight:600}.review-c{color:var(--review);font-weight:600}.ok{color:var(--pass)}
"""


def _h(x) -> str:
    return html.escape(str(x), quote=True)


def render_html(results: list[ScanResult]) -> str:
    parts = [
        "<!doctype html><html lang='en'><head><meta charset='utf-8'>",
        "<meta name='viewport' content='width=device-width,initial-scale=1'>",
        "<title>Cookie Consent Audit</title>",
        f"<style>{_CSS}</style></head><body>",
        "<h1>Cookie Consent Audit</h1>",
        f"<div class='muted'>Generated {_h(datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC'))}. "
        "Cookies recorded before any consent interaction.</div>",
        "<div class='card wrap'><table><tr><th>URL</th><th>Verdict</th><th>Cookies</th><th>Violations</th>"
        "<th>Review</th><th>Tracker requests</th></tr>",
    ]
    for r in results:
        s = r.summary or {}
        parts.append(
            f"<tr><td>{_h(r.url)}</td><td><span class='badge {r.verdict}'>{r.verdict}</span></td>"
            f"<td>{_h(s.get('total_cookies', ''))}</td><td>{_h(s.get('violations', ''))}</td>"
            f"<td>{_h(s.get('review', ''))}</td><td>{_h(s.get('tracker_requests', ''))}</td></tr>"
        )
    parts.append("</table></div>")

    for r in results:
        parts.append(f"<div class='card'><h2>{_h(r.url)} <span class='badge {r.verdict}'>{r.verdict}</span></h2>")
        parts.append(f"<div class='muted'>{_h(VERDICT_TEXT[r.verdict])}</div>")
        if r.error:
            parts.append(f"<p><code>{_h(r.error)}</code></p></div>")
            continue
        parts.append(
            f"<p class='muted'>Final URL: {_h(r.final_url)}<br>Consent banner: "
            f"{_h(r.consent_banner_hint or 'not detected')}<br>Scanned {_h(r.scanned_at)} in {_h(r.duration_s)}s</p>"
        )
        if r.cookies:
            parts.append(
                "<div class='wrap'><table><tr><th>Verdict</th><th>Severity</th><th>Category</th><th>Cookie</th>"
                "<th>Domain</th><th>Vendor</th><th>Party</th><th>Source</th><th>Lifetime</th><th>Reason</th></tr>"
            )
            for c in _sorted_cookies(r):
                cls = {"violation": "violation", "review": "review-c", "ok": "ok"}.get(c.verdict, "")
                parts.append(
                    f"<tr><td class='{cls}'>{_h(c.verdict)}</td><td>{_h(c.severity)}</td><td>{_h(c.category)}</td>"
                    f"<td><code>{_h(c.name)}</code></td><td>{_h(c.domain)}</td><td>{_h(c.vendor)}</td>"
                    f"<td>{'third' if c.third_party else 'first'}</td><td>{_h(c.source)}</td>"
                    f"<td>{_h(_lifetime(c))}</td><td>{_h(c.reason)}</td></tr>"
                )
            parts.append("</table></div>")
        else:
            parts.append("<p>No cookies were set before consent.</p>")
        if r.tracker_requests:
            parts.append("<h3>Requests to tracker hosts before consent</h3><ul>")
            for t in r.tracker_requests[:50]:
                parts.append(f"<li>{_h(t.vendor)} ({_h(t.category)}): <code>{_h(t.host)}</code></li>")
            parts.append("</ul>")
        parts.append("</div>")
    parts.append("</body></html>")
    return "".join(parts)


def write_reports(results: list[ScanResult], out_dir: str, formats: list[str]) -> list[Path]:
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    written = []
    if "json" in formats:
        p = out / f"audit-{stamp}.json"
        write_json(results, p)
        written.append(p)
    if "md" in formats:
        p = out / f"audit-{stamp}.md"
        p.write_text(render_markdown(results), encoding="utf-8")
        written.append(p)
    if "html" in formats:
        p = out / f"audit-{stamp}.html"
        p.write_text(render_html(results), encoding="utf-8")
        written.append(p)
    return written
