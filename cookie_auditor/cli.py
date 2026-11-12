"""Command line interface."""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

from playwright.sync_api import Error as PlaywrightError

from . import __version__
from .classifier import Classifier
from .report import console_summary, write_reports
from .scanner import DEFAULT_UA, Scanner


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="cookie-auditor",
        description="Detect cookies that are set before consent and classify them against known tracker signatures.",
    )
    p.add_argument("urls", nargs="*", help="One or more URLs or domains to audit")
    p.add_argument("-f", "--file", help="Text file with one URL per line (lines starting with # are ignored)")
    p.add_argument("-o", "--out", default="reports", help="Output directory for reports (default: reports)")
    p.add_argument(
        "--format",
        default="json,md,html",
        help="Comma separated report formats: json, md, html (default: all three)",
    )
    p.add_argument("--wait", type=float, default=3.0, help="Seconds to wait after load for scripts to settle (default: 3)")
    p.add_argument("--timeout", type=float, default=30.0, help="Navigation timeout in seconds (default: 30)")
    p.add_argument("--headed", action="store_true", help="Show the browser window instead of running headless")
    p.add_argument("--user-agent", default=DEFAULT_UA, help="User agent string")
    p.add_argument("--locale", default="en-IE", help="Browser locale (default: en-IE)")
    p.add_argument("--screenshots", action="store_true", help="Save a screenshot of each page next to the reports")
    p.add_argument("--signatures", help="JSON file with extra signatures (see README)")
    p.add_argument(
        "--strict",
        action="store_true",
        help="Treat functional and unrecognised persistent cookies, and tracker requests, as failures",
    )
    p.add_argument("--ignore-https-errors", action="store_true", help="Continue past TLS certificate errors")
    p.add_argument("--quiet", action="store_true", help="Only print the final summary line")
    p.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    return p


def read_urls(args) -> list[str]:
    urls = list(args.urls)
    if args.file:
        for line in Path(args.file).read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if line and not line.startswith("#"):
                urls.append(line)
    seen, ordered = set(), []
    for u in urls:
        if u not in seen:
            seen.add(u)
            ordered.append(u)
    return ordered


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    try:
        urls = read_urls(args)
    except (OSError, UnicodeDecodeError) as exc:
        print(f"Could not read URL file: {exc}", file=sys.stderr)
        return 2
    if not urls:
        print("No URLs given. Pass URLs as arguments or use --file.", file=sys.stderr)
        return 2

    formats = [f.strip().lower() for f in args.format.split(",") if f.strip()]
    bad = [f for f in formats if f not in {"json", "md", "html"}]
    if bad:
        print(f"Unknown format(s): {', '.join(bad)}. Use json, md, html.", file=sys.stderr)
        return 2

    try:
        classifier = Classifier.from_file(args.signatures, strict=args.strict)
    except (OSError, ValueError, KeyError, TypeError, AttributeError, re.error) as exc:
        print(f"Could not load signatures file: {exc}", file=sys.stderr)
        return 2

    shots = str(Path(args.out) / "screenshots") if args.screenshots else None
    results = []
    scanner = Scanner(
        classifier,
        wait=args.wait,
        timeout=args.timeout,
        headless=not args.headed,
        user_agent=args.user_agent,
        locale=args.locale,
        screenshot_dir=shots,
        ignore_https_errors=args.ignore_https_errors,
    )
    try:
        scanner.__enter__()
    except PlaywrightError as exc:
        first = str(exc).strip().splitlines()[0] if str(exc).strip() else "browser failed to start"
        print(f"Could not start Chromium: {first}", file=sys.stderr)
        print("Install it with: python -m playwright install chromium", file=sys.stderr)
        return 2
    try:
        for i, url in enumerate(urls, 1):
            if not args.quiet:
                print(f"({i}/{len(urls)}) scanning {url} ...", flush=True)
            result = scanner.scan(url)
            results.append(result)
            if not args.quiet:
                print(console_summary(result), flush=True)
    finally:
        scanner.__exit__(None, None, None)

    written = write_reports(results, args.out, formats)
    counts = {v: sum(1 for r in results if r.verdict == v) for v in ("PASS", "REVIEW", "FAIL", "ERROR")}
    print(
        f"\nDone: {counts['PASS']} pass, {counts['REVIEW']} review, {counts['FAIL']} fail, {counts['ERROR']} error."
    )
    for path in written:
        print(f"Report: {path}")

    if counts["FAIL"]:
        return 1
    if counts["ERROR"]:
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
