"""Headless browser scanner.

For every URL the scanner opens a brand new browser context (no cookies, no local
storage), loads the page, waits for scripts to settle, and records the cookies that
exist. The scanner never clicks, scrolls, or types, so every cookie it sees was
written before any consent interaction.
"""

from __future__ import annotations

import time
from datetime import datetime, timezone
from typing import Optional
from urllib.parse import urlparse

from playwright.sync_api import Error as PlaywrightError
from playwright.sync_api import TimeoutError as PlaywrightTimeout
from playwright.sync_api import sync_playwright

from .classifier import Classifier, registrable_domain
from .models import Cookie, ScanResult

DEFAULT_UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/130.0 Safari/537.36"
)

# Selectors of common consent banners. First match wins and is used as a hint only.
BANNER_SELECTORS = [
    ("#onetrust-banner-sdk", "OneTrust"),
    ("#CybotCookiebotDialog", "Cookiebot"),
    ("#didomi-host", "Didomi"),
    ("#usercentrics-root", "Usercentrics"),
    (".qc-cmp2-container", "Quantcast Choice"),
    (".osano-cm-window", "Osano"),
    ("#cookie-law-info-bar", "Cookie Law Info"),
    (".cmplz-cookiebanner", "Complianz"),
    (".cc-window", "Cookie Consent (Osano library)"),
    ("#truste-consent-track", "TrustArc"),
    ("[id*='cookie-banner' i]", "Generic banner"),
    ("[class*='cookie-banner' i]", "Generic banner"),
    ("[id*='cookie-consent' i]", "Generic banner"),
    ("[class*='cookie-consent' i]", "Generic banner"),
    ("[aria-label*='cookie' i]", "Generic banner"),
    ("[id*='consent' i][role='dialog']", "Generic banner"),
]

_BANNER_JS = """
(selectors) => {
  for (const [sel, label] of selectors) {
    try {
      const el = document.querySelector(sel);
      if (el) {
        const r = el.getBoundingClientRect();
        const style = getComputedStyle(el);
        const visible = r.width > 0 && r.height > 0 && style.visibility !== 'hidden' && style.display !== 'none';
        if (visible) return label;
      }
    } catch (e) {}
  }
  return '';
}
"""


def _same_site_label(value: str) -> str:
    return value if value else "unspecified"


def _parse_set_cookie_names(header_value: str) -> set[str]:
    """Extract cookie names from a raw (possibly newline joined) Set-Cookie header."""
    names = set()
    for line in header_value.split("\n"):
        line = line.strip()
        if "=" in line:
            names.add(line.split("=", 1)[0].strip())
    return names


def _preview(value: str, limit: int = 24) -> str:
    return value if len(value) <= limit else value[:limit] + "..."


class Scanner:
    """Reusable scanner. Use as a context manager so one browser serves many URLs."""

    def __init__(
        self,
        classifier: Optional[Classifier] = None,
        *,
        wait: float = 3.0,
        timeout: float = 30.0,
        headless: bool = True,
        user_agent: str = DEFAULT_UA,
        locale: str = "en-IE",
        screenshot_dir: Optional[str] = None,
        ignore_https_errors: bool = False,
    ):
        self.classifier = classifier or Classifier()
        self.wait = wait
        self.timeout_ms = int(timeout * 1000)
        self.headless = headless
        self.user_agent = user_agent
        self.locale = locale
        self.screenshot_dir = screenshot_dir
        self.ignore_https_errors = ignore_https_errors
        self._pw = None
        self._browser = None

    def __enter__(self) -> "Scanner":
        self._pw = sync_playwright().start()
        self._browser = self._pw.chromium.launch(headless=self.headless)
        return self

    def __exit__(self, *exc) -> None:
        try:
            if self._browser:
                self._browser.close()
        finally:
            if self._pw:
                self._pw.stop()

    # ------------------------------------------------------------------
    def scan(self, url: str) -> ScanResult:
        if "://" not in url:
            url = "https://" + url
        result = ScanResult(url=url, scanned_at=datetime.now(timezone.utc).isoformat(timespec="seconds"))
        started = time.monotonic()
        context = None
        try:
            context = self._browser.new_context(
                user_agent=self.user_agent,
                locale=self.locale,
                ignore_https_errors=self.ignore_https_errors,
                viewport={"width": 1366, "height": 900},
            )
            page = context.new_page()
            page.set_default_timeout(self.timeout_ms)

            responses = []
            seen_requests: dict[str, None] = {}

            def on_request(req):
                seen_requests[req.url] = None

            page.on("request", on_request)
            page.on("response", lambda resp: responses.append(resp))

            try:
                page.goto(url, wait_until="load", timeout=self.timeout_ms)
            except PlaywrightTimeout:
                # A slow page still has cookies worth reporting. Continue with what loaded.
                pass

            # Let deferred scripts, tag managers and pixels run. No user interaction.
            try:
                page.wait_for_load_state("networkidle", timeout=min(self.timeout_ms, 10_000))
            except PlaywrightTimeout:
                pass
            page.wait_for_timeout(int(self.wait * 1000))

            result.final_url = page.url
            result.host = urlparse(page.url).hostname or ""
            try:
                result.page_title = page.title()
            except PlaywrightError:
                result.page_title = ""

            hint = ""
            try:
                hint = page.evaluate(_BANNER_JS, BANNER_SELECTORS) or ""
            except PlaywrightError:
                pass
            result.consent_banner_detected = bool(hint)
            result.consent_banner_hint = hint

            header_cookie_names: set[str] = set()
            for resp in responses:
                try:
                    raw = resp.all_headers().get("set-cookie", "")
                except PlaywrightError:
                    continue
                if raw:
                    header_cookie_names |= _parse_set_cookie_names(raw)

            page_domain = registrable_domain(result.host)
            now = time.time()
            for c in context.cookies():
                expires = c.get("expires", -1)
                persistent = expires is not None and expires > 0
                result.cookies.append(
                    Cookie(
                        name=c["name"],
                        value_preview=_preview(c.get("value", "")),
                        domain=c["domain"],
                        path=c.get("path", "/"),
                        expires=expires if persistent else None,
                        lifetime_days=round((expires - now) / 86400, 1) if persistent else None,
                        http_only=bool(c.get("httpOnly")),
                        secure=bool(c.get("secure")),
                        same_site=_same_site_label(c.get("sameSite", "")),
                        source="http" if c["name"] in header_cookie_names else "javascript",
                        third_party=registrable_domain(c["domain"]) != page_domain,
                    )
                )

            for req_url in seen_requests:
                if req_url.startswith(("data:", "blob:")):
                    continue
                try:
                    host = urlparse(req_url).hostname or ""
                except ValueError:
                    continue
                if not host:
                    continue
                tr = self.classifier.classify_request(req_url, host)
                if tr:
                    result.tracker_requests.append(tr)

            if self.screenshot_dir:
                import os
                import re

                os.makedirs(self.screenshot_dir, exist_ok=True)
                slug = re.sub(r"[^a-zA-Z0-9]+", "_", result.host or "page").strip("_")
                path = os.path.join(self.screenshot_dir, f"{slug}.png")
                try:
                    page.screenshot(path=path)
                    result.screenshot = path
                except PlaywrightError:
                    pass

            self.classifier.finalize(result)
        except PlaywrightError as exc:
            result.error = str(exc).strip().splitlines()[0][:300]
            result.verdict = "ERROR"
        finally:
            if context:
                context.close()
            result.duration_s = round(time.monotonic() - started, 1)
        return result
