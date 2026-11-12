"""Cookie classification and verdict logic."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Optional

from . import signatures as sig
from .models import (
    ADVERTISING,
    ANALYTICS,
    CONSENT_REQUIRED,
    ESSENTIAL,
    FUNCTIONAL,
    SEVERITY_ORDER,
    SOCIAL,
    UNKNOWN,
    Cookie,
    ScanResult,
    TrackerRequest,
)

# Second level labels that, together with a two letter country code, form a public
# suffix (co.uk, com.au, ...). This is a small heuristic that avoids a dependency on
# the full public suffix list.
_SECOND_LEVEL = {"co", "com", "org", "net", "gov", "ac", "edu", "or", "ne", "go"}

SEVERITY_BY_CATEGORY = {ADVERTISING: "high", SOCIAL: "medium", ANALYTICS: "medium"}


def registrable_domain(host: str) -> str:
    """Return the registrable domain of a host (best effort)."""
    host = host.strip().lstrip(".").lower().split(":")[0]
    if not host or re.fullmatch(r"[\d.]+", host) or ":" in host:
        return host  # IPv4 address or bare host such as "localhost"
    labels = host.split(".")
    if len(labels) <= 2:
        return host
    if len(labels[-1]) == 2 and labels[-2] in _SECOND_LEVEL:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:])


def host_matches(host: str, suffix: str) -> bool:
    host = host.lstrip(".").lower()
    return host == suffix or host.endswith("." + suffix)


@dataclass
class Rule:
    pattern: re.Pattern
    vendor: str
    category: str


def _compile(rows: Iterable[tuple]) -> list[Rule]:
    return [Rule(re.compile(p, re.IGNORECASE), v, c) for p, v, c in rows]


class Classifier:
    """Classifies cookies and tracker requests.

    Matching order for a cookie:
      1. Essential name signatures (sessions, security, consent cookies).
      2. Tracker name signatures. Generic names (for example "fr" or "NID") only
         match when the cookie domain also belongs to a known tracker.
      3. Tracker domain signatures (any cookie set by a tracker host).
      4. Functional name signatures (preferences, chat widgets), reported for review.
      5. Heuristic for persistent identifier-like cookies, reported for review.
    """

    def __init__(self, extra_signatures: Optional[dict] = None, strict: bool = False):
        self.strict = strict
        self.essential = _compile(sig.ESSENTIAL_COOKIE_SIGNATURES)
        self.functional = _compile(sig.FUNCTIONAL_COOKIE_SIGNATURES)
        self.trackers = _compile(sig.TRACKER_COOKIE_SIGNATURES)
        self.domains = list(sig.TRACKER_DOMAIN_SIGNATURES)
        self.cookie_only_domains = list(sig.COOKIE_ONLY_DOMAIN_SIGNATURES)
        self.name_requires_domain = set(sig.NAME_REQUIRES_DOMAIN)
        if extra_signatures:
            self._load_extra(extra_signatures)

    # -- configuration ----------------------------------------------------
    @classmethod
    def from_file(cls, path: Optional[str], strict: bool = False) -> "Classifier":
        extra = None
        if path:
            extra = json.loads(Path(path).read_text(encoding="utf-8"))
            if not isinstance(extra, dict):
                raise ValueError("signatures file must contain a JSON object")
        return cls(extra, strict=strict)

    def _load_extra(self, extra: dict) -> None:
        for row in extra.get("essential_cookies", []):
            self.essential.insert(0, Rule(re.compile(row["pattern"], re.I), row.get("vendor", "Custom"), ESSENTIAL))
        for row in extra.get("tracker_cookies", []):
            self.trackers.insert(
                0, Rule(re.compile(row["pattern"], re.I), row.get("vendor", "Custom"), row.get("category", ANALYTICS))
            )
        for row in extra.get("tracker_domains", []):
            self.domains.insert(0, (row["domain"].lower(), row.get("vendor", "Custom"), row.get("category", ANALYTICS)))

    # -- domain helpers ---------------------------------------------------
    def match_domain(self, host: str, include_cookie_only: bool = False):
        rows = self.domains + (self.cookie_only_domains if include_cookie_only else [])
        best = None
        for suffix, vendor, category in rows:
            if host_matches(host, suffix):
                # Prefer the most specific (longest) suffix.
                if best is None or len(suffix) > len(best[0]):
                    best = (suffix, vendor, category)
        return best

    # -- cookies ----------------------------------------------------------
    def classify_cookie(self, cookie: Cookie) -> Cookie:
        name = cookie.name
        domain = cookie.domain.lstrip(".")

        for rule in self.essential:
            if rule.pattern.fullmatch(name):
                return self._finish(cookie, ESSENTIAL, rule.vendor, "high", f"Name matches {rule.vendor} essential cookie")

        for rule in self.trackers:
            if not rule.pattern.fullmatch(name):
                continue
            if name.lower() in self.name_requires_domain:
                dom = self.match_domain(domain, include_cookie_only=True)
                if not dom:
                    continue
            return self._finish(
                cookie, rule.category, rule.vendor, "high", f"Name matches {rule.vendor} cookie signature"
            )

        dom = self.match_domain(domain)
        if dom:
            _, vendor, category = dom
            return self._finish(cookie, category, vendor, "medium", f"Set by tracker domain {domain}")

        for rule in self.functional:
            if rule.pattern.fullmatch(name):
                return self._finish(
                    cookie, FUNCTIONAL, rule.vendor, "medium", f"{rule.vendor} preference or widget cookie, consent may still be required"
                )

        persistent = cookie.lifetime_days is not None and cookie.lifetime_days > 1
        id_like = len(cookie.value_preview.replace("...", "")) >= 12 and bool(
            re.search(r"[0-9a-f]{8,}|[A-Za-z0-9_\-]{16,}", cookie.value_preview)
        )
        if persistent and id_like:
            return self._finish(
                cookie,
                UNKNOWN,
                "",
                "low",
                f"Unrecognised persistent cookie ({cookie.lifetime_days:.0f} days) with an identifier like value",
                verdict_override="review",
            )
        return self._finish(cookie, UNKNOWN, "", "low", "Unrecognised cookie, no persistent identifier detected", verdict_override="info")

    def _finish(self, cookie, category, vendor, confidence, reason, verdict_override=None) -> Cookie:
        cookie.category = category
        cookie.vendor = vendor
        cookie.confidence = confidence
        cookie.reason = reason
        if verdict_override:
            cookie.verdict = verdict_override
        elif category == ESSENTIAL:
            cookie.verdict = "ok"
        elif category in CONSENT_REQUIRED:
            cookie.verdict = "violation"
        elif category == FUNCTIONAL:
            cookie.verdict = "review"
        else:
            cookie.verdict = "info"

        if cookie.verdict == "violation":
            cookie.severity = SEVERITY_BY_CATEGORY.get(category, "medium")
            if cookie.third_party and cookie.severity == "medium":
                cookie.severity = "high"
        elif cookie.verdict == "review":
            cookie.severity = "low"
        else:
            cookie.severity = "info"

        if self.strict and cookie.verdict == "review":
            cookie.verdict = "violation"
        return cookie

    # -- requests ---------------------------------------------------------
    def classify_request(self, url: str, host: str) -> Optional[TrackerRequest]:
        dom = self.match_domain(host)
        if not dom:
            return None
        _, vendor, category = dom
        if category == FUNCTIONAL:
            return None
        return TrackerRequest(url=url, host=host, vendor=vendor, category=category)

    # -- verdict ----------------------------------------------------------
    def finalize(self, result: ScanResult) -> ScanResult:
        """Classify every cookie in the result and compute the page verdict."""
        for c in result.cookies:
            self.classify_cookie(c)

        violations = [c for c in result.cookies if c.verdict == "violation"]
        reviews = [c for c in result.cookies if c.verdict == "review"]
        by_category: dict[str, int] = {}
        for c in result.cookies:
            by_category[c.category] = by_category.get(c.category, 0) + 1

        top = "info"
        for c in violations:
            if SEVERITY_ORDER[c.severity] > SEVERITY_ORDER[top]:
                top = c.severity

        vendors = sorted({c.vendor for c in violations if c.vendor})
        request_vendors = sorted({r.vendor for r in result.tracker_requests})

        result.summary = {
            "total_cookies": len(result.cookies),
            "by_category": by_category,
            "violations": len(violations),
            "review": len(reviews),
            "highest_severity": top,
            "violating_vendors": vendors,
            "tracker_requests": len(result.tracker_requests),
            "tracker_request_vendors": request_vendors,
            "third_party_cookies": sum(1 for c in result.cookies if c.third_party),
        }

        if violations:
            result.verdict = "FAIL"
        elif reviews or result.tracker_requests:
            result.verdict = "FAIL" if (self.strict and (reviews or result.tracker_requests)) else "REVIEW"
        else:
            result.verdict = "PASS"
        return result
