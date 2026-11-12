"""Data models shared across the auditor."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Optional

# Cookie categories, in the order they are reported.
ESSENTIAL = "essential"
FUNCTIONAL = "functional"
ANALYTICS = "analytics"
ADVERTISING = "advertising"
SOCIAL = "social"
UNKNOWN = "unknown"

# Categories that require prior consent and therefore count as violations
# when found before any consent interaction.
CONSENT_REQUIRED = {ANALYTICS, ADVERTISING, SOCIAL}

SEVERITY_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3}


@dataclass
class Cookie:
    name: str
    value_preview: str
    domain: str
    path: str
    expires: Optional[float]  # unix timestamp, None for session cookies
    lifetime_days: Optional[float]  # None for session cookies
    http_only: bool
    secure: bool
    same_site: str
    source: str  # "http" (Set-Cookie header) or "javascript" (document.cookie)
    third_party: bool

    # Filled in by the classifier.
    category: str = UNKNOWN
    vendor: str = ""
    confidence: str = "low"  # low, medium, high
    reason: str = ""
    verdict: str = "info"  # violation, review, ok, info
    severity: str = "info"


@dataclass
class TrackerRequest:
    url: str
    host: str
    vendor: str
    category: str


@dataclass
class ScanResult:
    url: str
    final_url: str = ""
    host: str = ""
    page_title: str = ""
    scanned_at: str = ""
    duration_s: float = 0.0
    consent_banner_detected: bool = False
    consent_banner_hint: str = ""
    cookies: list[Cookie] = field(default_factory=list)
    tracker_requests: list[TrackerRequest] = field(default_factory=list)
    screenshot: str = ""
    error: str = ""

    # Derived by the classifier / verdict step.
    verdict: str = "ERROR"  # PASS, REVIEW, FAIL, ERROR
    summary: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return asdict(self)
