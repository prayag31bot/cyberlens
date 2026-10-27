"""Domain types shared by the analysis services (plain dataclasses, stdlib only)."""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum


class Severity(str, Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class Verdict(str, Enum):
    SAFE = "SAFE"
    SUSPICIOUS = "SUSPICIOUS"
    PHISHING = "PHISHING"
    UNKNOWN = "UNKNOWN"


class SourceStatus(str, Enum):
    POSITIVE = "positive"        # source reports a threat
    NEGATIVE = "negative"        # source checked and found nothing (NOT proof of safety)
    UNAVAILABLE = "unavailable"  # timeout, outage, missing key, circuit open
    NOT_RUN = "not_run"          # feature disabled


@dataclass
class Indicator:
    id: str                 # stable machine id, e.g. "ip_host"
    title: str
    severity: Severity
    explanation: str        # why it matters, in plain language
    evidence: str           # the concrete data observed (never invented)
    provenance: str         # "rule", "dns", "header", "provider:<name>"
    reliability: float = 0.8  # 0..1 how much we trust this signal
    group: str = ""         # correlated signals share a group; only the max counts


@dataclass
class SourceResult:
    name: str
    status: SourceStatus
    detail: str = ""
    is_mock: bool = False
    trusted: bool = False   # True only for real, reputable providers


@dataclass
class Analysis:
    indicators: list[Indicator] = field(default_factory=list)
    sources: list[SourceResult] = field(default_factory=list)
    # check name -> "completed" | "unavailable" | "not_run"
    checks: dict[str, str] = field(default_factory=dict)
