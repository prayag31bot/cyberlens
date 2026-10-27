"""Explainable risk scoring. Pure functions, no I/O, fully unit-tested.

Policy (also in docs/risk-scoring.md):
  points(indicator) = BASE[severity] * reliability
  Correlated indicators share a `group`; only the highest-point one per group counts
  (prevents double counting e.g. 'punycode' + 'mixed scripts').
  score = min(100, sum(group maxima))
  Trusted, non-mock provider POSITIVE -> score floored at `trusted_intel_floor` (verdict PHISHING).
  Verdict: score >= phishing_threshold -> PHISHING; >= suspicious_threshold -> SUSPICIOUS.
  Below that: SAFE only if enough *real* checks completed, otherwise UNKNOWN.
  Absence of a blocklist hit never lowers risk and is never described as proof of safety.
The score is an internal risk estimate, not a probability of compromise.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from app.core.config import Settings
from app.core.models import Analysis, Indicator, Severity, SourceStatus, Verdict

BASE_POINTS = {Severity.INFO: 0, Severity.LOW: 8, Severity.MEDIUM: 18, Severity.HIGH: 40, Severity.CRITICAL: 60}


@dataclass
class ScoreLine:
    indicator_id: str
    group: str
    points: float
    counted: bool
    note: str = ""


@dataclass
class RiskAssessment:
    score: int
    verdict: Verdict
    confidence: str                 # "low" | "medium" | "high"  (evidence strength, not accuracy)
    breakdown: list[ScoreLine] = field(default_factory=list)
    unknowns: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)


def indicator_points(i: Indicator) -> float:
    return round(BASE_POINTS[i.severity] * max(0.0, min(1.0, i.reliability)), 1)


def assess(analysis: Analysis, settings: Settings) -> RiskAssessment:
    # ---- group dedup ----
    best: dict[str, Indicator] = {}
    for i in analysis.indicators:
        g = i.group or i.id
        if g not in best or indicator_points(i) > indicator_points(best[g]):
            best[g] = i
    lines: list[ScoreLine] = []
    total = 0.0
    for i in analysis.indicators:
        g = i.group or i.id
        counted = best[g] is i
        pts = indicator_points(i)
        lines.append(ScoreLine(i.id, g, pts, counted,
                               "" if counted else f"not counted: correlated with stronger signal '{best[g].id}'"))
        if counted:
            total += pts
    score = int(min(100, round(total)))
    notes: list[str] = []

    # ---- provider evidence ----
    trusted_positive = [s for s in analysis.sources
                        if s.status == SourceStatus.POSITIVE and s.trusted and not s.is_mock]
    mock_positive = [s for s in analysis.sources if s.status == SourceStatus.POSITIVE and s.is_mock]
    if trusted_positive:
        score = max(score, settings.trusted_intel_floor)
        notes.append("Trusted threat-intelligence match: " + ", ".join(s.name for s in trusted_positive))
    if mock_positive:
        # mock results are labelled and behave like a match so demos/tests are visible
        score = max(score, settings.trusted_intel_floor)
        notes.append("MOCK provider reported a match (test data, not real intelligence): "
                     + ", ".join(s.name for s in mock_positive))

    # ---- evidence strength ----
    real_checks = [k for k, v in analysis.checks.items() if k != "lexical" and v == "completed"]
    real_intel_negative = [s for s in analysis.sources
                           if s.status == SourceStatus.NEGATIVE and s.trusted and not s.is_mock]
    real_count = len(real_checks) + (1 if real_intel_negative else 0)
    unknowns = [f"{k}: {v.replace('_', ' ')}" for k, v in analysis.checks.items() if v != "completed"]
    unknowns += [f"{s.name}: {s.status.value}" + (f" ({s.detail})" if s.detail else "")
                 for s in analysis.sources if s.status in (SourceStatus.UNAVAILABLE, SourceStatus.NOT_RUN)]
    if real_count >= 3 or (real_count >= 2 and real_intel_negative):
        confidence = "high"
    elif real_count >= 1:
        confidence = "medium"
    else:
        confidence = "low"

    # ---- verdict ----
    if score >= settings.phishing_threshold:
        verdict = Verdict.PHISHING
    elif score >= settings.suspicious_threshold:
        verdict = Verdict.SUSPICIOUS
    elif real_count >= settings.min_real_checks_for_safe:
        verdict = Verdict.SAFE
    else:
        verdict = Verdict.UNKNOWN
        notes.append("Too few independent checks completed to call this safe.")

    # conflict note: strong rules signals but a trusted source found nothing
    if real_intel_negative and score >= settings.suspicious_threshold and not trusted_positive:
        notes.append("Conflicting evidence: rule-based signals are concerning although a reputation source "
                     "had no record. New phishing pages are often not listed yet; the rule-based verdict stands.")
    if verdict == Verdict.SAFE:
        notes.append("SAFE means no significant indicators were found in the checks listed above. "
                     "It is not a guarantee.")
    return RiskAssessment(score, verdict, confidence, lines, unknowns, notes)
