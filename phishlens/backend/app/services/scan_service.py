"""Orchestrates one scan: validate -> deterministic checks -> intel -> score -> explain -> report."""
from __future__ import annotations

import hashlib
import time
import uuid
from datetime import datetime, timezone

from app.core.config import Settings
from app.core.models import Analysis, SourceResult, SourceStatus
from app.schemas.scan import AIOut, IndicatorOut, ScanReport, SourceOut
from app.services import ai_service
from app.services.ai_service import AIProvider, AIUnavailable
from app.services.email_analyzer import analyze_email
from app.services.risk_engine import RiskAssessment, assess, indicator_points
from app.services.ssrf_guard import Resolver, SafeFetcher, default_resolver
from app.services.threat_intelligence import ProviderRunner
from app.services.url_analyzer import analyze_url
from app.services.url_normalizer import normalize_url


class ScanService:
    def __init__(self, settings: Settings, runner: ProviderRunner | None = None,
                 ai: AIProvider | None = None, resolver: Resolver = default_resolver,
                 fetcher: SafeFetcher | None = None):
        self.settings = settings
        self.runner = runner or ProviderRunner([], settings.provider_timeout_s)
        self.ai = ai
        self.resolver = resolver
        self.fetcher = fetcher or SafeFetcher(resolver=resolver, timeout=settings.fetch_timeout_s,
                                              max_redirects=settings.fetch_max_redirects,
                                              max_bytes=settings.fetch_max_bytes)

    # ---- URL ----
    def scan_url(self, raw_url: str) -> ScanReport:
        t0 = time.monotonic()
        n = normalize_url(raw_url, self.settings.max_url_length)     # raises InvalidURL
        analysis = analyze_url(n, dns_enabled=self.settings.dns_enabled, resolver=self.resolver)

        # threat intelligence (real or labelled mock; none configured => honestly "not run")
        if self.runner.providers:
            analysis.sources.extend(self.runner.run(n))
            analysis.checks["intel"] = ("completed" if any(
                s.status in (SourceStatus.POSITIVE, SourceStatus.NEGATIVE) and not s.is_mock for s in analysis.sources)
                else "unavailable")
        else:
            analysis.sources.append(SourceResult("Threat intelligence", SourceStatus.NOT_RUN,
                                                 "No reputation provider configured."))
            analysis.checks["intel"] = "not_run"

        chain: list[str] = []
        if self.settings.fetch_enabled:
            res = self.fetcher.fetch(n.normalized)
            chain = res.hops
            if res.blocked:
                analysis.sources.append(SourceResult("Safe page fetch", SourceStatus.UNAVAILABLE, res.error))
                analysis.checks["fetch"] = "unavailable"
            elif res.error:
                analysis.sources.append(SourceResult("Safe page fetch", SourceStatus.UNAVAILABLE, res.error))
                analysis.checks["fetch"] = "unavailable"
            else:
                analysis.checks["fetch"] = "completed"
                analysis.sources.append(SourceResult("Safe page fetch", SourceStatus.NEGATIVE,
                                                     f"HTTP {res.status}, {len(res.hops)} hop(s)."))
                self._inspect_page(analysis, res.body_snippet, n.registered_domain, res.hops)
        else:
            analysis.sources.append(SourceResult("Safe page fetch", SourceStatus.NOT_RUN,
                                                 "Disabled (SCAN_FETCH_ENABLED=false)."))
        return self._finish("url", n.normalized, analysis, "", t0, chain)

    @staticmethod
    def _inspect_page(analysis: Analysis, html: str, reg_domain: str, hops: list[str]) -> None:
        from app.core.models import Indicator, Severity
        import re
        if re.search(r"<input[^>]+type=[\"']?password", html, re.I):
            analysis.indicators.append(Indicator(
                "password_form", "Page contains a password field", Severity.MEDIUM,
                "A login form on a page you reached from a link is the main way credentials are stolen.",
                "found <input type=password> in the first part of the page", "fetch", 0.5, "credential_form"))
        if len(hops) >= 4:
            analysis.indicators.append(Indicator(
                "long_redirect_chain", "Long redirect chain", Severity.LOW,
                "Many hops can hide the final destination.", f"{len(hops)} URLs visited", "fetch", 0.5, "redirects"))

    # ---- Email ----
    def scan_email(self, text: str, headers: str = "") -> ScanReport:
        t0 = time.monotonic()
        if len(text) > self.settings.max_email_chars:
            raise ValueError("Email text is too long.")
        analysis = analyze_email(text, headers, dns_enabled=False)
        analysis.sources.append(SourceResult("SPF/DKIM/DMARC verification", SourceStatus.NOT_RUN,
                                             "PhishLens does not verify these itself; it only reads a pasted "
                                             "Authentication-Results header, if any."))
        digest = hashlib.sha256(text.encode("utf-8", "ignore")).hexdigest()[:12]
        return self._finish("email", f"email (not stored, sha256:{digest})", analysis, text, t0, [])

    # ---- shared ----
    def _finish(self, kind: str, target: str, analysis: Analysis, excerpt: str, t0: float,
                chain: list[str]) -> ScanReport:
        risk = assess(analysis, self.settings)
        try:
            exp = ai_service.explain(self.ai, kind, analysis, risk.score, risk.verdict, excerpt,
                                     self.settings.ai_max_input_chars)
        except AIUnavailable:
            exp = ai_service.rule_based_summary(analysis, risk.score, risk.verdict)
        by_id = {l.indicator_id: l for l in risk.breakdown}
        return ScanReport(
            scan_id=uuid.uuid4().hex, kind=kind,
            created_at=datetime.now(timezone.utc).isoformat(timespec="seconds"),
            duration_ms=int((time.monotonic() - t0) * 1000), target=target,
            score=risk.score, verdict=risk.verdict.value, confidence=risk.confidence,
            indicators=[IndicatorOut(id=i.id, title=i.title, severity=i.severity.value, explanation=i.explanation,
                                     evidence=i.evidence, provenance=i.provenance, reliability=i.reliability,
                                     points=indicator_points(i), counted=by_id[i.id].counted)
                        for i in analysis.indicators],
            sources=[SourceOut(name=s.name, status=s.status.value, detail=s.detail, is_mock=s.is_mock)
                     for s in analysis.sources],
            unknowns=risk.unknowns, notes=risk.notes, explanation=AIOut(**exp.model_dump()),
            redirect_chain=chain)
