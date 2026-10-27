"""Threat-intelligence adapter layer.

IMPORTANT HONESTY NOTE: only `MockProvider` is implemented. No real provider
(VirusTotal, Google Safe Browsing, URLhaus, OpenPhish) is integrated yet. Each
needs an API key and a review of its current terms/rate limits first (see
docs/threat-intel-adapters.md). Mock results are always flagged `is_mock=True`.
"""
from __future__ import annotations

import time
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FuturesTimeout
from typing import Protocol

from app.core.models import SourceResult, SourceStatus
from app.services.url_normalizer import NormalizedURL


class ThreatProvider(Protocol):
    name: str
    is_mock: bool

    def lookup(self, n: NormalizedURL) -> SourceResult: ...


class MockProvider:
    """Deterministic test provider. Hosts ending in '.phishlens-test.invalid' or
    'mock-malicious.test' are reported positive; everything else negative."""
    name = "MockIntel (test data)"
    is_mock = True
    POSITIVE_SUFFIXES = (".phishlens-test.invalid", "mock-malicious.test")

    def lookup(self, n: NormalizedURL) -> SourceResult:
        if n.host.endswith(self.POSITIVE_SUFFIXES):
            return SourceResult(self.name, SourceStatus.POSITIVE, "Listed in mock test feed.", is_mock=True)
        return SourceResult(self.name, SourceStatus.NEGATIVE, "Not in mock test feed.", is_mock=True)


class CircuitBreaker:
    """Open after `threshold` consecutive failures; retry after `reset_s`."""
    def __init__(self, threshold: int = 3, reset_s: float = 60.0, clock=time.monotonic):
        self.threshold, self.reset_s, self.clock = threshold, reset_s, clock
        self.failures = 0
        self.opened_at: float | None = None

    @property
    def is_open(self) -> bool:
        if self.opened_at is None:
            return False
        if self.clock() - self.opened_at >= self.reset_s:
            self.opened_at, self.failures = None, 0   # half-open: allow a retry
            return False
        return True

    def record(self, ok: bool) -> None:
        if ok:
            self.failures, self.opened_at = 0, None
        else:
            self.failures += 1
            if self.failures >= self.threshold:
                self.opened_at = self.clock()


class ProviderRunner:
    def __init__(self, providers: list[ThreatProvider], timeout_s: float = 4.0):
        self.providers = providers
        self.timeout_s = timeout_s
        self.breakers = {p.name: CircuitBreaker() for p in providers}

    def run(self, n: NormalizedURL) -> list[SourceResult]:
        if not self.providers:
            return []
        results: dict[str, SourceResult] = {}
        pool = ThreadPoolExecutor(max_workers=len(self.providers))
        futures = {}
        for p in self.providers:
            if self.breakers[p.name].is_open:
                results[p.name] = SourceResult(p.name, SourceStatus.UNAVAILABLE,
                                               "Temporarily skipped after repeated failures.", p.is_mock)
            else:
                futures[p.name] = (p, pool.submit(p.lookup, n))
        for name, (p, fut) in futures.items():
            try:
                results[name] = fut.result(timeout=self.timeout_s)
                self.breakers[name].record(True)
            except FuturesTimeout:
                results[name] = SourceResult(name, SourceStatus.UNAVAILABLE, "Timed out.", p.is_mock)
                self.breakers[name].record(False)
            except Exception:  # provider bug/outage must never crash a scan
                results[name] = SourceResult(name, SourceStatus.UNAVAILABLE, "Provider error.", p.is_mock)
                self.breakers[name].record(False)
        pool.shutdown(wait=False, cancel_futures=True)
        return [results[p.name] for p in self.providers]
