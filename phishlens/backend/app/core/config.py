"""Central configuration. Everything is read from environment variables so no
secret or tunable value is hardcoded. See .env.example."""
from __future__ import annotations

import os
from dataclasses import dataclass


def _int(name: str, default: int) -> int:
    try:
        return int(os.environ.get(name, default))
    except ValueError:
        return default


def _bool(name: str, default: bool) -> bool:
    return os.environ.get(name, str(default)).strip().lower() in {"1", "true", "yes", "on"}


@dataclass(frozen=True)
class Settings:
    # --- risk engine thresholds (configurable, see docs/risk-scoring.md) ---
    suspicious_threshold: int = 30
    phishing_threshold: int = 65
    trusted_intel_floor: int = 85
    # how many *real* check categories (dns, intel) must complete before SAFE is allowed
    min_real_checks_for_safe: int = 1

    # --- network safety ---
    dns_enabled: bool = True
    fetch_enabled: bool = False  # live page fetch is OFF by default (safer demo)
    fetch_timeout_s: float = 5.0
    fetch_max_redirects: int = 5
    fetch_max_bytes: int = 200_000
    provider_timeout_s: float = 4.0

    # --- AI ---
    anthropic_api_key: str = ""
    anthropic_model: str = "claude-sonnet-5-5"
    ai_max_tokens: int = 800
    ai_max_input_chars: int = 6000
    ai_timeout_s: float = 20.0

    # --- limits ---
    max_url_length: int = 2048
    max_email_chars: int = 20_000
    rate_limit_per_minute: int = 10

    @classmethod
    def from_env(cls) -> "Settings":
        return cls(
            suspicious_threshold=_int("RISK_SUSPICIOUS_THRESHOLD", 30),
            phishing_threshold=_int("RISK_PHISHING_THRESHOLD", 65),
            trusted_intel_floor=_int("RISK_TRUSTED_INTEL_FLOOR", 85),
            min_real_checks_for_safe=_int("RISK_MIN_REAL_CHECKS_FOR_SAFE", 1),
            dns_enabled=_bool("DNS_ENABLED", True),
            fetch_enabled=_bool("SCAN_FETCH_ENABLED", False),
            fetch_timeout_s=float(os.environ.get("FETCH_TIMEOUT_S", 5)),
            fetch_max_redirects=_int("FETCH_MAX_REDIRECTS", 5),
            fetch_max_bytes=_int("FETCH_MAX_BYTES", 200_000),
            provider_timeout_s=float(os.environ.get("PROVIDER_TIMEOUT_S", 4)),
            anthropic_api_key=os.environ.get("ANTHROPIC_API_KEY", ""),
            anthropic_model=os.environ.get("ANTHROPIC_MODEL", "claude-sonnet-5-5"),
            ai_max_tokens=_int("AI_MAX_TOKENS", 800),
            ai_max_input_chars=_int("AI_MAX_INPUT_CHARS", 6000),
            ai_timeout_s=float(os.environ.get("AI_TIMEOUT_S", 20)),
            max_url_length=_int("MAX_URL_LENGTH", 2048),
            max_email_chars=_int("MAX_EMAIL_CHARS", 20000),
            rate_limit_per_minute=_int("RATE_LIMIT_PER_MINUTE", 10),
        )
