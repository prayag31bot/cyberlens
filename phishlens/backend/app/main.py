"""FastAPI entry point. Run: uvicorn app.main:app --reload
NOTE: written to match FastAPI's API but not executed in the build sandbox (FastAPI could not be
installed there). The logic it calls (ScanService) is covered by tests; run `pytest` locally to
also exercise the HTTP layer (app/tests/test_api.py, skipped automatically if FastAPI is missing)."""
from __future__ import annotations

import logging
import uuid

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse

from app.core.config import Settings
from app.core.rate_limit import RateLimiter
from app.schemas.scan import EmailScanRequest, ScanReport, UrlScanRequest
from app.services.ai_service import ClaudeProvider
from app.services.scan_service import ScanService
from app.services.threat_intelligence import MockProvider, ProviderRunner
from app.services.url_normalizer import InvalidURL

log = logging.getLogger("phishlens")


def create_app(settings: Settings | None = None, service: ScanService | None = None) -> FastAPI:
    settings = settings or Settings.from_env()
    if service is None:
        ai = (ClaudeProvider(settings.anthropic_api_key, settings.anthropic_model, settings.ai_max_tokens,
                             settings.ai_timeout_s) if settings.anthropic_api_key else None)
        import os
        providers = [MockProvider()] if os.environ.get("ENABLE_MOCK_INTEL", "false").lower() == "true" else []
        service = ScanService(settings, ProviderRunner(providers, settings.provider_timeout_s), ai)
    limiter = RateLimiter(settings.rate_limit_per_minute)
    store: dict[str, ScanReport] = {}   # MVP in-memory store (only for non-private scans); DB in Phase 7

    app = FastAPI(title="PhishLens API", version="0.1.0", docs_url="/api/docs", openapi_url="/api/openapi.json")

    @app.middleware("http")
    async def common(request: Request, call_next):
        rid = uuid.uuid4().hex[:12]
        request.state.request_id = rid
        ip = request.client.host if request.client else "unknown"
        if request.url.path.startswith("/api/v1/scans") and request.method == "POST" and not limiter.allow(ip):
            return JSONResponse({"error": {"code": "rate_limited", "message": "Too many scans. Try again in a minute.",
                                           "request_id": rid}}, status_code=429, headers={"Retry-After": "60"})
        try:
            resp = await call_next(request)
        except Exception:
            log.exception("unhandled error request_id=%s", rid)   # details stay in server logs only
            resp = JSONResponse({"error": {"code": "internal_error", "message": "Something went wrong.",
                                           "request_id": rid}}, status_code=500)
        resp.headers["X-Request-ID"] = rid
        resp.headers["X-Content-Type-Options"] = "nosniff"
        resp.headers["Referrer-Policy"] = "no-referrer"
        resp.headers["Content-Security-Policy"] = "default-src 'none'; frame-ancestors 'none'"
        return resp

    def err(code: str, msg: str, status: int, request: Request):
        return JSONResponse({"error": {"code": code, "message": msg, "request_id": request.state.request_id}},
                            status_code=status)

    @app.get("/api/v1/health")
    def health():
        return {"status": "ok", "ai_configured": bool(settings.anthropic_api_key),
                "fetch_enabled": settings.fetch_enabled}

    @app.post("/api/v1/scans/url", response_model=ScanReport)
    def scan_url(body: UrlScanRequest, request: Request):
        try:
            report = service.scan_url(body.url)
        except InvalidURL as exc:
            return err("invalid_url", str(exc), 422, request)
        if not body.privacy_mode:
            store[report.scan_id] = report
        return report

    @app.post("/api/v1/scans/email", response_model=ScanReport)
    def scan_email(body: EmailScanRequest, request: Request):
        try:
            report = service.scan_email(body.text, body.headers)
        except ValueError as exc:
            return err("invalid_input", str(exc), 422, request)
        if not body.privacy_mode:
            store[report.scan_id] = report      # report holds indicators only, never the email body
        return report

    @app.get("/api/v1/scans/{scan_id}", response_model=ScanReport)
    def get_scan(scan_id: str, request: Request):
        r = store.get(scan_id)
        if not r:
            return err("not_found", "Scan not found.", 404, request)
        return r

    return app


app = create_app()
