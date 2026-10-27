# API reference and risk-scoring policy

Interactive docs once running: `http://localhost:8000/api/docs`.
All responses carry `X-Request-ID`. Errors always look like `{"error": {"code", "message", "request_id"}}`; stack traces never leave the server.

## Endpoints (implemented in `app/main.py`)
| Method + path | Purpose | Auth | Limits | Status codes |
|---|---|---|---|---|
| `GET /api/v1/health` | Liveness, shows whether AI/fetch are configured | none | none | 200 |
| `POST /api/v1/scans/url` | Scan a URL | none (MVP) | 10 POST scans/min/IP (configurable) | 200, 422 `invalid_url`/validation, 429, 500 |
| `POST /api/v1/scans/email` | Scan pasted email text (+ optional headers) | none (MVP) | same | 200, 422, 429, 500 |
| `GET /api/v1/scans/{id}` | Fetch a saved report (only scans made with `privacy_mode=false`) | none (MVP, id is unguessable 128-bit) | — | 200, 404 |

**Planned (not built):** `GET /api/v1/scans` (history), `DELETE /api/v1/scans/{id}`, auth routes. Those need user accounts (Phase 7); until then there is no per-user access control to document or test.

### Example
```http
POST /api/v1/scans/url
{"url": "http://secure-login-paypal.tk/verify", "privacy_mode": true}
```
Response (shape; values from a real run of the code with a stubbed DNS resolver and no AI key):
```json
{"scan_id":"…","kind":"url","verdict":"SUSPICIOUS","score":51,"confidence":"medium",
 "indicators":[{"id":"brand_impersonation","severity":"high","evidence":"host 'secure-login-paypal.tk' …","counted":true,"points":34.0}, "…"],
 "sources":[{"name":"WHOIS / domain age","status":"not_run"},{"name":"DNS","status":"negative"},{"name":"Threat intelligence","status":"not_run"}, "…"],
 "unknowns":["intel: not run","WHOIS / domain age: not_run (…)","Threat intelligence: not_run (No reputation provider configured.)","Safe page fetch: not_run (…)"],
 "explanation":{"source":"rules","summary":"Some concerning signs were found (risk score 51/100). …"},
 "limitations":"PhishLens combines rule-based checks … not a probability …"}
```
Validation: URL 1–2048 chars, only http/https, no control chars; email text 1–20 000 chars.

## Risk scoring policy
1. Each indicator has a **severity** and **reliability** (0–1). Points = base × reliability, base: info 0, low 8, medium 18, high 40, critical 60.
2. **Correlated signals share a `group`**; only the highest-point one counts (e.g. punycode + mixed scripts). The breakdown shows uncounted ones with the reason.
3. Score = sum over groups, capped at 100.
4. **Trusted, non-mock provider positive** → score floored at 85 → PHISHING. A *mock* positive does the same but is labelled "MOCK … test data".
5. Verdict: ≥65 PHISHING, ≥30 SUSPICIOUS (both configurable via env). Below that: SAFE only if at least `RISK_MIN_REAL_CHECKS_FOR_SAFE` real checks (DNS, real intel) completed; otherwise UNKNOWN.
6. **Confidence** = evidence strength (how many real checks finished), not accuracy. Unavailable/not-run sources are listed under `unknowns` and never count as "clean".
7. Conflict rule: concerning rule signals + a clean reputation source → rules stand, with an explicit note (new phishing pages are often not listed yet).
8. The score is an internal estimate, **not** a probability. No accuracy percentage is claimed anywhere; none has been measured.

Weights are hand-set heuristics, not trained or calibrated on data. Lexical signals alone rarely exceed SUSPICIOUS except strong homograph/lookalike combinations; that is deliberate.
