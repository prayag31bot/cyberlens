# PhishLens — Architecture and Diagrams

> The Mermaid diagrams below were written by hand and **not rendered or validated here** (no Mermaid CLI available in the build sandbox). Paste each into https://mermaid.live to check; tell me if any fails and I'll fix it.

## 1. Stack and why
| Layer | Choice | Why (beginner view) |
|---|---|---|
| Frontend | Next.js + TypeScript + Tailwind | Standard, lots of tutorials; **not built yet (Phase 3)** |
| Backend | FastAPI + Pydantic | Automatic validation and `/api/docs` page |
| Analysis core | Plain Python (stdlib) | Easy to test, no heavy deps |
| DB | PostgreSQL + SQLAlchemy/Alembic | Planned Phase 7; MVP currently keeps non-private scans **in memory** |
| Jobs | None in MVP (scans run synchronously, ~1–5 s) | Redis/Celery only needed once page-fetching/sandboxing is slow |
| AI | Claude via `ClaudeProvider` behind an `AIProvider` interface | Swappable; explains, never decides |

Simpler-alternative trade-off: SQLite instead of PostgreSQL and no Celery would be quicker to finish; Postgres/Redis are kept in `docker-compose` because the project brief asks for production-style structure.

## 2. Folder map (what exists today)
```
phishlens/
  backend/app/
    main.py                  FastAPI app, middleware (request id, rate limit, security headers)
    core/  config.py models.py rate_limit.py
    schemas/scan.py          request/response models (Pydantic)
    services/
      url_normalizer.py      validate + canonicalise URL (no network)
      ssrf_guard.py          IP blocking, DNS pinning, SafeFetcher with per-hop checks
      url_analyzer.py        deterministic URL indicators + real DNS lookup
      email_analyzer.py      text/header indicators
      threat_intelligence.py provider interface, MockProvider, timeouts, circuit breaker
      risk_engine.py         scoring policy (pure functions)
      ai_service.py          prompt, schema validation, rules-only fallback
      scan_service.py        orchestration
    tests/                   test_core.py (53 tests), test_api.py (needs FastAPI)
  docs/  infra/  frontend/(empty until Phase 3)
```
Not created yet: `models/` (SQLAlchemy), `repositories/`, `workers/`, `api/routes/` split (routes currently live in `main.py`), auth.

## 3. Diagrams

### A. System context
```mermaid
flowchart LR
  U[User / Browser] --> FE[Next.js Frontend]
  FE -->|REST JSON| API[FastAPI Backend]
  API --> DB[(PostgreSQL)]
  API -->|queue, optional| W[Background Worker]
  API -->|evidence only| AI[Claude API]
  API --> TI[Threat-intel providers]
  API --> DNS[Public DNS]
  W --> DNS
```

### B. Components
```mermaid
flowchart TB
  subgraph Frontend
    SF[ScanForm] --> RV[ResultView]
    RV --> IL[IndicatorList]
    RV --> SB[ScoreBreakdown]
  end
  subgraph Backend
    R[API routes] --> SS[ScanService]
    SS --> UN[UrlNormalizer]
    SS --> UA[UrlAnalyzer]
    SS --> EA[EmailAnalyzer]
    SS --> PR[ProviderRunner]
    SS --> RE[RiskEngine]
    SS --> AIS[AI Service]
    UA --> SG[SSRF Guard]
    PR --> MP[MockProvider]
    PR --> RP[Real providers - planned]
    AIS --> CP[ClaudeProvider]
    SS --> REPO[Repositories - planned]
  end
  SF --> R
  REPO --> PG[(PostgreSQL)]
```

### C. Class diagram
```mermaid
classDiagram
  class ScanService { +scan_url(raw) ScanReport
    +scan_email(text, headers) ScanReport }
  class Indicator { id; title; severity; evidence; provenance; reliability; group }
  class Analysis { indicators; sources; checks }
  class SourceResult { name; status; is_mock; trusted }
  class RiskAssessment { score; verdict; confidence; breakdown; unknowns }
  class ThreatProvider { <<interface>> +lookup(url) SourceResult }
  class MockProvider
  class ProviderRunner { +run(url) list }
  class CircuitBreaker { +record(ok); is_open }
  class AIProvider { <<interface>> +complete(system, user) str }
  class ClaudeProvider
  class SafeFetcher { +fetch(url) FetchResult }
  ScanService --> ProviderRunner
  ScanService --> AIProvider
  ScanService --> SafeFetcher
  ScanService ..> Analysis
  Analysis o-- Indicator
  Analysis o-- SourceResult
  ProviderRunner o-- ThreatProvider
  ProviderRunner o-- CircuitBreaker
  ThreatProvider <|.. MockProvider
  AIProvider <|.. ClaudeProvider
  ScanService ..> RiskAssessment
```

### D. Sequence — URL scan
```mermaid
sequenceDiagram
  actor U as User
  participant F as Frontend
  participant A as API
  participant S as ScanService
  participant P as Providers
  participant C as Claude
  participant D as DB
  U->>F: enter URL, click Scan
  F->>A: POST /api/v1/scans/url
  A->>A: request id, rate limit
  A->>S: scan_url(url)
  S->>S: normalize + validate
  alt invalid
    S-->>A: InvalidURL
    A-->>F: 422 invalid_url
  else valid
    S->>S: lexical checks, DNS lookup
    S->>P: lookup (parallel, timeout)
    P-->>S: positive / negative / unavailable
    S->>S: risk engine score + verdict
    S->>C: evidence only (sanitized)
    alt AI ok and schema valid
      C-->>S: JSON explanation
    else AI fails
      S->>S: rules-only explanation
    end
    opt privacy_mode = false
      S->>D: save minimal report
    end
    S-->>A: ScanReport
    A-->>F: 200 report
  end
  F-->>U: verdict, score, indicators
```

### E. Activity
```mermaid
flowchart TD
  A([Start]) --> B{URL valid?}
  B -- no --> E1[Return 422 with safe message]
  B -- yes --> C[Lexical checks]
  C --> D{DNS ok?}
  D -- timeout --> D1[Mark DNS unavailable]
  D -- ok/NXDOMAIN --> D2[Record DNS result]
  D1 --> F
  D2 --> F[Query providers in parallel]
  F --> G{Each provider}
  G -- timeout/error --> G1[Mark unavailable, open breaker if repeated]
  G -- result --> G2[positive or negative]
  G1 --> H
  G2 --> H[Score with dedup]
  H --> I{Trusted positive?}
  I -- yes --> V1[PHISHING]
  I -- no --> J{score >= phishing?}
  J -- yes --> V1
  J -- no --> K{score >= suspicious?}
  K -- yes --> V2[SUSPICIOUS]
  K -- no --> L{enough real checks?}
  L -- yes --> V3[SAFE with caveat]
  L -- no --> V4[UNKNOWN]
  V1 --> M[AI explanation or rules fallback]
  V2 --> M
  V3 --> M
  V4 --> M
  M --> N([Return report])
```

### F. Use cases
```mermaid
flowchart LR
  V((Visitor)) --> U1[Scan URL]
  V --> U2[Scan email text]
  R((Registered user)) --> U1
  R --> U2
  R --> U3[View history]
  R --> U4[Delete scans]
  AD((Admin)) --> U5[View health and quotas]
  AD --> U6[View provider status]
  U1 -.uses.-> X1[Claude API]
  U1 -.uses.-> X2[Threat-intel providers]
  U1 -.uses.-> X3[DNS]
```
Registration, history and admin views are designed, not implemented.

### G. Entity relationship (planned schema)
```mermaid
erDiagram
  USER ||--o{ SCAN : owns
  SCAN ||--o{ THREAT_INDICATOR : has
  SCAN ||--o{ SOURCE_RESULT : has
  SCAN ||--o| SCAN_REPORT : summarised_by
  USER ||--o{ USAGE_QUOTA : has
  USER ||--o{ AUDIT_EVENT : triggers
  USER { uuid id PK
    string email UK
    string password_hash
    timestamptz created_at }
  SCAN { uuid id PK
    uuid user_id FK
    string kind
    string target_normalized
    string target_sha256
    int score
    string verdict
    string confidence
    int duration_ms
    timestamptz created_at
    timestamptz expires_at }
  THREAT_INDICATOR { uuid id PK
    uuid scan_id FK
    string indicator_id
    string severity
    string evidence
    string provenance
    float reliability
    bool counted }
  SOURCE_RESULT { uuid id PK
    uuid scan_id FK
    string source_name
    string status
    bool is_mock }
  SCAN_REPORT { uuid id PK
    uuid scan_id FK
    json explanation
    string ai_source }
  USAGE_QUOTA { uuid id PK
    uuid user_id FK
    date day
    int scans_used }
  AUDIT_EVENT { uuid id PK
    uuid user_id FK
    string action
    string request_id
    timestamptz created_at }
```
Indexes: `scan(user_id, created_at DESC)`, `scan(expires_at)`, unique `user(email)`, unique `usage_quota(user_id, day)`. Cascade delete from scan to children. **Retention:** email bodies and uploads are never stored (only a SHA-256 prefix); URL scans stored only when `privacy_mode=false`; default expiry 7 days via `expires_at` job.

### H. Deployment
```mermaid
flowchart LR
  B[Browser] --> CDN[Frontend host - Vercel or container]
  CDN --> GW[API container - FastAPI/uvicorn]
  GW --> PG[(Postgres)]
  GW --> RD[(Redis - rate limit and queue)]
  RD --> WK[Worker container - egress-restricted]
  GW --> EXT[Claude and intel APIs]
  WK --> NET[Public internet only via allow-list]
```

### I. Data flow
```mermaid
flowchart LR
  U[URL or email text] --> V[Validate and normalise]
  V --> T[Technical evidence: indicators, DNS, intel]
  T --> S[Risk engine]
  T -->|ids, titles, evidence, truncated excerpt| AI[Claude]
  AI -->|validated JSON| R[Report]
  S --> R
  R --> UI[Results page]
  R -->|if saving allowed: indicators only| DB[(DB)]
```

### J. End-to-end flowchart
```mermaid
flowchart TD
  A[Type URL] --> B[Client checks non-empty and length]
  B --> C[POST to API]
  C --> D[Rate limit check]
  D -- exceeded --> D1[429 Retry-After]
  D -- ok --> E[Normalise and validate]
  E -- invalid --> E1[422]
  E -- ok --> F[Checks and intel]
  F --> G[Score and verdict]
  G --> H[Explain: AI or rules]
  H --> I[200 JSON report]
  I --> J[Render badge, score, indicators, sources, unknowns, limits]
  J --> K[Copy / export / scan another]
```

## 4. AI integration (answers to the brief's questions)
- **Where called:** `ScanService._finish` → `ai_service.explain`, after scoring.
- **Sent:** indicator ids/titles/evidence (≤300 chars each), source statuses, score/verdict, and for emails a control-char-stripped excerpt capped at `AI_MAX_INPUT_CHARS` (default 6000). Never sent: API keys, user identity, stored history.
- **Validation:** JSON extracted, validated with Pydantic (`AIAnalysis`), `evidence_references` filtered to real indicator ids.
- **Failure:** timeout, bad JSON, missing key → `rule_based_summary`, labelled `source: "rules"`.
- **Cost control:** one call per scan, `max_tokens=800`, truncated input, 1 retry, rate limit per IP.
- **Injection defence:** content is wrapped in `<untrusted_data>`; closing tags inside content are neutralised; system prompt forbids following embedded instructions; the AI **cannot change the score or verdict** (so an injection cannot flip a verdict).
- **AI vs deterministic:** deterministic checks produce evidence and the score; the AI only explains and spots wording patterns in email text (shown separately).
- **Not verified:** `ClaudeProvider` has not been run against the live API (no key/network in the sandbox).
