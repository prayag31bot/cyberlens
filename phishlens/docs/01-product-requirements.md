# PhishLens — Product Requirements (Phase 1)

Name suggestion: **PhishLens** ("see what a link or email really is"). Easy to say, no trademark claim made — check availability before public launch.

## 1. Reference-site analysis (what was actually verified)

Source: the public home page of https://phishscan.io/, fetched on 2026-10-25. **Only the home page was read.** Its feature, about, FAQ, pricing and guide pages were *not* opened, so anything about them below is limited to what the home page itself says (links, pricing cards, copy).

### Verified from the public home page
- **Navigation:** Check, Domains, Mail Gateway, Pricing, Resources, Sign in, language switch (EN/UA).
- **Input modes (tabs):** URL, Email text, File .eml, QR code. Example chips: "PayPal lookalike", "Shortened link", "Fake invoice site". Also advertises forwarding a suspicious email to a mailbox.
- **Result presentation (sample cards):** verdict label + 0–100 score (PHISHING 94, SUSPICIOUS 58, SAFE 8) with bullet indicators (free TLD, domain age, no valid SSL, brand spoofing, redirect chain, URL shortener, tracking parameters, SPF/DKIM pass, clean VirusTotal).
- **Advertised checks:** AI verdict on email text; SPF/DKIM/DMARC and Received chain; WHOIS and DNS; redirect following; malware scanning (VirusTotal, ClamAV, YARA); GeoIP; score with breakdown.
- **Claimed stats (self-reported, unverified):** 437K+ threats tracked, 12 intelligence sources, ~25 s full check with AI (1–7 s local), 24/7 Certificate-Transparency monitoring ("live certificate radar").
- **Other product lines:** domain monitoring / lookalike detection, DMARC monitoring, mail gateway, sandbox.
- **Accounts & pricing:** no signup needed to check; account for history and domain monitoring. Free (5 checks/day, 7-day history), Pro $19/mo, Business $49/mo, Enterprise from $149/mo.
- **Footer / trust pages:** Privacy, Security, Terms, Cookies, Status, guides, blog, quizzes. Cookie banner with "Essential only / Allow all".
- **Visual style:** dark navy theme (`theme-color #0f1a35`), card-based layout, severity-labelled indicator lists, 4-step "How it works" strip, pricing cards with a "most popular" badge.

### Not verifiable (do not assume)
Backend language, framework, database, AI prompts/model, exact scoring rules, loading/error/empty-state designs, and responsive breakpoints. The page text does not establish them, and I did not render it in a browser. If you want those documented, send screenshots at mobile/tablet/desktop widths.

## 2. Feature comparison

| Feature | Reference behavior (home page) | Our MVP | External dependency | Status |
|---|---|---|---|---|
| URL scan | Paste link, 0–100 score, indicators | Same, rules-based + optional AI | DNS (stdlib) | **Built (backend core)** |
| Verdicts | Phishing / Suspicious / Safe | Adds UNKNOWN, never "safe" from silence | none | **Built** |
| Email text scan | AI + checks | Rules + optional Claude | Anthropic API key | **Built (rules)**; AI adapter written, untested live |
| Email headers SPF/DKIM/DMARC | Advertised | Parses *supplied* Authentication-Results only; labels "not verified" otherwise | none | **Built** |
| .eml upload | Advertised | Designed, not built | — | Planned |
| QR code | Advertised | Designed, not built | QR decoder lib | Planned |
| Redirect following | Advertised | Safe fetcher design with per-hop SSRF check | HTTP client | Guard built; fetcher planned |
| WHOIS / domain age | Advertised | Adapter interface only | RDAP/WHOIS provider | Planned (unavailable shown honestly) |
| Threat intel (VirusTotal etc.) | "12 sources" | Adapter interface + labelled mock | Provider API keys, ToS check | Interface + mock only |
| Malware scan / sandbox | Advertised | Out of scope | — | Not planned |
| CT-log radar, domain monitoring | Advertised | Out of scope for MVP | — | Roadmap |
| Accounts, history, quotas | Free/Pro tiers | Optional accounts, history, delete | PostgreSQL | Designed (Phase 7) |
| PDF report | Advertised | Copy/export JSON + print view | — | Planned |
| Frontend (Next.js) | — | Landing, scan, results | Node | Phase 3 (not started) |

## 3. MVP scope

**In:** URL scanner, pasted-email analyzer (+ optional headers), explainable risk engine, SSRF-safe network layer, AI explanation with rules-only fallback, results page, optional accounts/history, rate limits.
**Out for MVP:** attachment sandboxing, malware scanning, CT-log monitoring, mail gateway, payments.

## 4. Differentiators (student-realistic)
1. Every indicator carries evidence + provenance (`rule`, `provider:x`, `header`, `unavailable`).
2. Score breakdown lists **unknowns** explicitly; missing data lowers confidence, never raises "safe".
3. Privacy-first mode: scan without saving; emails are never stored in full, only hashes and indicator summaries.

## 5. Key requirements
- Verdict thresholds configurable; score is an internal risk estimate, not a probability.
- No blocklist hit ≠ safe. Unavailable provider ≠ negative match.
- Scanned content is untrusted data, including for the LLM (prompt-injection safe).
- No fabricated technical facts (domain age, certs, DNS) from the AI.
