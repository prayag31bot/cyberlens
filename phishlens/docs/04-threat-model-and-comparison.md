# Threat model, limitations and comparison

## Security controls: built vs planned
| Threat | Control | Status |
|---|---|---|
| SSRF via URL | public-IP-only, resolved-IP validation, ports 80/443, IP pinning, per-hop redirect checks, size/time/redirect caps | **Built + unit-tested with fake DNS/HTTP**; not tested against real servers |
| DNS rebinding | validate then connect to the validated IP; any bad record blocks | Built + tested |
| Cloud metadata (169.254.169.254) | link-local blocked incl. via redirect and IPv4-mapped IPv6 | Built + tested |
| Worker egress | network-level allow-list | **Planned** (infra, not code) |
| Prompt injection | data tags, tag-escape neutralised, schema validation, AI cannot alter score | Built; tested with fake model only |
| Secret leakage | env vars only; errors generic; no email body in report or logs | Built; `.env` is git-ignored |
| XSS in reports | API returns JSON only with CSP `default-src 'none'`; frontend must escape (React does by default) | API built; frontend pending |
| Abuse / cost | per-IP rate limit (in-memory), 1 AI call per scan, token cap | Built (single instance only) |
| SQLi / IDOR / CSRF / sessions | ORM, ownership checks, SameSite cookies | **Planned with accounts** |
| Malware / attachments | not handled; files are never accepted or executed | Out of scope |

Known limitations: no WHOIS/domain age, no real threat-intel provider, no QR/.eml, no live page rendering, brand list is a small demo list, public-suffix handling is a short built-in list, rate limiter is per-process, and the AI path is untested against the real API. The HTTP layer (`main.py`) has not been run yet.

## PhishLens vs a general-purpose AI chatbot
| Aspect | General chatbot | PhishLens (as built today) |
|---|---|---|
| Live DNS / reputation lookups | Only if given tools | DNS yes; reputation **mock only** until providers are added |
| Repeatable output | Wording and judgement can vary | Same input → same rule-based score and breakdown |
| Evidence-linked reasons | Free text | Each indicator has evidence + provenance + points |
| Explicit unknowns | Not guaranteed | Listed in every report |
| Batch / API / history | Not by default | API yes; batch and history planned |
| Privacy controls | Provider policy | Default no-save mode; email bodies never stored |
| Cost / ease | Free-form, flexible | Narrow tool, needs hosting |
A chatbot can analyse pasted text well and may beat this MVP on nuanced email wording. The honest value is *evidence + repeatability + workflow*, not "smarter". No head-to-head accuracy test has been run.

Target users: non-technical people checking a link; students/SMBs without a security team. Limits: not a replacement for a mail gateway, EDR or professional analysis.
