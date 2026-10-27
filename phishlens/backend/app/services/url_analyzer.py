"""Deterministic URL checks. Every indicator carries the concrete evidence seen.

Nothing here claims facts we did not observe: DNS results come from a real
lookup (or are reported unavailable); domain age/WHOIS is NOT checked in the MVP
and is listed as an unavailable source rather than guessed.
"""
from __future__ import annotations

import re
import unicodedata
from urllib.parse import parse_qsl

from app.core.models import Analysis, Indicator, Severity, SourceResult, SourceStatus
from app.services.ssrf_guard import Resolver, default_resolver, ip_block_reason
from app.services.url_normalizer import NormalizedURL

# brand -> legitimate registered domains (small demo list; extend as needed)
BRANDS: dict[str, set[str]] = {
    "paypal": {"paypal.com", "paypal.me"},
    "google": {"google.com", "google.co.in", "gmail.com", "goo.gl", "youtube.com"},
    "microsoft": {"microsoft.com", "live.com", "office.com", "outlook.com", "microsoftonline.com"},
    "apple": {"apple.com", "icloud.com"},
    "amazon": {"amazon.com", "amazon.in", "amazon.co.uk", "amazonaws.com"},
    "facebook": {"facebook.com", "fb.com"},
    "instagram": {"instagram.com"},
    "netflix": {"netflix.com"},
    "whatsapp": {"whatsapp.com", "whatsapp.net"},
    "linkedin": {"linkedin.com"},
    "github": {"github.com", "github.io"},
    "paytm": {"paytm.com"},
    "phonepe": {"phonepe.com"},
    "sbi": {"sbi.co.in", "onlinesbi.sbi", "sbi.bank.in"},
    "hdfcbank": {"hdfcbank.com"},
    "icicibank": {"icicibank.com"},
    "dhl": {"dhl.com"},
    "fedex": {"fedex.com"},
}

RISKY_TLDS = {"tk", "ml", "ga", "cf", "gq", "top", "xyz", "click", "zip", "mov", "work",
              "support", "rest", "country", "kim", "loan", "men", "icu", "cyou", "sbs"}
SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly",
              "rebrand.ly", "cutt.ly", "shorturl.at", "tiny.cc", "rb.gy"}
KEYWORDS = ("login", "signin", "sign-in", "verify", "verification", "secure", "account",
            "update", "password", "banking", "wallet", "confirm", "suspend", "unlock", "otp", "billing")

_LEET = str.maketrans({"0": "o", "1": "l", "3": "e", "4": "a", "5": "s", "7": "t", "$": "s"})


def _edit_distance_le(a: str, b: str, limit: int = 1) -> bool:
    if abs(len(a) - len(b)) > limit:
        return False
    # simple DP; strings are short
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[-1] <= limit


def _scripts(text: str) -> set[str]:
    out = set()
    for ch in text:
        if ch.isalpha():
            name = unicodedata.name(ch, "")
            out.add(name.split(" ")[0] if name else "UNKNOWN")
    return out


def check_brand(n: NormalizedURL) -> Indicator | None:
    """Brand impersonation: brand name inside a host that is not the brand's domain,
    or a registered label that is a near-miss (typosquat / leetspeak) of a brand."""
    if n.is_ip:
        return None
    reg = n.registered_domain
    reg_label = reg.split(".")[0]
    if any(reg in legit for legit in BRANDS.values()):
        return None  # genuinely a known brand's own domain
    labels = n.host.split(".")
    tokens = {t for l in labels for t in l.split("-")}
    deleet = reg_label.translate(_LEET)
    for brand, legit in BRANDS.items():
        if brand in tokens or (len(brand) >= 6 and any(brand in l for l in labels)):
            return Indicator(
                id="brand_impersonation", title=f"Mentions '{brand}' but is not the official domain",
                severity=Severity.HIGH, provenance="rule", reliability=0.85, group="impersonation",
                explanation="Attackers put a trusted brand name in the host to look legitimate. The real site "
                            f"would use one of: {', '.join(sorted(legit))}.",
                evidence=f"host '{n.host}' (registered domain '{reg}')")
        near = deleet == brand or (len(brand) >= 6 and _edit_distance_le(deleet, brand, 1))
        if near and reg_label != brand:
            return Indicator(
                id="brand_lookalike", title=f"Look-alike of '{brand}'",
                severity=Severity.HIGH, provenance="rule", reliability=0.8, group="impersonation",
                explanation="The domain differs from a well-known brand by a character or two (typosquatting "
                            "or number-for-letter swaps).",
                evidence=f"'{reg_label}' is within one edit of '{brand}' (registered domain '{reg}')")
    # punycode that decodes to something close to a brand
    if n.is_punycode:
        uni = n.unicode_host.split(".")[-2] if "." in n.unicode_host else n.unicode_host
        folded = unicodedata.normalize("NFKD", uni).encode("ascii", "ignore").decode()
        for brand in BRANDS:
            if folded and _edit_distance_le(folded, brand, 1) and len(brand) >= 5:
                return Indicator(
                    id="idn_homoglyph", title=f"Internationalised look-alike of '{brand}'",
                    severity=Severity.HIGH, provenance="rule", reliability=0.85, group="impersonation",
                    explanation="Non-ASCII characters can imitate letters of a trusted brand.",
                    evidence=f"'{n.unicode_host}' (encoded as '{n.host}') resembles '{brand}' after removing accents")
    return None


def analyze_url(n: NormalizedURL, *, dns_enabled: bool = True,
                resolver: Resolver = default_resolver) -> Analysis:
    a = Analysis()
    add = a.indicators.append
    a.checks["lexical"] = "completed"

    if n.scheme == "http":
        add(Indicator("no_https", "Connection is not encrypted (http)", Severity.LOW,
                      "Pages that ask for logins or payments should use HTTPS. Plain http can be read or altered "
                      "in transit. Many legitimate sites also use https, so this alone is weak evidence.",
                      f"scheme is http{' (assumed: you did not type a scheme)' if n.assumed_scheme else ''}",
                      "rule", 0.5, "transport"))
    if n.is_ip:
        add(Indicator("ip_host", "Address uses a raw IP instead of a domain name", Severity.HIGH,
                      "Legitimate services almost always use a domain name. IP-only links are a common way to avoid "
                      "domain reputation checks.", f"host is {n.ip}" + (" written in an obfuscated form" if n.ip_obfuscated else ""),
                      "rule", 0.8, "ip_host"))
        reason = ip_block_reason(n.ip or "")
        if reason:
            add(Indicator("private_ip_target", "Points at a non-public address", Severity.MEDIUM,
                          "This address is not reachable from the public internet. Scanner will not contact it.",
                          f"{n.ip}: {reason}", "rule", 0.9, "ip_host"))
    if n.has_userinfo:
        add(Indicator("userinfo_trick", "URL contains '@' / embedded credentials", Severity.HIGH,
                      "Text before '@' is ignored by browsers when choosing the server, so attackers write a trusted "
                      "name first and hide the real host after it.", f"real host is '{n.host}'", "rule", 0.85, "userinfo"))
    if n.is_punycode:
        add(Indicator("punycode", "Internationalised (punycode) domain name", Severity.MEDIUM,
                      "Domains starting with 'xn--' encode non-English characters, which can mimic Latin letters.",
                      f"{n.host} displays as {n.unicode_host}", "rule", 0.6, "idn"))
    if not n.is_ip and len(_scripts(n.unicode_host.replace(".", "").replace("-", ""))) > 1:
        add(Indicator("mixed_scripts", "Host mixes alphabets (e.g. Latin + Cyrillic)", Severity.HIGH,
                      "Mixing scripts in one name is a classic homograph attack technique.",
                      f"scripts found: {', '.join(sorted(_scripts(n.unicode_host)))}", "rule", 0.85, "idn"))
    if n.tld in RISKY_TLDS:
        add(Indicator("risky_tld", f"Top-level domain .{n.tld} is frequently abused", Severity.LOW,
                      "Some cheap or free TLDs are over-represented in abuse reports. Many sites on them are harmless, "
                      "so this only raises suspicion slightly.", f"TLD is .{n.tld}", "rule", 0.4, "tld"))
    if n.registered_domain in SHORTENERS:
        add(Indicator("shortener", "Link shortener hides the real destination", Severity.MEDIUM,
                      "You cannot see where this goes until it is followed. Treat as unknown destination.",
                      f"{n.registered_domain}", "rule", 0.6, "shortener"))
    if n.port and n.port not in (80, 443):
        add(Indicator("odd_port", "Non-standard port", Severity.LOW,
                      "Phishing kits are sometimes hosted on unusual ports.", f"port {n.port}", "rule", 0.5, "port"))
    brand = check_brand(n)
    if brand:
        add(brand)
    depth = len(n.subdomain.split(".")) if n.subdomain else 0
    if depth >= 3:
        add(Indicator("deep_subdomain", "Unusually many subdomain levels", Severity.LOW,
                      "Long subdomain chains push the real domain to the end where users do not look.",
                      f"{depth} levels before '{n.registered_domain}'", "rule", 0.5, "subdomain"))
    hy = n.host.replace("xn--", "").count("-")
    if hy >= 3:
        add(Indicator("many_hyphens", "Host name contains many hyphens", Severity.LOW,
                      "Strings like 'secure-account-verify-login' are typical of generated phishing domains.",
                      f"{hy} hyphens in '{n.host}'", "rule", 0.5, "subdomain"))
    host_kw = [k for k in KEYWORDS if k in n.host]
    path_kw = [k for k in KEYWORDS if k in (n.path + "?" + n.query).lower()]
    if host_kw:
        add(Indicator("credential_keywords_host", "Host contains credential/payment words", Severity.MEDIUM,
                      "Words like login/verify/secure in the domain are used to look official.",
                      f"keywords in host: {', '.join(host_kw)}", "rule", 0.55, "keywords"))
    elif path_kw:
        add(Indicator("credential_keywords_path", "Path or query contains credential/payment words", Severity.LOW,
                      "Many real sites have a /login page, so this is weak on its own.",
                      f"keywords in path/query: {', '.join(path_kw)}", "rule", 0.35, "keywords"))
    for k, v in parse_qsl(n.query, keep_blank_values=True):
        if re.match(r"https?://", v, re.I) or re.match(r"https?%3a", v, re.I):
            add(Indicator("embedded_url", "Another URL is embedded in the query string", Severity.MEDIUM,
                          "Open-redirect style links use a trusted site to bounce you to another address.",
                          f"parameter '{k}' contains a URL", "rule", 0.55, "redirect_param"))
            break
    if len(n.normalized) > 200:
        add(Indicator("long_url", "Very long URL", Severity.LOW,
                      "Long URLs can hide the important part or carry tracking/obfuscated data.",
                      f"{len(n.normalized)} characters", "rule", 0.3, "length"))

    # --- DNS (real lookup, or honest "unavailable") ---
    a.sources.append(SourceResult("WHOIS / domain age", SourceStatus.NOT_RUN,
                                  "Not implemented in the MVP; no domain-age claims are made."))
    if n.is_ip:
        a.checks["dns"] = "not_run"
    elif not dns_enabled:
        a.checks["dns"] = "not_run"
        a.sources.append(SourceResult("DNS", SourceStatus.NOT_RUN, "DNS lookups disabled by configuration."))
    else:
        try:
            ips = resolver(n.host, 443)
            a.checks["dns"] = "completed"
            a.sources.append(SourceResult("DNS", SourceStatus.NEGATIVE, f"Resolved to {len(ips)} address(es)."))
            blocked = [ip for ip in ips if ip_block_reason(ip)]
            if blocked:
                add(Indicator("resolves_private", "Domain resolves to a non-public address", Severity.MEDIUM,
                              "Public sites should not resolve to internal addresses; this can indicate misconfiguration "
                              "or an attempt to target internal systems. The scanner will not fetch it.",
                              f"{blocked[0]}: {ip_block_reason(blocked[0])}", "dns", 0.85, "dns"))
        except OSError as exc:
            # gaierror = name not found; anything else (timeout) = unavailable
            import socket
            if isinstance(exc, socket.gaierror) and exc.errno in (socket.EAI_NONAME, getattr(socket, "EAI_NODATA", -5)):
                a.checks["dns"] = "completed"
                a.sources.append(SourceResult("DNS", SourceStatus.NEGATIVE, "Domain name does not exist."))
                add(Indicator("nxdomain", "Domain does not resolve", Severity.LOW,
                              "The name has no DNS records right now: it may be mistyped, expired, or taken down.",
                              f"no DNS answer for {n.host}", "dns", 0.6, "dns"))
            else:
                a.checks["dns"] = "unavailable"
                a.sources.append(SourceResult("DNS", SourceStatus.UNAVAILABLE, "Lookup failed or timed out."))
    return a
