"""Deterministic analysis of pasted email text (+ optional raw headers).

SPF/DKIM/DMARC: we do NOT perform these checks (that needs the original message
and live DNS/crypto). We only *read* an Authentication-Results header if the user
pasted one, and label it "as reported in the supplied header, not verified by
PhishLens" because anyone can forge that header text.
"""
from __future__ import annotations

import re
from email.utils import parseaddr

from app.core.models import Analysis, Indicator, Severity
from app.services.url_analyzer import BRANDS, analyze_url
from app.services.url_normalizer import InvalidURL, normalize_url, split_domain

URL_RE = re.compile(r"https?://[^\s<>\"')\]]+", re.I)
URGENCY = ["urgent", "immediately", "within 24 hours", "within 48 hours", "act now", "final notice",
           "last warning", "account will be suspended", "account will be closed", "account has been locked",
           "suspended", "expires today", "verify now", "limited time", "avoid suspension", "action required"]
CREDENTIALS = ["password", "passcode", "otp", "one-time", "verification code", "pin number", "cvv",
               "card number", "social security", "ssn", "aadhaar", "net banking", "login details", "security question"]
PAYMENT = ["wire transfer", "gift card", "bitcoin", "crypto", "western union", "pay the invoice", "payment overdue",
           "update your payment", "billing information", "refund", "claim your prize", "you have won", "lottery"]
BEC = ["change of bank", "new bank details", "updated bank account", "change our bank", "keep this confidential",
       "are you available", "i need a favor", "do not call", "reply only by email", "urgent wire", "update vendor"]
RISKY_EXT = (".exe", ".scr", ".js", ".vbs", ".bat", ".cmd", ".iso", ".img", ".lnk", ".html", ".htm",
             ".docm", ".xlsm", ".pptm", ".jar", ".msi", ".hta", ".zip", ".rar", ".7z")
AUTH_RE = re.compile(r"\b(spf|dkim|dmarc)\s*=\s*(pass|fail|softfail|neutral|none|temperror|permerror|policy)", re.I)


def _hits(text: str, phrases: list[str]) -> list[str]:
    low = text.lower()
    return [p for p in phrases if p in low]


def _header(headers: str, name: str) -> str:
    m = re.search(rf"^{name}:\s*(.+(?:\r?\n[ \t]+.+)*)", headers, re.I | re.M)
    return re.sub(r"\s+", " ", m.group(1)).strip() if m else ""


def analyze_email(text: str, headers: str = "", *, dns_enabled: bool = False, max_urls: int = 5) -> Analysis:
    a = Analysis()
    add = a.indicators.append
    a.checks["lexical"] = "completed"
    body = text or ""

    u = _hits(body, URGENCY)
    if u:
        add(Indicator("urgency", "Urgency / pressure language", Severity.MEDIUM,
                      "Scammers create time pressure so you act before thinking or verifying.",
                      "phrases: " + ", ".join(u[:5]), "rule", 0.55, "pressure"))
    c = _hits(body, CREDENTIALS)
    if c:
        add(Indicator("credential_request", "Asks for credentials or sensitive data", Severity.HIGH,
                      "Legitimate organisations do not ask for passwords, OTPs or card details by email.",
                      "mentions: " + ", ".join(c[:5]), "rule", 0.7, "sensitive_request"))
    p = _hits(body, PAYMENT)
    if p:
        add(Indicator("payment_request", "Payment, prize or refund pretext", Severity.MEDIUM,
                      "Unexpected payment requests, refunds and prizes are common lures.",
                      "mentions: " + ", ".join(p[:5]), "rule", 0.55, "payment"))
    b = _hits(body, BEC)
    if b:
        add(Indicator("bec_pattern", "Business-email-compromise wording", Severity.HIGH,
                      "Requests to change bank details or keep things confidential are typical of invoice/CEO fraud.",
                      "phrases: " + ", ".join(b[:5]), "rule", 0.65, "payment"))
    att = sorted({m for m in re.findall(r"[\w\-. ]+\.(?:%s)\b" % "|".join(e[1:] for e in RISKY_EXT), body, re.I)})
    if att:
        add(Indicator("risky_attachment", "Mentions a risky attachment type", Severity.MEDIUM,
                      "Executables, scripts, disk images, macro documents and HTML files are common malware carriers.",
                      "file names mentioned: " + ", ".join(att[:4]), "rule", 0.6, "attachment"))

    # ---- sender / reply-to ----
    frm = _header(headers, "From") if headers else ""
    reply = _header(headers, "Reply-To") if headers else ""
    if frm:
        name, addr = parseaddr(frm)
        dom = addr.split("@")[-1].lower() if "@" in addr else ""
        _, reg, _ = split_domain(dom) if "." in dom else ("", dom, "")
        low_name = name.lower()
        for brand, legit in BRANDS.items():
            if brand in low_name.replace(" ", "") and reg and reg not in legit:
                add(Indicator("display_name_mismatch", f"Display name says '{brand}' but address is {dom}", Severity.HIGH,
                              "The visible name is easy to fake; the actual address domain does not match the brand.",
                              f"From: {frm}", "header", 0.85, "impersonation"))
                break
        if reply:
            _, raddr = parseaddr(reply)
            rdom = raddr.split("@")[-1].lower() if "@" in raddr else ""
            if rdom and dom and split_domain(rdom)[1] != split_domain(dom)[1]:
                add(Indicator("reply_to_mismatch", "Reply-To differs from From domain", Severity.MEDIUM,
                              "Replies would go to a different organisation than the one shown as sender.",
                              f"From domain {dom}, Reply-To domain {rdom}", "header", 0.7, "sender"))
    elif headers:
        a.checks["sender"] = "unavailable"

    # ---- authentication results (reported, not verified) ----
    auth_line = _header(headers, "Authentication-Results") if headers else ""
    if auth_line:
        found = {k.lower(): v.lower() for k, v in AUTH_RE.findall(auth_line)}
        bad = {k: v for k, v in found.items() if v in ("fail", "softfail", "permerror")}
        if bad:
            add(Indicator("auth_failed", "Authentication failures reported in supplied header", Severity.HIGH,
                          "The receiving server reported failed sender authentication, so the From address may be forged.",
                          "as reported in header (not verified by PhishLens): " + ", ".join(f"{k}={v}" for k, v in bad.items()),
                          "header", 0.7, "auth"))
        a.checks["auth_header"] = "completed"
    else:
        a.checks["auth_header"] = "not_run" if not headers else "unavailable"

    # ---- URLs inside the email ----
    urls = list(dict.fromkeys(URL_RE.findall(body)))
    for raw in urls[:max_urls]:
        try:
            n = normalize_url(raw.rstrip(".,;"))
        except InvalidURL:
            continue
        sub = analyze_url(n, dns_enabled=dns_enabled)
        for i in sub.indicators:
            i.id = f"url:{n.host}:{i.id}"
            i.group = f"url:{n.host}:{i.group or i.id}"
            i.title = f"Link {n.host}: {i.title}"
            add(i)
    if len(urls) > max_urls:
        a.checks["urls_beyond_limit"] = "not_run"
    if urls and any(i.id.startswith("url:") for i in a.indicators):
        pass
    return a
