"""Validate and normalise a user-supplied URL.

Goals: reject junk early, produce one canonical form, and expose the parts the
analyzers need. Never makes network calls.
"""
from __future__ import annotations

import ipaddress
import re
import socket
from dataclasses import dataclass
from urllib.parse import urlsplit

# Small built-in list of multi-part public suffixes so "evil.co.uk" is not read as
# registered domain "co.uk". A real deployment should use the Public Suffix List.
MULTI_PART_SUFFIXES = {
    "co.uk", "org.uk", "ac.uk", "gov.uk", "com.au", "net.au", "org.au",
    "co.in", "net.in", "org.in", "gov.in", "ac.in", "co.jp", "com.br",
    "com.cn", "co.za", "com.mx", "co.nz", "com.sg", "com.tr",
}

_CTRL = re.compile(r"[\x00-\x20\x7f]")


class InvalidURL(ValueError):
    """Raised with a user-safe message when the URL cannot be accepted."""


@dataclass(frozen=True)
class NormalizedURL:
    original: str
    normalized: str
    scheme: str
    host: str                 # ASCII/punycode, lowercase, no trailing dot
    unicode_host: str         # decoded for display / script analysis
    port: int | None
    path: str
    query: str
    has_userinfo: bool
    assumed_scheme: bool
    is_ip: bool
    ip: str | None
    ip_obfuscated: bool       # decimal/hex/octal/short forms like 2130706433
    is_punycode: bool
    registered_domain: str
    subdomain: str
    tld: str


def _parse_ip(host: str) -> tuple[str | None, bool]:
    """Return (canonical_ip, obfuscated?) if host is an IP in any common notation."""
    h = host.strip("[]")
    try:
        return str(ipaddress.ip_address(h)), False
    except ValueError:
        pass
    # inet_aton accepts 127.1, 0x7f.0.0.1, 017700000001, 2130706433 ...
    if re.fullmatch(r"[0-9a-fx.]+", h, re.I):
        try:
            packed = socket.inet_aton(h)
            return str(ipaddress.IPv4Address(packed)), True
        except OSError:
            return None, False
    return None, False


def split_domain(host: str) -> tuple[str, str, str]:
    """Return (subdomain, registered_domain, tld) using the small suffix list."""
    labels = host.split(".")
    if len(labels) < 2:
        return "", host, host
    two = ".".join(labels[-2:])
    if two in MULTI_PART_SUFFIXES and len(labels) >= 3:
        reg = ".".join(labels[-3:])
        return ".".join(labels[:-3]), reg, two
    return ".".join(labels[:-2]), two, labels[-1]


def normalize_url(raw: str, max_length: int = 2048) -> NormalizedURL:
    if raw is None or not isinstance(raw, str):
        raise InvalidURL("Please enter a URL.")
    text = raw.strip()
    if not text:
        raise InvalidURL("Please enter a URL.")
    if len(text) > max_length:
        raise InvalidURL(f"URL is too long (max {max_length} characters).")
    if _CTRL.search(text):
        raise InvalidURL("URL contains spaces or control characters.")

    assumed = False
    if "://" not in text:
        if re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*:", text) and not re.match(r"^[^/]*:\d+(/|$)", text):
            # e.g. javascript:, data:, file:, mailto:
            scheme = text.split(":", 1)[0].lower()
            raise InvalidURL(f"Unsupported protocol '{scheme}'. Only http and https are allowed.")
        text = "http://" + text.lstrip("/")
        assumed = True

    try:
        parts = urlsplit(text)
        port = parts.port
    except ValueError:
        raise InvalidURL("URL is malformed.")

    scheme = parts.scheme.lower()
    if scheme not in ("http", "https"):
        raise InvalidURL(f"Unsupported protocol '{scheme}'. Only http and https are allowed.")

    host_raw = parts.hostname
    if not host_raw:
        raise InvalidURL("URL has no host name.")
    host_raw = host_raw.rstrip(".").lower()
    if not host_raw:
        raise InvalidURL("URL has no host name.")

    ip, obfuscated = _parse_ip(host_raw)
    if ip:
        host = ip if ":" not in ip else ip
        unicode_host = host
        is_punycode = False
        sub, reg, tld = "", host, ""
    else:
        try:
            host = host_raw.encode("idna").decode("ascii")
        except UnicodeError:
            raise InvalidURL("Host name contains invalid characters.")
        if len(host) > 253 or any(not (0 < len(l) <= 63) for l in host.split(".")):
            raise InvalidURL("Host name is malformed.")
        if not re.fullmatch(r"[a-z0-9-]+(\.[a-z0-9-]+)*", host):
            raise InvalidURL("Host name contains invalid characters.")
        if "." not in host:
            raise InvalidURL("Host name must include a domain (for example example.com).")
        try:
            unicode_host = host.encode("ascii").decode("idna")
        except UnicodeError:
            unicode_host = host
        is_punycode = any(l.startswith("xn--") for l in host.split("."))
        sub, reg, tld = split_domain(host)

    default_port = 443 if scheme == "https" else 80
    netloc = host if not ip or ":" not in ip else f"[{host}]"
    if port and port != default_port:
        netloc += f":{port}"
    path = parts.path or "/"
    normalized = f"{scheme}://{netloc}{path}" + (f"?{parts.query}" if parts.query else "")

    return NormalizedURL(
        original=raw.strip(), normalized=normalized, scheme=scheme, host=host,
        unicode_host=unicode_host, port=port, path=path, query=parts.query,
        has_userinfo=bool(parts.username or parts.password or "@" in parts.netloc),
        assumed_scheme=assumed, is_ip=bool(ip), ip=ip, ip_obfuscated=obfuscated,
        is_punycode=is_punycode, registered_domain=reg, subdomain=sub, tld=tld,
    )
