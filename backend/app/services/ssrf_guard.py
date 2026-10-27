"""SSRF protection and a safe, bounded HTTP fetcher.

Rules enforced:
* only http/https, only ports 80/443
* every resolved IP must be globally routable (blocks loopback, private,
  link-local incl. 169.254.169.254 cloud metadata, multicast, reserved, CGNAT...)
* we connect to the *validated IP* (pinning) so DNS cannot change between check
  and use (DNS-rebinding defence)
* every redirect target goes through the same checks again
* strict timeout, redirect limit and response size limit; bodies are never executed
"""
from __future__ import annotations

import http.client
import ipaddress
import socket
import ssl
from dataclasses import dataclass, field
from typing import Callable
from urllib.parse import urljoin

from app.services.url_normalizer import InvalidURL, normalize_url

ALLOWED_PORTS = {80, 443}
REDIRECT_CODES = {301, 302, 303, 307, 308}


class SSRFBlocked(Exception):
    """Raised when a target is not allowed. Message is safe to show to users."""


def ip_block_reason(ip_str: str) -> str | None:
    """Return a reason string if the IP must not be contacted, else None."""
    try:
        ip = ipaddress.ip_address(ip_str)
    except ValueError:
        return "not a valid IP address"
    if isinstance(ip, ipaddress.IPv6Address):
        if ip.ipv4_mapped:
            ip = ip.ipv4_mapped
        elif ip.sixtofour:
            ip = ip.sixtofour
    if ip.is_loopback:
        return "loopback address"
    if ip.is_unspecified:
        return "unspecified address"
    if ip.is_link_local:
        return "link-local address (includes cloud metadata 169.254.169.254)"
    if ip.is_multicast:
        return "multicast address"
    if ip.is_private:
        return "private network address"
    if ip.is_reserved:
        return "reserved address"
    if not ip.is_global:
        return "non-public address (e.g. carrier-grade NAT)"
    return None


Resolver = Callable[[str, int], list[str]]


def default_resolver(host: str, port: int) -> list[str]:
    infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    return sorted({i[4][0] for i in infos})


def resolve_and_validate(host: str, port: int, resolver: Resolver = default_resolver) -> list[str]:
    """Resolve host and ensure *all* addresses are public. Returns the IPs."""
    if port not in ALLOWED_PORTS:
        raise SSRFBlocked(f"Port {port} is not allowed (only 80 and 443).")
    # A literal IP never needs DNS but still must be validated.
    try:
        ipaddress.ip_address(host.strip("[]"))
        ips = [host.strip("[]")]
    except ValueError:
        try:
            ips = resolver(host, port)
        except OSError:
            raise SSRFBlocked("Host name could not be resolved.")
    if not ips:
        raise SSRFBlocked("Host name could not be resolved.")
    for ip in ips:
        reason = ip_block_reason(ip)
        if reason:
            raise SSRFBlocked(f"Blocked: host resolves to a {reason}.")
    return ips


@dataclass
class FetchResult:
    final_url: str
    hops: list[str] = field(default_factory=list)   # every URL visited, in order
    status: int | None = None
    body_snippet: str = ""
    truncated: bool = False
    error: str = ""
    blocked: bool = False


ConnFactory = Callable[[str, str, int, str, float], "http.client.HTTPConnection"]


def _real_connection(scheme: str, ip: str, port: int, host: str, timeout: float):
    """Connect to the pinned IP; for https verify the certificate against the host name."""
    if scheme == "https":
        ctx = ssl.create_default_context()
        raw = socket.create_connection((ip, port), timeout=timeout)
        sock = ctx.wrap_socket(raw, server_hostname=host)
        conn = http.client.HTTPSConnection(host, port, timeout=timeout, context=ctx)
    else:
        sock = socket.create_connection((ip, port), timeout=timeout)
        conn = http.client.HTTPConnection(host, port, timeout=timeout)
    conn.sock = sock
    return conn


class SafeFetcher:
    def __init__(self, resolver: Resolver = default_resolver, conn_factory: ConnFactory = _real_connection,
                 timeout: float = 5.0, max_redirects: int = 5, max_bytes: int = 200_000):
        self.resolver = resolver
        self.conn_factory = conn_factory
        self.timeout = timeout
        self.max_redirects = max_redirects
        self.max_bytes = max_bytes

    def fetch(self, url: str) -> FetchResult:
        result = FetchResult(final_url=url)
        current = url
        for _ in range(self.max_redirects + 1):
            try:
                n = normalize_url(current)
                port = n.port or (443 if n.scheme == "https" else 80)
                ips = resolve_and_validate(n.host, port, self.resolver)
            except (InvalidURL, SSRFBlocked) as exc:
                result.error, result.blocked = str(exc), True
                return result
            result.hops.append(n.normalized)
            result.final_url = n.normalized
            try:
                conn = self.conn_factory(n.scheme, ips[0], port, n.host, self.timeout)
                target = n.path + (f"?{n.query}" if n.query else "")
                conn.request("GET", target, headers={
                    "Host": n.host, "User-Agent": "PhishLens-Scanner/0.1 (+safe-fetch)",
                    "Accept": "text/html,*/*;q=0.5", "Connection": "close"})
                resp = conn.getresponse()
                result.status = resp.status
                if resp.status in REDIRECT_CODES and resp.getheader("Location"):
                    current = urljoin(n.normalized, resp.getheader("Location"))
                    conn.close()
                    continue
                data = resp.read(self.max_bytes + 1)
                result.truncated = len(data) > self.max_bytes
                result.body_snippet = data[: self.max_bytes].decode("utf-8", errors="replace")
                conn.close()
                return result
            except (OSError, http.client.HTTPException, ssl.SSLError) as exc:
                result.error = f"Connection failed: {type(exc).__name__}"
                return result
        result.error = f"Too many redirects (limit {self.max_redirects})."
        return result
