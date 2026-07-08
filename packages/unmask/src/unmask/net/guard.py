"""SSRF guard for fetch-only network mode.

`mcd` fetches a referenced URL only to read its bytes as evidence — never to execute
it — but the URL comes from potentially-malicious code, so it must not be usable to
reach the analyst's own network. `classify_url` is the gate every fetch (and every
redirect hop) passes: http(s) only, an allowed port, and a host that resolves to
*only* public addresses. Anything private/loopback/link-local (incl. the cloud
metadata endpoint), reserved, or unresolvable is refused.

Residual: a host that passes validation could re-resolve to an internal address at
connect time (DNS rebinding). We re-validate every redirect and keep timeouts short;
full protection would require pinning the connection to the validated IP, deferred.
"""

from __future__ import annotations

import ipaddress
import socket
from urllib.parse import urlsplit

_ALLOWED_SCHEMES = {"http", "https"}
_ALLOWED_PORTS = {80, 443, 8080, 8443}
# Suffixes that name a private/loopback scope by convention, independent of DNS.
_BLOCKED_SUFFIXES = (".local", ".localhost", ".internal", ".intranet", ".lan", ".home.arpa")
_BLOCKED_HOSTNAMES = {"localhost", "ip6-localhost", "ip6-loopback"}


def _ip_is_public(ip: ipaddress._BaseAddress) -> bool:
    """Public = not any of the scopes an SSRF payload would target. ipaddress covers
    loopback/link-local (incl. 169.254.169.254)/private/reserved/multicast; we also
    unwrap IPv4-mapped/6to4/Teredo IPv6 so a mapped private v4 can't sneak through."""
    if isinstance(ip, ipaddress.IPv6Address):
        if ip.ipv4_mapped is not None:
            return _ip_is_public(ip.ipv4_mapped)
        if getattr(ip, "sixtofour", None) is not None:
            return _ip_is_public(ip.sixtofour)
        if getattr(ip, "teredo", None) is not None:
            return _ip_is_public(ip.teredo[1])
    return not (
        ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved
        or ip.is_multicast or ip.is_unspecified
    )


def _resolve(host: str) -> list[ipaddress._BaseAddress]:
    """Every address the host resolves to (v4 + v6). An IP literal resolves to
    itself. Raises OSError if resolution fails."""
    try:
        return [ipaddress.ip_address(host)]
    except ValueError:
        pass
    infos = socket.getaddrinfo(host, None, proto=socket.IPPROTO_TCP)
    addrs = []
    for info in infos:
        sockaddr = info[4]
        try:
            addrs.append(ipaddress.ip_address(sockaddr[0]))
        except ValueError:
            continue
    if not addrs:
        raise OSError(f"no addresses for {host!r}")
    return addrs


def check_url(url: str, *, resolver=_resolve):
    """Return ``(is_safe, reason, addrs)``. ``addrs`` is the validated public IPs the
    host resolved to (empty when unsafe) — the fetcher PINS the connection to one of
    these so a later re-resolution (DNS rebinding) cannot redirect it to an internal
    host. ``reason`` is empty when safe. ``resolver`` is injectable so tests need no DNS."""
    try:
        parts = urlsplit(url)
    except ValueError as exc:
        return False, f"unparseable-url: {exc}", []

    if parts.scheme.lower() not in _ALLOWED_SCHEMES:
        return False, f"scheme-not-allowed: {parts.scheme or '(none)'}", []
    host = parts.hostname
    if not host:
        return False, "no-host", []

    host_l = host.lower().rstrip(".")
    if host_l in _BLOCKED_HOSTNAMES or host_l.endswith(_BLOCKED_SUFFIXES):
        return False, f"blocked-host: {host_l}", []

    try:
        port = parts.port
    except ValueError:
        return False, "invalid-port", []
    if port is not None and port not in _ALLOWED_PORTS:
        return False, f"port-not-allowed: {port}", []

    try:
        addrs = resolver(host)
    except OSError as exc:
        return False, f"unresolvable: {exc}", []
    for ip in addrs:
        if not _ip_is_public(ip):
            return False, f"non-public-address: {ip}", []
    return True, "", addrs


def classify_url(url: str, *, resolver=_resolve) -> tuple[bool, str]:
    """``(is_safe, reason)`` — the boolean gate; `check_url` also returns validated IPs."""
    ok, reason, _addrs = check_url(url, resolver=resolver)
    return ok, reason
