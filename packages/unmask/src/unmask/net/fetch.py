"""Fetch a referenced URL's bytes as evidence — never execute them.

Every request and every redirect hop is re-validated by `check_url`; auto-redirect is
disabled so a 30x can't bounce the fetcher onto an internal host. The connection is then
PINNED to the exact IP `check_url` validated (with the original Host header / TLS SNI),
so a rebinding DNS record can't flip the target to an internal address between the check
and the connect. The response is read under a hard size cap and written to disk for the
scanner to rescan statically. Nothing here runs the fetched content.
"""

from __future__ import annotations

import hashlib
import http.client
import os
import re
import socket
import ssl
from dataclasses import dataclass, field
from urllib.parse import urljoin, urlsplit

from unmask.net.guard import _resolve, check_url

_REDIRECT_CODES = {301, 302, 303, 307, 308}


@dataclass
class FetchPolicy:
    max_bytes: int = 2_000_000
    timeout: float = 8.0
    max_redirects: int = 3
    max_fetches: int = 8
    user_agent: str = "unmask-mcd/fetch-only (static analysis; does not execute fetched content)"


@dataclass
class FetchResult:
    url: str
    ok: bool = False
    path: str | None = None
    status: int | None = None
    content_type: str | None = None
    bytes_len: int = 0
    sha256: str | None = None
    final_url: str | None = None
    redirects: list = field(default_factory=list)
    blocked_reason: str | None = None
    error: str | None = None


class _PinnedHTTPConnection(http.client.HTTPConnection):
    """Connects to a pre-validated IP while keeping the original host for the Host
    header — closes the DNS-rebinding window (no second resolution at connect time)."""

    def __init__(self, host, ip, **kw):
        super().__init__(host, **kw)
        self._pinned_ip = ip

    def connect(self):
        self.sock = socket.create_connection((self._pinned_ip, self.port), self.timeout,
                                              self.source_address)


class _PinnedHTTPSConnection(http.client.HTTPSConnection):
    """As above; validates the TLS cert against the original hostname (SNI) while
    connecting to the pinned IP."""

    def __init__(self, host, ip, **kw):
        super().__init__(host, **kw)
        self._pinned_ip = ip

    def connect(self):
        sock = socket.create_connection((self._pinned_ip, self.port), self.timeout,
                                        self.source_address)
        self.sock = self._context.wrap_socket(sock, server_hostname=self.host)


def _safe_name(url: str) -> str:
    base = os.path.basename(urlsplit(url).path) or "fetched"
    base = re.sub(r"[^A-Za-z0-9._-]", "_", base)[:80]
    return base or "fetched"


def _request_pinned(url: str, ip: str, policy: FetchPolicy):
    """One pinned GET. Returns the open connection + response (caller closes)."""
    parts = urlsplit(url)
    host = parts.hostname
    port = parts.port or (443 if parts.scheme == "https" else 80)
    path = parts.path or "/"
    if parts.query:
        path += "?" + parts.query
    headers = {"User-Agent": policy.user_agent, "Accept": "*/*"}
    if parts.scheme == "https":
        conn = _PinnedHTTPSConnection(host, ip, port=port, timeout=policy.timeout,
                                      context=ssl.create_default_context())
    else:
        conn = _PinnedHTTPConnection(host, ip, port=port, timeout=policy.timeout)
    conn.request("GET", path, headers=headers)
    return conn, conn.getresponse()


def fetch(url: str, dest_dir: str, policy: FetchPolicy | None = None, *, resolver=_resolve) -> FetchResult:
    """Guarded GET of ``url`` into ``dest_dir``. Returns a `FetchResult`; a blocked or
    failed fetch is reported (``blocked_reason``/``error``), never raised."""
    policy = policy or FetchPolicy()
    current = url
    redirects: list[str] = []

    for _hop in range(policy.max_redirects + 1):
        safe, reason, addrs = check_url(current, resolver=resolver)
        if not safe:
            return FetchResult(url=url, final_url=current, redirects=redirects, blocked_reason=reason)
        conn = None
        try:
            conn, resp = _request_pinned(current, str(addrs[0]), policy)
            status = resp.status
            if status in _REDIRECT_CODES:
                loc = resp.getheader("Location")
                if not loc:
                    return FetchResult(url=url, status=status, error="redirect-without-location",
                                       redirects=redirects)
                current = urljoin(current, loc)
                redirects.append(current)
                continue
            if status >= 400:
                return FetchResult(url=url, status=status, error=f"http-error-{status}", redirects=redirects)
            data = resp.read(policy.max_bytes + 1)
            ctype = resp.headers.get_content_type() if resp.headers else None
        except (OSError, ssl.SSLError, http.client.HTTPException, ValueError) as e:
            return FetchResult(url=url, error=f"fetch-failed: {type(e).__name__}: {e}", redirects=redirects)
        finally:
            if conn is not None:
                conn.close()

        if len(data) > policy.max_bytes:
            return FetchResult(url=url, status=status, error=f"too-large (> {policy.max_bytes} bytes)",
                               final_url=current, redirects=redirects)

        os.makedirs(dest_dir, exist_ok=True)
        digest = hashlib.sha256(data).hexdigest()
        out = os.path.join(dest_dir, f"{digest[:12]}-{_safe_name(current)}")
        with open(out, "wb") as f:
            f.write(data)
        return FetchResult(url=url, ok=True, path=out, status=status, content_type=ctype,
                           bytes_len=len(data), sha256=digest, final_url=current, redirects=redirects)

    return FetchResult(url=url, error=f"too-many-redirects (> {policy.max_redirects})", redirects=redirects)
