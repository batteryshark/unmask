"""Fetch a referenced URL's bytes as evidence — never execute them.

Every request and every redirect hop is re-validated by `classify_url`; auto-redirect
is disabled so a 30x can't bounce the fetcher onto an internal host behind the guard's
back. The response is read under a hard size cap and written to disk for the scanner to
rescan statically — exactly the same "recovered source" path as container reveal and
the transform seam. Nothing here runs the fetched content.
"""

from __future__ import annotations

import hashlib
import os
import re
import urllib.request
from dataclasses import dataclass, field
from urllib.error import HTTPError, URLError
from urllib.parse import urljoin, urlsplit

from unmask.net.guard import _resolve, classify_url

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


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None  # never auto-follow; we re-validate each hop ourselves


def _safe_name(url: str) -> str:
    base = os.path.basename(urlsplit(url).path) or "fetched"
    base = re.sub(r"[^A-Za-z0-9._-]", "_", base)[:80]
    return base or "fetched"


def _read_capped(resp, max_bytes: int) -> bytes | None:
    data = resp.read(max_bytes + 1)
    if len(data) > max_bytes:
        return None
    return data


def fetch(url: str, dest_dir: str, policy: FetchPolicy | None = None, *, resolver=_resolve) -> FetchResult:
    """Guarded GET of ``url`` into ``dest_dir``. Returns a `FetchResult`; a blocked or
    failed fetch is reported (``blocked_reason``/``error``), never raised."""
    policy = policy or FetchPolicy()
    opener = urllib.request.build_opener(_NoRedirect)
    current = url
    redirects: list[str] = []

    for _hop in range(policy.max_redirects + 1):
        safe, reason = classify_url(current, resolver=resolver)
        if not safe:
            return FetchResult(url=url, final_url=current, redirects=redirects, blocked_reason=reason)
        req = urllib.request.Request(current, headers={"User-Agent": policy.user_agent, "Accept": "*/*"})
        try:
            resp = opener.open(req, timeout=policy.timeout)
        except HTTPError as e:
            if e.code in _REDIRECT_CODES:
                loc = e.headers.get("Location")
                if not loc:
                    return FetchResult(url=url, status=e.code, error="redirect-without-location")
                current = urljoin(current, loc)
                redirects.append(current)
                continue
            return FetchResult(url=url, status=e.code, error=f"http-error-{e.code}", redirects=redirects)
        except (URLError, OSError, ValueError) as e:
            return FetchResult(url=url, error=f"fetch-failed: {type(e).__name__}: {e}", redirects=redirects)

        with resp:
            data = _read_capped(resp, policy.max_bytes)
            status = getattr(resp, "status", None) or resp.getcode()
            ctype = resp.headers.get_content_type() if resp.headers else None
        if data is None:
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
