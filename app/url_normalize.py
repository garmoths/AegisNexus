"""Ortak URL normalizasyonu — ingest ve scanner aynı kuralları kullanır."""
from __future__ import annotations

import hashlib
import re
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse


def _strip_www(host: str) -> str:
    h = host.lower().strip()
    return h[4:] if h.startswith("www.") else h


def _host_port(netloc: str) -> tuple[str, str | None]:
    """netloc -> (host küçük harf, port veya None). IPv6 köşeli parantezli desteklenir."""
    netloc = netloc.strip().lower().split("@")[-1]
    if not netloc:
        return "", None
    if netloc.startswith("["):
        end = netloc.find("]")
        if end != -1:
            host = netloc[1:end]
            rest = netloc[end + 1 :]
            if rest.startswith(":") and rest[1:].isdigit():
                return host, rest[1:]
            return host, None
    if ":" in netloc:
        host, port = netloc.rsplit(":", 1)
        if port.isdigit():
            return _strip_www(host), port
    return _strip_www(netloc), None


def normalize_url_record(raw: str) -> tuple[str | None, str | None, str | None]:
    """
    Satır veya URL'den (canonical_url, sha256_hex, domain_norm) üretir.
    Geçersizse (None, None, None).
    """
    line = (raw or "").strip()
    if not line or line.startswith("#") or line.startswith("//"):
        return None, None, None

    if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", line):
        line = "http://" + line

    try:
        p = urlparse(line)
    except Exception:
        return None, None, None

    netloc = (p.netloc or "").strip()
    path = p.path if p.path else "/"

    if not netloc and path and path != "/":
        first, _, rest = path.partition("/")
        if "." in first or first.startswith("["):
            netloc = first
            path = "/" + rest if rest else "/"

    if not netloc:
        return None, None, None

    host, port = _host_port(netloc)
    if not host:
        return None, None, None

    scheme = (p.scheme or "http").lower()
    query = urlencode(sorted(parse_qsl(p.query, keep_blank_values=True)))

    netloc_canon = f"{host}:{port}" if port else host
    canonical = urlunparse((scheme, netloc_canon, path, "", query, ""))
    digest = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
    return canonical, digest, host
