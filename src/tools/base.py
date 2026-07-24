"""Shared HTTP plumbing for every threat-intel tool.

One place owns: per-source rate limiting, retry/backoff on 429/5xx, a 24h
SQLite response cache, and DEMO_MODE fixture loading. Tools call
`request_json(...)` and always get a ToolResult back — network failures are
returned as typed statuses, never raised into the graph.
"""
from __future__ import annotations

import json
import sqlite3
import threading
import time
from pathlib import Path
from typing import Any, Optional

import httpx
from tenacity import (
    retry,
    retry_if_exception_type,
    stop_after_attempt,
    wait_exponential,
)

from ..config import CACHE_DB, FIXTURES_DIR, demo_mode

CACHE_TTL_SECONDS = 24 * 3600
HTTP_TIMEOUT = 20.0

# Minimum seconds between calls per source (free-tier friendly).
MIN_INTERVAL = {
    "virustotal": 15.0,   # 4 req/min
    "abuseipdb": 1.0,
    "otx": 1.0,
    "nvd": 0.7,           # 50 req / 30s with key
    "shodan": 1.1,        # ~1 req/s
}


class _RetryableStatus(Exception):
    """Raised on 429/5xx so tenacity retries with backoff."""


class RateLimiter:
    """Simple per-key minimum-interval limiter (single-process Streamlit app)."""

    def __init__(self) -> None:
        self._last: dict[str, float] = {}
        self._lock = threading.Lock()

    def wait(self, key: str) -> None:
        interval = MIN_INTERVAL.get(key, 1.0)
        with self._lock:
            now = time.monotonic()
            elapsed = now - self._last.get(key, 0.0)
            if elapsed < interval:
                time.sleep(interval - elapsed)
            self._last[key] = time.monotonic()


class HttpCache:
    """Tiny SQLite key/value cache with TTL. Best-effort — cache errors never fatal."""

    def __init__(self, path: Path) -> None:
        self.path = path
        self.enabled = True
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            with self._conn() as c:
                c.execute(
                    "CREATE TABLE IF NOT EXISTS cache "
                    "(k TEXT PRIMARY KEY, v TEXT, ts REAL)"
                )
        except Exception:
            self.enabled = False

    def _conn(self) -> sqlite3.Connection:
        return sqlite3.connect(self.path, timeout=5)

    def get(self, key: str) -> Optional[dict[str, Any]]:
        if not self.enabled:
            return None
        try:
            with self._conn() as c:
                row = c.execute("SELECT v, ts FROM cache WHERE k=?", (key,)).fetchone()
            if not row:
                return None
            value, ts = row
            if time.time() - ts > CACHE_TTL_SECONDS:
                return None
            return json.loads(value)
        except Exception:
            return None

    def set(self, key: str, value: dict[str, Any]) -> None:
        if not self.enabled:
            return
        try:
            with self._conn() as c:
                c.execute(
                    "INSERT OR REPLACE INTO cache (k, v, ts) VALUES (?, ?, ?)",
                    (key, json.dumps(value), time.time()),
                )
        except Exception:
            pass


_limiter = RateLimiter()
_cache = HttpCache(CACHE_DB)


def _fixture_path(source: str, ident: str) -> Path:
    safe = "".join(ch if ch.isalnum() else "_" for ch in ident)[:80]
    return FIXTURES_DIR / f"{source}_{safe}.json"


def load_fixture(source: str, ident: str) -> Optional[dict[str, Any]]:
    """DEMO_MODE / test fixture loader. Falls back to a per-source default."""
    specific = _fixture_path(source, ident)
    default = FIXTURES_DIR / f"{source}_default.json"
    for p in (specific, default):
        try:
            if p.exists():
                return json.loads(p.read_text(encoding="utf-8"))
        except Exception:
            continue
    return None


@retry(
    retry=retry_if_exception_type((_RetryableStatus, httpx.TransportError)),
    wait=wait_exponential(multiplier=1, min=1, max=8),
    stop=stop_after_attempt(3),
    reraise=True,
)
def _do_request(method: str, url: str, **kwargs) -> httpx.Response:
    resp = httpx.request(method, url, timeout=HTTP_TIMEOUT, **kwargs)
    if resp.status_code == 429 or resp.status_code >= 500:
        raise _RetryableStatus(f"{resp.status_code} from {url}")
    return resp


def request_json(
    source: str,
    endpoint: str,
    *,
    url: str,
    api_key: str | None,
    cache_id: str,
    method: str = "GET",
    headers: dict | None = None,
    params: dict | None = None,
    require_key: bool = True,
) -> "ToolResult":
    """Fetch JSON and wrap it in a ToolResult. Never raises to the caller."""
    from ..schemas import ToolResult  # avoid circular import at module load

    def result(**kw) -> ToolResult:
        return ToolResult(source=source, endpoint=endpoint, **kw)

    if require_key and not api_key:
        return result(status="unavailable", error="API key not configured")

    # DEMO_MODE: serve a fixture, skip the network entirely.
    if demo_mode():
        fx = load_fixture(source, cache_id)
        if fx is not None:
            return result(status="ok", data=fx, cached=True)
        return result(status="no_data", error="no fixture for demo mode")

    ck = f"{source}:{endpoint}:{cache_id}"
    hit = _cache.get(ck)
    if hit is not None:
        return result(status="ok", data=hit, cached=True)

    try:
        _limiter.wait(source)
        resp = _do_request(method, url, headers=headers, params=params)
    except _RetryableStatus:
        return result(status="rate_limited", error="rate limited / server busy after retries")
    except httpx.HTTPError as exc:
        return result(status="error", error=f"network error: {type(exc).__name__}")

    if resp.status_code == 404:
        return result(status="no_data", error="not found")
    if resp.status_code in (401, 403):
        return result(status="unavailable", error=f"auth failed ({resp.status_code})")
    if resp.status_code >= 400:
        return result(status="error", error=f"HTTP {resp.status_code}")

    try:
        data = resp.json()
    except Exception:
        return result(status="error", error="malformed JSON response")

    _cache.set(ck, data)
    return result(status="ok", data=data)
