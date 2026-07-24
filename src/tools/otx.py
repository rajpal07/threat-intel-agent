"""AlienVault OTX — pulse-based reputation for IP/domain/hash, passive DNS,
and threat-actor pulse search.

Pulse names/descriptions are attacker-authorable free text, so they are the
prime indirect-injection vector; they are whitelisted here and later scanned
by the sanitizer node before reaching the LLM.
"""
from __future__ import annotations

from ..config import API_KEYS
from ..schemas import ToolResult
from .base import request_json

BASE = "https://otx.alienvault.com/api/v1"
SOURCE = "AlienVault OTX"


def _headers() -> dict:
    return {"X-OTX-API-KEY": API_KEYS.get("otx") or ""}


def _pulses(general: dict, limit: int = 5) -> dict:
    info = general.get("pulse_info") or {}
    pulses = info.get("pulses") or []
    return {
        "pulse_count": info.get("count", 0),
        "pulse_names": [p.get("name", "") for p in pulses[:limit]],
        "tags": sorted({t for p in pulses[:limit] for t in (p.get("tags") or [])})[:12],
    }


def lookup_ip(ip: str) -> ToolResult:
    res = request_json(
        SOURCE, "IPv4/general", url=f"{BASE}/indicators/IPv4/{ip}/general",
        api_key=API_KEYS.get("otx"), cache_id=ip, headers=_headers(),
    )
    if res.usable:
        g = res.data
        res.data = {"asn": g.get("asn"), "country": g.get("country_name"), **_pulses(g)}
    return res


def lookup_domain(domain: str) -> ToolResult:
    res = request_json(
        SOURCE, "domain/general", url=f"{BASE}/indicators/domain/{domain}/general",
        api_key=API_KEYS.get("otx"), cache_id=domain, headers=_headers(),
    )
    if res.usable:
        res.data = _pulses(res.data)
    return res


def lookup_hash(file_hash: str) -> ToolResult:
    res = request_json(
        SOURCE, "file/general", url=f"{BASE}/indicators/file/{file_hash}/general",
        api_key=API_KEYS.get("otx"), cache_id=file_hash, headers=_headers(),
    )
    if res.usable:
        res.data = _pulses(res.data)
    return res


def passive_dns(ip: str) -> ToolResult:
    """IP -> hostnames seen resolving to it (pivot)."""
    res = request_json(
        SOURCE, "IPv4/passive_dns", url=f"{BASE}/indicators/IPv4/{ip}/passive_dns",
        api_key=API_KEYS.get("otx"), cache_id=f"{ip}_pdns", headers=_headers(),
    )
    if res.usable:
        rows = res.data.get("passive_dns") or []
        hosts = [r.get("hostname") for r in rows if isinstance(r, dict) and r.get("hostname")]
        res.data = {"passive_dns_hosts": hosts[:15]}
    return res


def search_actor(actor: str) -> ToolResult:
    """Actor name -> matching pulse names/tags (secondary to bundled MITRE)."""
    res = request_json(
        SOURCE, "search/pulses", url=f"{BASE}/search/pulses",
        api_key=API_KEYS.get("otx"), cache_id=f"actor_{actor}", headers=_headers(),
        params={"q": actor, "limit": 5},
    )
    if res.usable:
        rows = res.data.get("results") or []
        res.data = {
            "matched_pulses": [r.get("name", "") for r in rows[:5]],
            "tags": sorted({t for r in rows[:5] for t in (r.get("tags") or [])})[:12],
        }
    return res
