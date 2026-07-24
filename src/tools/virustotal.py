"""VirusTotal v3 — IP, domain, file-hash reputation and IP->domain pivots.

Only whitelisted fields are lifted out of the (large, partly user-controlled)
API response, so raw community content never reaches the LLM prompt.
"""
from __future__ import annotations

from ..config import API_KEYS
from ..schemas import ToolResult
from .base import request_json

BASE = "https://www.virustotal.com/api/v3"
SOURCE = "VirusTotal"


def _headers() -> dict:
    return {"x-apikey": API_KEYS.get("virustotal") or "", "accept": "application/json"}


def _stats(attrs: dict) -> dict:
    s = attrs.get("last_analysis_stats") or {}
    return {
        "malicious": s.get("malicious", 0),
        "suspicious": s.get("suspicious", 0),
        "harmless": s.get("harmless", 0),
        "undetected": s.get("undetected", 0),
    }


def _top_detections(attrs: dict, limit: int = 5) -> list[str]:
    results = attrs.get("last_analysis_results") or {}
    hits = [
        f"{eng}: {r.get('result')}"
        for eng, r in results.items()
        if isinstance(r, dict) and r.get("category") == "malicious" and r.get("result")
    ]
    return hits[:limit]


def lookup_ip(ip: str) -> ToolResult:
    res = request_json(
        SOURCE, "ip_addresses", url=f"{BASE}/ip_addresses/{ip}",
        api_key=API_KEYS.get("virustotal"), cache_id=ip, headers=_headers(),
    )
    if res.usable:
        a = (res.data.get("data") or {}).get("attributes") or {}
        res.data = {
            "stats": _stats(a), "reputation": a.get("reputation"),
            "asn": a.get("asn"), "as_owner": a.get("as_owner"),
            "country": a.get("country"), "network": a.get("network"),
            "top_detections": _top_detections(a),
        }
    return res


def lookup_domain(domain: str) -> ToolResult:
    res = request_json(
        SOURCE, "domains", url=f"{BASE}/domains/{domain}",
        api_key=API_KEYS.get("virustotal"), cache_id=domain, headers=_headers(),
    )
    if res.usable:
        a = (res.data.get("data") or {}).get("attributes") or {}
        res.data = {
            "stats": _stats(a), "reputation": a.get("reputation"),
            "categories": list((a.get("categories") or {}).values())[:5],
            "registrar": a.get("registrar"),
            "top_detections": _top_detections(a),
        }
    return res


def lookup_hash(file_hash: str) -> ToolResult:
    res = request_json(
        SOURCE, "files", url=f"{BASE}/files/{file_hash}",
        api_key=API_KEYS.get("virustotal"), cache_id=file_hash, headers=_headers(),
    )
    if res.usable:
        a = (res.data.get("data") or {}).get("attributes") or {}
        ptc = a.get("popular_threat_classification") or {}
        res.data = {
            "stats": _stats(a),
            "threat_label": ptc.get("suggested_threat_label"),
            "type_description": a.get("type_description"),
            "meaningful_name": a.get("meaningful_name"),
            "names": (a.get("names") or [])[:3],
            "top_detections": _top_detections(a),
        }
    return res


def resolutions(ip: str) -> ToolResult:
    """IP -> historical domain resolutions (pivot)."""
    res = request_json(
        SOURCE, "ip_resolutions", url=f"{BASE}/ip_addresses/{ip}/resolutions",
        api_key=API_KEYS.get("virustotal"), cache_id=f"{ip}_res", headers=_headers(),
        params={"limit": 20},
    )
    if res.usable:
        items = res.data.get("data") or []
        domains = [
            (i.get("attributes") or {}).get("host_name")
            for i in items if isinstance(i, dict)
        ]
        res.data = {"resolved_domains": [d for d in domains if d][:15]}
    return res
