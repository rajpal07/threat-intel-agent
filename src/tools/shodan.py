"""Shodan — host exposure: open ports, services, ASN/org, hostnames."""
from __future__ import annotations

from ..config import API_KEYS
from ..schemas import ToolResult
from .base import request_json

BASE = "https://api.shodan.io"
SOURCE = "Shodan"


def host(ip: str) -> ToolResult:
    key = API_KEYS.get("shodan")
    res = request_json(
        SOURCE, "host", url=f"{BASE}/shodan/host/{ip}",
        api_key=key, cache_id=ip, params={"key": key or ""},
    )
    if res.usable:
        d = res.data
        # Whitelist product/port only; skip raw banner text (injection vector).
        services = [
            {"port": s.get("port"), "product": s.get("product"), "transport": s.get("transport")}
            for s in (d.get("data") or [])
        ][:15]
        res.data = {
            "ports": d.get("ports", []),
            "asn": d.get("asn"),
            "isp": d.get("isp"),
            "org": d.get("org"),
            "os": d.get("os"),
            "hostnames": (d.get("hostnames") or [])[:10],
            "country": d.get("country_name"),
            "services": services,
        }
    return res
