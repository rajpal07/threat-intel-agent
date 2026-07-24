"""AbuseIPDB — IP abuse confidence score and report metadata."""
from __future__ import annotations

from ..config import API_KEYS
from ..schemas import ToolResult
from .base import request_json

BASE = "https://api.abuseipdb.com/api/v2"
SOURCE = "AbuseIPDB"


def check_ip(ip: str) -> ToolResult:
    res = request_json(
        SOURCE, "check", url=f"{BASE}/check",
        api_key=API_KEYS.get("abuseipdb"), cache_id=ip,
        headers={"Key": API_KEYS.get("abuseipdb") or "", "Accept": "application/json"},
        params={"ipAddress": ip, "maxAgeInDays": 90},
    )
    if res.usable:
        d = res.data.get("data") or {}
        res.data = {
            "abuse_confidence_score": d.get("abuseConfidenceScore"),
            "total_reports": d.get("totalReports"),
            "country_code": d.get("countryCode"),
            "isp": d.get("isp"),
            "domain": d.get("domain"),
            "usage_type": d.get("usageType"),
            "is_tor": d.get("isTor"),
            "last_reported_at": d.get("lastReportedAt"),
        }
    return res
