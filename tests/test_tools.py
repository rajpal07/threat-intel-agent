"""Tool layer: DEMO_MODE fixtures, error handling, missing keys (rate-limit,
404, 500, timeout, malformed JSON all exercised via mocked httpx)."""
from __future__ import annotations

import httpx
import respx

from src import config
from src.tools import abuseipdb, nvd, virustotal


# --- DEMO_MODE / fixtures --------------------------------------------------
def test_demo_ip_lookup(demo):
    r = virustotal.lookup_ip("45.83.122.10")
    assert r.status == "ok" and r.cached
    assert r.data["stats"]["malicious"] == 11


def test_demo_hash_lookup(demo):
    r = virustotal.lookup_hash("275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f")
    assert r.status == "ok"
    assert r.data["threat_label"] == "trojan.eicar/test"


# --- missing key -----------------------------------------------------------
def test_missing_key_is_unavailable(monkeypatch):
    monkeypatch.setenv("DEMO_MODE", "false")
    monkeypatch.setitem(config.API_KEYS, "virustotal", None)
    r = virustotal.lookup_ip("8.8.8.8")
    assert r.status == "unavailable"
    assert "key" in r.error.lower()


# --- live path (mocked) ----------------------------------------------------
@respx.mock
def test_http_200(fast_net):
    respx.get("https://www.virustotal.com/api/v3/ip_addresses/1.2.3.4").mock(
        return_value=httpx.Response(200, json={"data": {"attributes": {
            "last_analysis_stats": {"malicious": 4, "suspicious": 0, "harmless": 1, "undetected": 2},
            "asn": 123, "as_owner": "X"}}}))
    r = virustotal.lookup_ip("1.2.3.4")
    assert r.status == "ok" and r.data["stats"]["malicious"] == 4


@respx.mock
def test_http_404(fast_net):
    respx.get("https://www.virustotal.com/api/v3/ip_addresses/1.2.3.5").mock(
        return_value=httpx.Response(404))
    r = virustotal.lookup_ip("1.2.3.5")
    assert r.status == "no_data"


@respx.mock
def test_http_429_rate_limited(fast_net):
    respx.get("https://api.abuseipdb.com/api/v2/check").mock(
        return_value=httpx.Response(429))
    r = abuseipdb.check_ip("1.2.3.6")
    assert r.status == "rate_limited"


@respx.mock
def test_http_500(fast_net):
    respx.get("https://www.virustotal.com/api/v3/ip_addresses/1.2.3.7").mock(
        return_value=httpx.Response(500))
    r = virustotal.lookup_ip("1.2.3.7")
    assert r.status == "rate_limited"  # 5xx retried then reported as busy


@respx.mock
def test_timeout(fast_net):
    respx.get("https://www.virustotal.com/api/v3/ip_addresses/1.2.3.8").mock(
        side_effect=httpx.ConnectTimeout("timeout"))
    r = virustotal.lookup_ip("1.2.3.8")
    assert r.status == "error"


@respx.mock
def test_malformed_json(fast_net):
    respx.get("https://www.virustotal.com/api/v3/ip_addresses/1.2.3.9").mock(
        return_value=httpx.Response(200, text="not-json{{"))
    r = virustotal.lookup_ip("1.2.3.9")
    assert r.status == "error" and "malformed" in r.error.lower()


@respx.mock
def test_nvd_no_key_still_works(fast_net, monkeypatch):
    """NVD is usable without a key (lower rate limit)."""
    monkeypatch.setitem(config.API_KEYS, "nvd", None)
    respx.get(url__startswith="https://services.nvd.nist.gov/rest/json/cves/2.0").mock(
        return_value=httpx.Response(200, json={"totalResults": 1, "vulnerabilities": [
            {"cve": {"id": "CVE-2021-26084", "descriptions": [{"lang": "en", "value": "RCE"}],
                     "metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": 9.8, "baseSeverity": "CRITICAL"}}]}}}]}))
    r = nvd.search("Confluence 7.13")
    assert r.status == "ok" and r.data["cves"][0]["id"] == "CVE-2021-26084"
