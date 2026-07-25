"""Deterministic routing pieces: IOC extraction, classification, private-IP
handling, confidence scoring, and the LLM-less router fallback."""
from __future__ import annotations

from langchain_core.messages import HumanMessage

from src.agent import confidence, nodes
from src.ioc import classify, extract_entities, is_private_ip, valid_public_ip
from src.schemas import ToolResult


def test_extract_entities_ip_hash_domain_cve():
    ents = extract_entities(
        "check 45.83.122.10 and evil.example.com and CVE-2021-26084 and "
        "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f")
    types = {e.type for e in ents}
    assert {"ip", "domain", "cve", "hash"} <= types


def test_private_ip_detection():
    assert is_private_ip("192.168.1.1")
    assert is_private_ip("10.0.0.5")
    assert not is_private_ip("8.8.8.8")
    assert valid_public_ip("8.8.8.8")
    assert not valid_public_ip("192.168.1.1")


def test_classify():
    assert classify("8.8.8.8") == "ip"
    assert classify("CVE-2021-26084") == "cve"
    assert classify("example.com") == "domain"
    assert classify("Confluence") == "product"


def test_router_fallback_without_llm():
    """No LLM key -> deterministic fallback still routes an IOC query."""
    state = {"messages": [HumanMessage("Is 8.8.8.8 malicious?")], "trace": nodes._blank_trace()}
    out = nodes.route_and_resolve(state)
    assert out["route"]["intent"] == "ioc_lookup"
    assert any(e["type"] == "ip" for e in out["route"]["entities"])


def test_confidence_high_when_corroborated():
    results = [
        ToolResult(source="VirusTotal", status="ok",
                   data={"stats": {"malicious": 40, "suspicious": 2, "harmless": 15}}),
        ToolResult(source="AbuseIPDB", status="ok",
                   data={"abuse_confidence_score": 100, "total_reports": 600}),
    ]
    r = confidence.score(results, "ioc_lookup")
    assert r.band == "high" and r.verdict == "Malicious"


def test_confidence_low_when_no_data():
    results = [ToolResult(source="VirusTotal", status="rate_limited")]
    r = confidence.score(results, "ioc_lookup")
    assert r.band == "low" and r.verdict == "Inconclusive"


def test_confidence_conflict_lowers():
    results = [
        ToolResult(source="VirusTotal", status="ok", data={"stats": {"malicious": 30, "harmless": 5}}),
        ToolResult(source="AbuseIPDB", status="ok", data={"abuse_confidence_score": 0, "total_reports": 0}),
        ToolResult(source="AlienVault OTX", status="ok", data={"pulse_count": 0}),
    ]
    r = confidence.score(results, "ioc_lookup")
    assert r.band in ("medium", "low") and r.confidence < 70


def test_confidence_ratio_aware():
    """3/90 detections must be less certain than 40/10 (denominator/consensus)."""
    weak = confidence.score(
        [ToolResult(source="VirusTotal", status="ok", data={"stats": {"malicious": 3, "harmless": 88}})],
        "ioc_lookup")
    strong = confidence.score(
        [ToolResult(source="VirusTotal", status="ok", data={"stats": {"malicious": 40, "harmless": 10}})],
        "ioc_lookup")
    assert weak.confidence < strong.confidence


def test_confidence_injection_caps():
    """A tampered (Layer-2 flagged) source cannot produce high confidence."""
    results = [
        ToolResult(source="VirusTotal", status="ok", data={"stats": {"malicious": 40, "harmless": 5}}),
        ToolResult(source="AlienVault OTX", status="ok", data={"pulse_count": 9},
                   suspicion_flags=["instruction_override"]),
    ]
    r = confidence.score(results, "ioc_lookup")
    assert r.confidence <= 60 and r.band != "high"


def test_confidence_verdicts_by_intent():
    exp = confidence.score(
        [ToolResult(source="NVD", status="ok", data={"cves": [{"severity": "CRITICAL"}]})], "exposure_check")
    assert exp.verdict.startswith("Exposed") and exp.band == "high"
    act = confidence.score(
        [ToolResult(source="MITRE ATT&CK", status="ok", data={"group": "APT29"})], "actor_profile")
    assert act.verdict.startswith("Profiled") and act.band == "high"


def test_confidence_selfcheck():
    confidence._demo()  # runnable model self-check


def test_format_caveats_splits_to_new_line_without_asterisks():
    text = "Item 2 [NVD]. Caveats: ** The evidence provided does not explicitly confirm version."
    formatted = nodes._format_caveats(text)
    assert "\n\nCaveats: The evidence provided" in formatted
    assert "**" not in formatted

