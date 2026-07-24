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
        ToolResult(source="VirusTotal", status="ok", data={"stats": {"malicious": 11}}),
        ToolResult(source="AbuseIPDB", status="ok", data={"abuse_confidence_score": 100}),
    ]
    level, _ = confidence.score(results)
    assert level == "high"


def test_confidence_low_when_no_data():
    results = [ToolResult(source="VirusTotal", status="rate_limited")]
    level, _ = confidence.score(results)
    assert level == "low"


def test_confidence_conflict_capped():
    results = [
        ToolResult(source="VirusTotal", status="ok", data={"stats": {"malicious": 11}}),
        ToolResult(source="AbuseIPDB", status="ok", data={"abuse_confidence_score": 0}),
        ToolResult(source="AlienVault OTX", status="ok", data={"pulse_count": 0}),
    ]
    level, rationale = confidence.score(results)
    assert level == "medium" and "disagree" in rationale.lower()
