"""Deterministic IOC extraction/classification.

Backs up the LLM router: even if entity extraction is imperfect, regex-detected
indicators still drive tool selection. Also flags private/reserved IPs so we
don't waste API calls on them.
"""
from __future__ import annotations

import ipaddress
import re

from .schemas import Entity

IPV4_RE = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b")
HASH_RE = re.compile(r"\b[a-fA-F0-9]{64}|\b[a-fA-F0-9]{40}\b|\b[a-fA-F0-9]{32}\b")
CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE)
# domain: at least one dot, valid TLD-ish; excludes things caught as IP.
DOMAIN_RE = re.compile(
    r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,24}\b"
)

_HASH_LEN_OK = {32, 40, 64}


def is_private_ip(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
        return addr.is_private or addr.is_loopback or addr.is_reserved or addr.is_link_local
    except ValueError:
        return False


def valid_public_ip(ip: str) -> bool:
    try:
        ipaddress.ip_address(ip)
        return not is_private_ip(ip)
    except ValueError:
        return False


def extract_entities(text: str) -> list[Entity]:
    """Regex pass over raw text -> typed entities (dedup, order-stable)."""
    found: list[Entity] = []
    seen: set[tuple[str, str]] = set()

    def add(value: str, etype: str) -> None:
        key = (value.lower(), etype)
        if key not in seen:
            seen.add(key)
            found.append(Entity(value=value, type=etype))

    if not text:
        return found

    for m in CVE_RE.finditer(text):
        add(m.group(0).upper(), "cve")
    ips = set()
    for m in IPV4_RE.finditer(text):
        ips.add(m.group(0))
        add(m.group(0), "ip")
    for m in HASH_RE.finditer(text):
        h = m.group(0)
        if len(h) in _HASH_LEN_OK:
            add(h.lower(), "hash")
    for m in DOMAIN_RE.finditer(text):
        d = m.group(0)
        if d in ips:
            continue
        # skip if it's actually the tail of an IP or an email-ish artifact
        if d.replace(".", "").isdigit():
            continue
        add(d.lower(), "domain")
    return found


def classify(value: str) -> str:
    if CVE_RE.fullmatch(value):
        return "cve"
    if IPV4_RE.fullmatch(value):
        return "ip"
    if HASH_RE.fullmatch(value) and len(value) in _HASH_LEN_OK:
        return "hash"
    if DOMAIN_RE.fullmatch(value):
        return "domain"
    return "product"
