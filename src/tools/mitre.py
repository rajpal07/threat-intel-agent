"""MITRE ATT&CK actor lookup from a bundled, offline JSON subset.

Offline and unlimited: covers 'What TTPs is APT29 known for?' even when OTX is
down or unkeyed. Data is a curated subset of ATT&CK Enterprise groups; see
data/mitre_attack_trimmed.json.
"""
from __future__ import annotations

import json
from functools import lru_cache

from ..config import MITRE_FILE
from ..schemas import ToolResult

SOURCE = "MITRE ATT&CK"


@lru_cache(maxsize=1)
def _load() -> dict:
    try:
        return json.loads(MITRE_FILE.read_text(encoding="utf-8"))
    except Exception:
        return {"groups": []}


def _norm(s: str) -> str:
    return "".join(ch for ch in s.lower() if ch.isalnum())


def lookup_actor(name: str) -> ToolResult:
    groups = _load().get("groups", [])
    target = _norm(name)
    match = None
    for g in groups:
        names = [g.get("name", "")] + (g.get("aliases") or [])
        for n in names:
            nn = _norm(n)
            if not nn:
                continue
            # exact, OR alias appears inside a longer query, OR query inside alias
            if target == nn or (len(nn) >= 4 and nn in target) or (len(target) >= 4 and target in nn):
                match = g
                break
        if match:
            break

    if not match:
        return ToolResult(
            source=SOURCE, endpoint="groups", status="no_data",
            error=f"'{name}' not in bundled ATT&CK subset",
            data={"known_groups": [g["name"] for g in groups]},
        )

    return ToolResult(
        source=SOURCE, endpoint="groups", status="ok",
        data={
            "group": match.get("name"),
            "aliases": match.get("aliases", []),
            "description": match.get("description", ""),
            "techniques": match.get("techniques", []),
            "software": match.get("software", []),
        },
    )
