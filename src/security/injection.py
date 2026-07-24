"""Direct prompt-injection scanner for user chat input (zero LLM cost).

Layer 1 of defense. Heuristic/regex only — deliberately fast and deterministic.
It is intentionally miss-tolerant: the real backstops are (a) the router can
only emit a fixed intent enum, and (b) the synthesis prompt treats retrieved
data as untrusted. This layer catches the obvious, logs it, and lets the UI
show the analyst that a block happened.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field

# (category, pattern). Case-insensitive. Targeted to avoid firing on normal
# threat-intel phrasing ("ignore" alone is fine; "ignore previous instructions"
# is not).
_RAW_PATTERNS: list[tuple[str, str]] = [
    ("instruction_override",
     r"\b(ignore|disregard|forget)\b[^.\n]{0,40}\b(previous|prior|above|earlier|preceding|all|any|your)\b[^.\n]{0,25}\b(instruction|instructions|prompt|prompts|rule|rules|context|message|messages)\b"),
    ("instruction_override",
     r"\bnew\s+(instruction|instructions|rule|rules|system\s+prompt)\b\s*[:\-]"),
    ("system_prompt_exfil",
     r"\b(reveal|show|print|repeat|expose|display|output|leak|give\s+me|tell\s+me)\b[^.\n]{0,30}\b(your|system|initial|original)\s+(system\s+|initial\s+|original\s+)?(prompt|instructions|rules|guidelines|configuration)\b"),
    ("system_prompt_exfil",
     r"\bwhat\s+(is|are)\s+your\s+(system\s+)?(prompt|instructions|rules|guidelines)\b"),
    ("role_reassignment",
     r"\byou\s+are\s+now\b"),
    ("role_reassignment",
     r"\b(pretend|act)\s+(to\s+be|as\s+if|as)\b[^.\n]{0,30}\b(unrestricted|jailbroken|dan|no\s+rules|no\s+restrictions|evil|admin|developer)\b"),
    ("jailbreak",
     r"\b(jailbreak|do\s+anything\s+now|dan\s+mode|developer\s+mode|god\s+mode)\b"),
    ("guardrail_bypass",
     r"\b(override|bypass|disable|turn\s+off|remove)\b[^.\n]{0,25}\b(instruction|instructions|rule|rules|safety|guardrail|guardrails|filter|filters|restriction|restrictions)\b"),
    ("secret_exfil",
     r"\b(api[\s_-]*key|api[\s_-]*keys|secret|secrets|token|credentials|password)\b[^.\n]{0,20}\b(reveal|show|print|give|leak|expose|what)\b"),
    ("secret_exfil",
     r"\b(reveal|show|print|give\s+me|leak|expose|what('?s| is)?)\b[^.\n]{0,20}\b(api[\s_-]*key|api[\s_-]*keys|secret\s+key|credentials|password)\b"),
    ("tag_injection",
     r"</?\s*(system|assistant|instructions?|prompt)\s*>"),
    ("tag_injection",
     r"\[\s*(system|inst|admin|assistant)\s*\]"),
    ("encoded_payload",
     r"\bdecode\b[^.\n]{0,25}\b(base64|hex|rot13|the\s+following)\b"),
    # --- hardening (added after VAPT: catch obvious attacks at layer 1) ---
    ("instruction_override",
     r"\bforget\s+(everything|all|it\s+all)\b"),
    ("instruction_override",
     r"\bignore\s+(the\s+|all\s+)?(evidence|findings?|results?|analysis)\b"),
    ("instruction_override",
     r"\bnew\s+directive\b"),
    ("role_reassignment",
     r"\bfrom\s+now\s+on\s+you\s+(are|will|must|should|shall)\b"),
    ("role_reassignment",
     r"\byou\s+are\s+[a-z0-9_-]*bot\b"),
    ("role_prefix_injection",
     r"^\s*(system|assistant|developer|admin|root)\s*:\s*\S"),
    ("jailbreak",
     r"\b(no\s+filters?|without\s+(any\s+)?(filters?|restrictions?|limits?))\b"),
    ("code_exfil",
     r"\bopen\s*\(\s*['\"][^'\"]*\.env"),
    ("code_exfil",
     r"\bos\.environ\b|\bsubprocess\b|\bexec\s*\(|\beval\s*\(|__import__|\bread\s*\(\s*\)"),
]

PATTERNS: list[tuple[str, re.Pattern]] = [
    (name, re.compile(pat, re.IGNORECASE)) for name, pat in _RAW_PATTERNS
]

# Categories that only make sense as an attack on the ASSISTANT itself. These
# are the only ones the indirect sanitizer scans retrieved data for — because
# technique-jargon categories (guardrail_bypass, secret_exfil, code_exfil,
# encoded_payload) legitimately appear in CVE and malware descriptions
# ("bypass authentication", "uses exec()", "decodes base64") and must NOT be
# treated as injection when they come from a threat-intel source.
AGENT_DIRECTED = frozenset({
    "instruction_override", "role_reassignment", "jailbreak",
    "system_prompt_exfil", "tag_injection", "role_prefix_injection",
})


@dataclass
class InjectionVerdict:
    blocked: bool
    categories: list[str] = field(default_factory=list)

    @property
    def summary(self) -> str:
        return ", ".join(sorted(set(self.categories))) or "none"


def find_matches(text: str, only: frozenset[str] | None = None) -> list[str]:
    """Return the categories of every pattern that fires on `text`.

    `only` restricts the scan to a subset of categories (the sanitizer passes
    AGENT_DIRECTED so benign CVE/malware jargon isn't flagged as injection).
    """
    if not text:
        return []
    return [name for name, pat in PATTERNS
            if (only is None or name in only) and pat.search(text)]


def scan_input(text: str) -> InjectionVerdict:
    """Verdict for a user-typed message. Any match => block."""
    cats = find_matches(text)
    return InjectionVerdict(blocked=bool(cats), categories=cats)


REFUSAL_MESSAGE = (
    "⚠️ **Request blocked by the input guard.** That message looks like a "
    "prompt-injection or scope-manipulation attempt (e.g. trying to override my "
    "instructions or extract my configuration), so I won't act on it.\n\n"
    "I'm a threat-intelligence assistant — ask me to check an IP, domain, or file "
    "hash, profile a threat actor, assess a software version's exposure, or pivot "
    "between related indicators."
)
