"""Prompt injection detection via deterministic rules and patterns."""

from __future__ import annotations

import re
from dataclasses import dataclass

from agentwall.models.types import ThreatMatch, ThreatType, TrustLevel


@dataclass(frozen=True)
class InjectionPattern:
    name: str
    pattern: re.Pattern[str]
    score: float
    detail: str


# High-signal instruction-override patterns
_PATTERNS: list[InjectionPattern] = [
    InjectionPattern(
        name="ignore_previous",
        pattern=re.compile(
            r"(?i)\b(ignore|disregard|forget|override)\b.{0,40}\b(previous|prior|above|"
            r"all)\b.{0,40}\b(instructions?|prompts?|rules?|guidelines?)\b"
        ),
        score=0.95,
        detail="Attempts to override prior instructions",
    ),
    InjectionPattern(
        name="ignore_all",
        pattern=re.compile(
            r"(?i)\bignore\s+all\s+(previous|prior|above)?\s*(instructions?|prompts?|rules?)\b"
        ),
        score=0.98,
        detail="Explicit ignore-all-instructions directive",
    ),
    InjectionPattern(
        name="system_roleplay",
        pattern=re.compile(
            r"(?i)\b(you\s+are\s+now|act\s+as|pretend\s+(to\s+be|you\s+are)|from\s+now\s+on\s+you)\b"
            r".{0,60}\b(system|admin|developer|jailbreak|unrestricted|DAN)\b"
        ),
        score=0.85,
        detail="Role-hijack / jailbreak attempt",
    ),
    InjectionPattern(
        name="fake_system_message",
        pattern=re.compile(
            r"(?i)(important\s+)?(system\s+)?(message|prompt|instruction)\s*[:：]"
            r"|(?:^|\n)\s*\[?\s*system\s*\]?\s*:"
            r"|(?:^|\n)\s*<\s*system\s*>"
        ),
        score=0.80,
        detail="Fabricated system message marker",
    ),
    InjectionPattern(
        name="reveal_secrets",
        pattern=re.compile(
            r"(?i)\b(reveal|show|print|dump|exfiltrate|send|leak)\b.{0,40}\b("
            r"system\s+prompt|api\s*key|secret|password|token|credentials?|"
            r"private\s+key|\.ssh|id_rsa|\.env)\b"
        ),
        score=0.92,
        detail="Requests disclosure of secrets or system prompt",
    ),
    InjectionPattern(
        name="new_instructions",
        pattern=re.compile(
            r"(?i)\b(new\s+instructions?|updated\s+instructions?|revised\s+instructions?)\s*[:：]"
        ),
        score=0.75,
        detail="Injected 'new instructions' block",
    ),
    InjectionPattern(
        name="do_anything_now",
        pattern=re.compile(r"(?i)\b(do\s+anything\s+now|DAN\s+mode|developer\s+mode\s+enabled)\b"),
        score=0.90,
        detail="Known jailbreak phrase",
    ),
    InjectionPattern(
        name="bypass_safety",
        pattern=re.compile(
            r"(?i)\b(bypass|disable|turn\s+off|remove)\b.{0,30}\b("
            r"safety|filter|guardrail|restriction|content\s+polic)\w*\b"
        ),
        score=0.85,
        detail="Attempts to disable safety controls",
    ),
    InjectionPattern(
        name="hidden_instruction",
        pattern=re.compile(
            r"(?i)(<!--.{0,200}(ignore|instruction|system).{0,200}-->)"
            r"|(\[INST\])|(\[/INST\])|(<<SYS>>)|(<\/?sys>)"
        ),
        score=0.80,
        detail="Hidden or markup-wrapped instruction",
    ),
    InjectionPattern(
        name="tool_exfil_combo",
        pattern=re.compile(
            r"(?i)\b(read|cat|open|access)\b.{0,60}\b("
            r"~/?\.ssh|id_rsa|\.aws/credentials|\.env|passwd)\b"
            r".{0,80}\b(send|post|upload|curl|wget|exfiltrate|transmit)\b"
        ),
        score=0.98,
        detail="Read-credentials-and-exfiltrate pattern",
    ),
]


def normalize_text(text: str) -> str:
    """Light normalization before pattern matching."""
    text = text.replace("\u200b", "").replace("\ufeff", "")
    text = re.sub(r"[ \t]+", " ", text)
    # Decode common leetspeak / spacing tricks for key phrases
    text = re.sub(r"(?i)i\s*g\s*n\s*o\s*r\s*e", "ignore", text)
    return text


class InjectionScanner:
    """Detect prompt-injection attempts without requiring an LLM."""

    def __init__(self, patterns: list[InjectionPattern] | None = None) -> None:
        self.patterns = patterns or list(_PATTERNS)

    def scan(
        self,
        text: str,
        *,
        trust: TrustLevel | str = TrustLevel.UNKNOWN,
    ) -> list[ThreatMatch]:
        if not text or not text.strip():
            return []

        normalized = normalize_text(text)
        matches: list[ThreatMatch] = []
        trust_val = TrustLevel(trust) if isinstance(trust, str) else trust

        for pattern in self.patterns:
            m = pattern.pattern.search(normalized)
            if not m:
                continue
            score = pattern.score
            # Stricter on untrusted sources (web, docs, email, tool output)
            if trust_val == TrustLevel.UNTRUSTED:
                score = min(1.0, score + 0.05)
            elif trust_val == TrustLevel.TRUSTED:
                score = max(0.0, score - 0.15)

            evidence = m.group(0)[:120]
            threat = ThreatType.PROMPT_INJECTION
            if pattern.name in {"reveal_secrets", "tool_exfil_combo"}:
                threat = ThreatType.CREDENTIAL_EXFILTRATION

            matches.append(
                ThreatMatch(
                    threat=threat,
                    score=score,
                    detail=pattern.detail,
                    evidence=evidence,
                    rule=f"injection.{pattern.name}",
                )
            )

        return matches
