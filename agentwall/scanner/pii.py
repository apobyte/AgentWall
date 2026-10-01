"""Lightweight PII pattern scanner for output guarding."""

from __future__ import annotations

import re
from dataclasses import dataclass

from agentwall.models.types import ThreatMatch, ThreatType


@dataclass(frozen=True)
class PIIPattern:
    name: str
    pattern: re.Pattern[str]
    score: float
    detail: str


_PII_PATTERNS: list[PIIPattern] = [
    PIIPattern(
        name="email",
        pattern=re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"),
        score=0.40,
        detail="Email address",
    ),
    PIIPattern(
        name="ssn",
        pattern=re.compile(r"\b\d{3}-\d{2}-\d{4}\b"),
        score=0.90,
        detail="US Social Security Number pattern",
    ),
    PIIPattern(
        name="credit_card",
        pattern=re.compile(r"\b(?:\d[ -]*?){13,19}\b"),
        score=0.55,
        detail="Possible credit card number",
    ),
    PIIPattern(
        name="phone",
        pattern=re.compile(
            r"\b(?:\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b"
        ),
        score=0.35,
        detail="Phone number",
    ),
]


def _luhn_ok(number: str) -> bool:
    digits = [int(c) for c in number if c.isdigit()]
    if len(digits) < 13 or len(digits) > 19:
        return False
    checksum = 0
    parity = len(digits) % 2
    for i, d in enumerate(digits):
        if i % 2 == parity:
            d *= 2
            if d > 9:
                d -= 9
        checksum += d
    return checksum % 10 == 0


class PIIScanner:
    """Detect common PII patterns in agent output."""

    def __init__(self, patterns: list[PIIPattern] | None = None) -> None:
        self.patterns = patterns or list(_PII_PATTERNS)

    def scan(self, text: str) -> list[ThreatMatch]:
        if not text:
            return []

        matches: list[ThreatMatch] = []
        for pattern in self.patterns:
            for m in pattern.pattern.finditer(text):
                value = m.group(0)
                if pattern.name == "credit_card" and not _luhn_ok(value):
                    continue
                matches.append(
                    ThreatMatch(
                        threat=ThreatType.PII_LEAKAGE,
                        score=pattern.score,
                        detail=pattern.detail,
                        evidence=value[:6] + "…" if len(value) > 8 else "***",
                        rule=f"pii.{pattern.name}",
                    )
                )
        return matches
