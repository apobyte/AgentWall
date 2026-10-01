"""Secret and credential pattern scanner."""

from __future__ import annotations

import re
from dataclasses import dataclass

from agentwall.models.types import ThreatMatch, ThreatType


@dataclass(frozen=True)
class SecretPattern:
    name: str
    pattern: re.Pattern[str]
    score: float
    detail: str


_SECRET_PATTERNS: list[SecretPattern] = [
    SecretPattern(
        name="aws_access_key",
        pattern=re.compile(r"\b(AKIA[0-9A-Z]{16})\b"),
        score=0.98,
        detail="AWS access key ID",
    ),
    SecretPattern(
        name="aws_secret_key",
        pattern=re.compile(
            r"(?i)(aws_secret_access_key|aws_secret_key)\s*[=:]\s*['\"]?([A-Za-z0-9/+=]{40})['\"]?"
        ),
        score=0.95,
        detail="AWS secret access key",
    ),
    SecretPattern(
        name="github_token",
        pattern=re.compile(r"\b(gh[pousr]_[A-Za-z0-9_]{36,})\b"),
        score=0.98,
        detail="GitHub personal/OAuth/user token",
    ),
    SecretPattern(
        name="github_fine_grained",
        pattern=re.compile(r"\b(github_pat_[A-Za-z0-9_]{20,})\b"),
        score=0.98,
        detail="GitHub fine-grained personal access token",
    ),
    SecretPattern(
        name="openai_key",
        pattern=re.compile(r"\b(sk-[A-Za-z0-9]{20,})\b"),
        score=0.95,
        detail="OpenAI-style API key",
    ),
    SecretPattern(
        name="anthropic_key",
        pattern=re.compile(r"\b(sk-ant-[A-Za-z0-9\-_]{20,})\b"),
        score=0.98,
        detail="Anthropic API key",
    ),
    SecretPattern(
        name="slack_token",
        pattern=re.compile(r"\b(xox[baprs]-[A-Za-z0-9-]{10,})\b"),
        score=0.95,
        detail="Slack token",
    ),
    SecretPattern(
        name="private_key",
        pattern=re.compile(
            r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----"
        ),
        score=1.0,
        detail="PEM/OpenSSH private key material",
    ),
    SecretPattern(
        name="generic_api_key",
        pattern=re.compile(
            r"(?i)(?:api[_-]?key|apikey|access[_-]?token|auth[_-]?token|secret[_-]?key)"
            r"\s*[=:]\s*['\"]?([A-Za-z0-9_\-]{20,})['\"]?"
        ),
        score=0.75,
        detail="Generic API key / token assignment",
    ),
    SecretPattern(
        name="password_assignment",
        pattern=re.compile(
            r"(?i)(?:password|passwd|pwd)\s*[=:]\s*['\"]([^'\"]{6,})['\"]"
        ),
        score=0.70,
        detail="Hardcoded password assignment",
    ),
    SecretPattern(
        name="jwt",
        pattern=re.compile(
            r"\b(eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,})\b"
        ),
        score=0.80,
        detail="JSON Web Token",
    ),
    SecretPattern(
        name="connection_string",
        pattern=re.compile(
            r"(?i)(postgres|mysql|mongodb|redis|amqp)://[^\s:]+:[^\s@]+@[^\s]+"
        ),
        score=0.90,
        detail="Database connection string with credentials",
    ),
]

# Paths that strongly imply credential access intent in free text
_CREDENTIAL_PATH_HINTS = re.compile(
    r"(?i)\b(read|cat|open|access|exfiltrate|steal|dump|send|upload|copy|print|show|reveal)\b"
    r".{0,80}"
    r"(~/?\.ssh(?:/id_rsa|/id_ed25519|/id_ecdsa)?|"
    r"~/?\.aws/credentials|"
    r"~/?\.gnupg|"
    r"(?:^|[\s\"'`])\.env(?:\.\w+)?|"
    r"/etc/shadow|"
    r"credentials\.json|"
    r"service[_-]?account\.json)"
    r"|"
    r"(~/?\.ssh(?:/id_rsa|/id_ed25519|/id_ecdsa)?|"
    r"~/?\.aws/credentials|"
    r"/etc/shadow)"
    r".{0,80}"
    r"\b(read|cat|open|access|exfiltrate|steal|dump|send|upload|copy|print|show|reveal)\b"
)


def _redact(value: str, keep: int = 4) -> str:
    if len(value) <= keep * 2:
        return "***"
    return f"{value[:keep]}…{value[-keep:]}"


class SecretScanner:
    """Detect secrets, tokens, and credential material in text."""

    def __init__(self, patterns: list[SecretPattern] | None = None) -> None:
        self.patterns = patterns or list(_SECRET_PATTERNS)

    def scan(self, text: str) -> list[ThreatMatch]:
        if not text:
            return []

        matches: list[ThreatMatch] = []
        for pattern in self.patterns:
            for m in pattern.pattern.finditer(text):
                evidence = _redact(m.group(0))
                matches.append(
                    ThreatMatch(
                        threat=ThreatType.SECRET_EXPOSURE,
                        score=pattern.score,
                        detail=pattern.detail,
                        evidence=evidence,
                        rule=f"secrets.{pattern.name}",
                    )
                )

        path_hit = _CREDENTIAL_PATH_HINTS.search(text)
        if path_hit:
            matches.append(
                ThreatMatch(
                    threat=ThreatType.CREDENTIAL_EXFILTRATION,
                    score=0.85,
                    detail="References protected credential path",
                    evidence=path_hit.group(0),
                    rule="secrets.credential_path",
                )
            )

        return matches
