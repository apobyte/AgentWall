"""Shared types and data models for AgentWall."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class Decision(str, Enum):
    ALLOW = "allow"
    REVIEW = "review"
    BLOCK = "block"


class RiskLevel(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class ThreatType(str, Enum):
    PROMPT_INJECTION = "prompt_injection"
    SECRET_EXPOSURE = "secret_exposure"
    CREDENTIAL_EXFILTRATION = "credential_exfiltration"
    DANGEROUS_SHELL = "dangerous_shell"
    UNAUTHORIZED_FILE_ACCESS = "unauthorized_file_access"
    UNAUTHORIZED_NETWORK = "unauthorized_network"
    PII_LEAKAGE = "pii_leakage"
    DESTRUCTIVE_COMMAND = "destructive_command"
    POLICY_VIOLATION = "policy_violation"


class TrustLevel(str, Enum):
    TRUSTED = "trusted"
    UNTRUSTED = "untrusted"
    UNKNOWN = "unknown"


class ContentSource(str, Enum):
    USER = "user"
    SYSTEM = "system"
    WEB = "web"
    DOCUMENT = "document"
    EMAIL = "email"
    TOOL = "tool"
    UNKNOWN = "unknown"


@dataclass
class ContentEnvelope:
    """Content with provenance — keeps untrusted data distinct from instructions."""

    content: str
    source: ContentSource | str = ContentSource.UNKNOWN
    trust: TrustLevel | str = TrustLevel.UNKNOWN
    url: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if isinstance(self.source, str):
            try:
                self.source = ContentSource(self.source)
            except ValueError:
                self.source = ContentSource.UNKNOWN
        if isinstance(self.trust, str):
            try:
                self.trust = TrustLevel(self.trust)
            except ValueError:
                self.trust = TrustLevel.UNKNOWN


@dataclass
class ThreatMatch:
    threat: ThreatType
    score: float
    detail: str
    evidence: str | None = None
    rule: str | None = None


@dataclass
class ScanResult:
    """Result of scanning input/output content."""

    allowed: bool
    risk: float
    risk_level: RiskLevel
    threats: list[ThreatType]
    action: Decision
    matches: list[ThreatMatch] = field(default_factory=list)
    reasons: list[str] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "allowed": self.allowed,
            "risk": round(self.risk, 2),
            "risk_level": self.risk_level.value,
            "threats": [t.value for t in self.threats],
            "action": self.action.value,
            "matches": [
                {
                    "threat": m.threat.value,
                    "score": m.score,
                    "detail": m.detail,
                    "evidence": m.evidence,
                    "rule": m.rule,
                }
                for m in self.matches
            ],
            "reasons": self.reasons,
            "metadata": self.metadata,
        }

    def __str__(self) -> str:
        if not self.threats:
            return (
                f"Risk: {self.risk_level.value.upper()} ({self.risk:.0f})\n"
                f"Decision: {self.action.value.upper()}"
            )
        threat_names = ", ".join(t.value.upper() for t in self.threats)
        lines = [
            f"Threat: {threat_names}",
            f"Risk: {self.risk_level.value.upper()} ({self.risk:.0f}/100)",
            f"Decision: {self.action.value.upper()}",
        ]
        if self.reasons:
            lines.append(f"Reason: {self.reasons[0]}")
        return "\n".join(lines)


@dataclass
class ToolCall:
    """A tool invocation requested by an agent."""

    tool: str
    arguments: dict[str, Any] = field(default_factory=dict)
    command: str | None = None
    path: str | None = None
    url: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if self.command is None and "command" in self.arguments:
            self.command = str(self.arguments["command"])
        if self.path is None and "path" in self.arguments:
            self.path = str(self.arguments["path"])
        if self.url is None and "url" in self.arguments:
            self.url = str(self.arguments["url"])


@dataclass
class ToolDecision:
    """Decision on whether an agent may execute a tool call."""

    allowed: bool
    risk: float
    risk_level: RiskLevel
    action: Decision
    threats: list[ThreatType] = field(default_factory=list)
    matches: list[ThreatMatch] = field(default_factory=list)
    reasons: list[str] = field(default_factory=list)
    rule: str | None = None
    resource: str | None = None
    require_confirmation: bool = False
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "allowed": self.allowed,
            "risk": round(self.risk, 2),
            "risk_level": self.risk_level.value,
            "action": self.action.value,
            "threats": [t.value for t in self.threats],
            "matches": [
                {
                    "threat": m.threat.value,
                    "score": m.score,
                    "detail": m.detail,
                    "evidence": m.evidence,
                    "rule": m.rule,
                }
                for m in self.matches
            ],
            "reasons": self.reasons,
            "rule": self.rule,
            "resource": self.resource,
            "require_confirmation": self.require_confirmation,
            "metadata": self.metadata,
        }

    def __str__(self) -> str:
        status = (
            "BLOCKED" if self.action == Decision.BLOCK else self.action.value.upper()
        )
        lines = [status]
        if self.rule:
            lines.append(f"Rule: {self.rule}")
        if self.resource:
            lines.append(f"Resource: {self.resource}")
        lines.append(f"Risk: {self.risk_level.value.upper()} ({self.risk:.0f}/100)")
        if self.reasons:
            lines.append(f"Reason: {self.reasons[0]}")
        if self.require_confirmation:
            lines.append("! Requires human confirmation")
        return "\n".join(lines)
