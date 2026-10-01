"""Audit logging for AgentWall decisions."""

from __future__ import annotations

import json
import threading
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


@dataclass
class AuditEvent:
    timestamp: str
    event_type: str
    action: str
    risk: float
    risk_level: str
    threats: list[str] = field(default_factory=list)
    reasons: list[str] = field(default_factory=list)
    resource: str | None = None
    rule: str | None = None
    detail: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class AuditLogger:
    """Append-only JSONL audit trail of AgentWall decisions."""

    def __init__(
        self,
        path: str | Path | None = None,
        *,
        enabled: bool = True,
        memory_limit: int = 1000,
    ) -> None:
        self.enabled = enabled
        self.path = Path(path) if path else None
        self.memory_limit = memory_limit
        self._events: list[AuditEvent] = []
        self._lock = threading.Lock()

        if self.path:
            self.path.parent.mkdir(parents=True, exist_ok=True)

    def log(
        self,
        event_type: str,
        *,
        action: str,
        risk: float,
        risk_level: str,
        threats: list[str] | None = None,
        reasons: list[str] | None = None,
        resource: str | None = None,
        rule: str | None = None,
        detail: dict[str, Any] | None = None,
    ) -> AuditEvent | None:
        if not self.enabled:
            return None

        event = AuditEvent(
            timestamp=datetime.now(timezone.utc).isoformat(),
            event_type=event_type,
            action=action,
            risk=round(risk, 2),
            risk_level=risk_level,
            threats=threats or [],
            reasons=reasons or [],
            resource=resource,
            rule=rule,
            detail=detail or {},
        )

        with self._lock:
            self._events.append(event)
            if len(self._events) > self.memory_limit:
                self._events = self._events[-self.memory_limit :]
            if self.path:
                with self.path.open("a", encoding="utf-8") as fh:
                    fh.write(json.dumps(event.to_dict(), ensure_ascii=False) + "\n")

        return event

    def recent(self, limit: int = 20) -> list[AuditEvent]:
        with self._lock:
            return list(self._events[-limit:])

    def clear(self) -> None:
        with self._lock:
            self._events.clear()

    def stats(self) -> dict[str, Any]:
        with self._lock:
            events = list(self._events)
        total = len(events)
        blocked = sum(1 for e in events if e.action == "block")
        review = sum(1 for e in events if e.action == "review")
        allowed = sum(1 for e in events if e.action == "allow")
        critical = sum(1 for e in events if e.risk_level == "critical")
        return {
            "total": total,
            "allowed": allowed,
            "review": review,
            "blocked": blocked,
            "critical": critical,
        }
