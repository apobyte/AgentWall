"""AgentWall Shield — main security facade for AI agents."""

from __future__ import annotations

from functools import wraps
from pathlib import Path
from typing import Any, Callable, TypeVar

from agentwall.audit.logger import AuditLogger
from agentwall.models.types import (
    ContentEnvelope,
    ContentSource,
    Decision,
    ScanResult,
    ThreatMatch,
    ThreatType,
    ToolCall,
    ToolDecision,
    TrustLevel,
)
from agentwall.policy.engine import PolicyEngine
from agentwall.policy.parser import Policy, default_policy, load_policy
from agentwall.risk.scorer import RiskScorer
from agentwall.scanner.injection import InjectionScanner
from agentwall.scanner.pii import PIIScanner
from agentwall.scanner.secrets import SecretScanner
from agentwall.tools.filesystem import FilesystemGuard
from agentwall.tools.network import NetworkGuard
from agentwall.tools.shell import ShellGuard

F = TypeVar("F", bound=Callable[..., Any])

_UNTRUSTED_SOURCES = {
    ContentSource.WEB,
    ContentSource.DOCUMENT,
    ContentSource.EMAIL,
    ContentSource.TOOL,
}


class Shield:
    """
    Local security firewall for AI agents.

    Sits before the model (input/output scanning) and after the model
    (tool-call gating) without requiring an LLM.
    """

    def __init__(
        self,
        policy: Policy | str | Path | None = None,
        *,
        audit_path: str | Path | None = None,
        audit: bool = True,
        scorer: RiskScorer | None = None,
    ) -> None:
        if isinstance(policy, (str, Path)):
            self.policy = load_policy(policy)
        elif policy is None:
            self.policy = default_policy()
        else:
            self.policy = policy

        self.policy_engine = PolicyEngine(self.policy)
        self.scorer = scorer or RiskScorer(
            allow_below=self.policy.risk.allow_below,
            review_below=self.policy.risk.review_below,
            block_at=self.policy.risk.block_at,
        )
        self.injection = InjectionScanner()
        self.secrets = SecretScanner()
        self.pii = PIIScanner()
        self.shell_guard = ShellGuard()
        self.fs_guard = FilesystemGuard()
        self.net_guard = NetworkGuard()
        self.audit = AuditLogger(path=audit_path, enabled=audit)

    # ------------------------------------------------------------------
    # Input / output scanning
    # ------------------------------------------------------------------

    def scan(
        self,
        content: str | ContentEnvelope,
        *,
        source: str | ContentSource | None = None,
        trust: str | TrustLevel | None = None,
    ) -> ScanResult:
        """Scan text (or a provenance-tagged envelope) for injection/secrets."""
        envelope = self._as_envelope(content, source=source, trust=trust)
        untrusted = self._is_untrusted(envelope)

        matches: list[ThreatMatch] = []
        matches.extend(self.injection.scan(envelope.content, trust=envelope.trust))
        matches.extend(self.secrets.scan(envelope.content))

        force_block = False
        # Secrets policy
        secret_hits = [
            m
            for m in matches
            if m.threat in {ThreatType.SECRET_EXPOSURE, ThreatType.CREDENTIAL_EXFILTRATION}
        ]
        if secret_hits and self.policy_engine.secrets_action() == Decision.BLOCK:
            force_block = True

        risk = self.scorer.score(matches, untrusted_source=untrusted)
        # Untrusted content carrying injection is treated more harshly
        if untrusted and any(m.threat == ThreatType.PROMPT_INJECTION for m in matches):
            risk = min(100.0, risk + 15.0)
            force_block = force_block or risk >= self.scorer.block_at

        # High-confidence injection attempts always block (model-independent hard rule)
        for m in matches:
            if m.threat == ThreatType.PROMPT_INJECTION and m.score >= 0.85:
                force_block = True
                risk = max(risk, 85.0)
                break
            if m.threat == ThreatType.CREDENTIAL_EXFILTRATION and m.score >= 0.90:
                force_block = True
                risk = max(risk, 90.0)

        action = self.scorer.decide(risk, force_block=force_block)
        if untrusted:
            for m in matches:
                if m.threat == ThreatType.PROMPT_INJECTION and m.score >= 0.75:
                    action = Decision.BLOCK
                    risk = max(risk, 85.0)
                    break

        result = ScanResult(
            allowed=action == Decision.ALLOW,
            risk=risk,
            risk_level=self.scorer.level(risk),
            threats=self._unique_threats(matches),
            action=action,
            matches=matches,
            reasons=[m.detail for m in matches],
            metadata={
                "source": envelope.source.value
                if isinstance(envelope.source, ContentSource)
                else str(envelope.source),
                "trust": envelope.trust.value
                if isinstance(envelope.trust, TrustLevel)
                else str(envelope.trust),
                "url": envelope.url,
            },
        )
        self._audit_scan("input_scan", result)
        return result

    def scan_output(self, content: str) -> ScanResult:
        """Guard model/tool output for secrets and PII leakage."""
        matches: list[ThreatMatch] = []
        if self.policy.secrets.scan_output:
            matches.extend(self.secrets.scan(content))
        matches.extend(self.pii.scan(content))

        force_block = False
        if any(m.threat == ThreatType.SECRET_EXPOSURE for m in matches):
            if self.policy_engine.secrets_action() == Decision.BLOCK:
                force_block = True

        risk = self.scorer.score(matches)
        action = self.scorer.decide(risk, force_block=force_block)
        result = ScanResult(
            allowed=action == Decision.ALLOW,
            risk=risk,
            risk_level=self.scorer.level(risk),
            threats=self._unique_threats(matches),
            action=action,
            matches=matches,
            reasons=[m.detail for m in matches],
            metadata={"kind": "output"},
        )
        self._audit_scan("output_scan", result)
        return result

    # ------------------------------------------------------------------
    # Tool call gating
    # ------------------------------------------------------------------

    def check_tool(self, tool_call: ToolCall | dict[str, Any]) -> ToolDecision:
        """Allow / ask / block an agent tool request."""
        call = tool_call if isinstance(tool_call, ToolCall) else self._dict_to_tool(tool_call)
        tool = call.tool.lower().strip()

        if tool in {"shell", "bash", "terminal", "execute", "run"}:
            return self.check_shell(call.command or "")
        if tool in {"read_file", "write_file", "filesystem", "file", "read", "write", "open"}:
            path = call.path or str(call.arguments.get("filename", ""))
            return self.check_filesystem(path)
        if tool in {"network", "http", "fetch", "browse", "web", "request"}:
            url = call.url or str(call.arguments.get("url", call.arguments.get("host", "")))
            return self.check_network(url)

        # Unknown tools: low-risk allow with audit
        decision = ToolDecision(
            allowed=True,
            risk=10.0,
            risk_level=self.scorer.level(10.0),
            action=Decision.ALLOW,
            reasons=[f"Unknown tool '{call.tool}' — allowed with audit"],
            metadata={"tool": call.tool},
        )
        self._audit_tool(decision)
        return decision

    def check_shell(self, command: str) -> ToolDecision:
        finding = self.shell_guard.analyze(command)
        verdict = self.policy_engine.check_shell(command)

        matches = list(finding.matches)
        if verdict.matches:
            matches.extend(verdict.matches)

        # If the command touches denied filesystem paths, apply filesystem policy too
        for token in finding.tokens:
            if any(hint in token for hint in ("/", "\\", "~", ".env", "id_rsa", "id_ed25519")):
                fs_verdict = self.policy_engine.check_filesystem(token)
                if fs_verdict.action == Decision.BLOCK:
                    if fs_verdict.matches:
                        matches.extend(fs_verdict.matches)
                    verdict = fs_verdict
                    break

        risk = self.scorer.score(matches)
        if verdict.action == Decision.BLOCK:
            risk = max(risk, 90.0)
        elif verdict.require_confirmation:
            risk = max(risk, 45.0)

        action = self.scorer.decision_for_policy(
            risk,
            policy_action=verdict.action,
            require_confirmation=verdict.require_confirmation,
        )
        # Destructive commands and credential-path access always block
        forced_rule = None
        if any(
            m.threat == ThreatType.DESTRUCTIVE_COMMAND and m.score >= 0.85
            for m in matches
        ):
            action = Decision.BLOCK
            risk = max(risk, 95.0)
            forced_rule = next(
                (
                    m.rule
                    for m in matches
                    if m.threat == ThreatType.DESTRUCTIVE_COMMAND and m.score >= 0.85
                ),
                "shell.destructive",
            )
        elif any(
            m.threat == ThreatType.CREDENTIAL_EXFILTRATION and m.score >= 0.85
            for m in matches
        ):
            action = Decision.BLOCK
            risk = max(risk, 95.0)
            forced_rule = next(
                (
                    m.rule
                    for m in matches
                    if m.threat == ThreatType.CREDENTIAL_EXFILTRATION and m.score >= 0.85
                ),
                "shell.credential",
            )

        decision = ToolDecision(
            allowed=action == Decision.ALLOW,
            risk=risk,
            risk_level=self.scorer.level(risk),
            action=action,
            threats=self._unique_threats(matches),
            matches=matches,
            reasons=[verdict.reason] if verdict.reason else [m.detail for m in matches],
            rule=forced_rule or verdict.rule,
            resource=verdict.resource or command,
            require_confirmation=verdict.require_confirmation or action == Decision.REVIEW,
        )
        self._audit_tool(decision)
        return decision

    def check_filesystem(self, path: str) -> ToolDecision:
        matches = list(self.fs_guard.analyze(path))
        verdict = self.policy_engine.check_filesystem(path)
        if verdict.matches:
            matches.extend(verdict.matches)

        risk = self.scorer.score(matches)
        if verdict.action == Decision.BLOCK:
            risk = max(risk, 90.0)

        action = self.scorer.decision_for_policy(risk, policy_action=verdict.action)
        decision = ToolDecision(
            allowed=action == Decision.ALLOW,
            risk=risk,
            risk_level=self.scorer.level(risk),
            action=action,
            threats=self._unique_threats(matches),
            matches=matches,
            reasons=[verdict.reason] if verdict.reason else [m.detail for m in matches],
            rule=verdict.rule,
            resource=verdict.resource or path,
        )
        self._audit_tool(decision)
        return decision

    def check_network(self, url_or_host: str) -> ToolDecision:
        matches = list(self.net_guard.analyze(url_or_host))
        verdict = self.policy_engine.check_network(url_or_host)
        if verdict.matches:
            matches.extend(verdict.matches)

        risk = self.scorer.score(matches)
        if verdict.action == Decision.BLOCK:
            risk = max(risk, 80.0)

        action = self.scorer.decision_for_policy(risk, policy_action=verdict.action)
        decision = ToolDecision(
            allowed=action == Decision.ALLOW,
            risk=risk,
            risk_level=self.scorer.level(risk),
            action=action,
            threats=self._unique_threats(matches),
            matches=matches,
            reasons=[verdict.reason] if verdict.reason else [m.detail for m in matches],
            rule=verdict.rule,
            resource=verdict.resource or url_or_host,
        )
        self._audit_tool(decision)
        return decision

    # ------------------------------------------------------------------
    # Decorators / middleware helpers
    # ------------------------------------------------------------------

    def protect(self, func: F | None = None, *, tool: str | None = None) -> Any:
        """Decorator that gates a tool function through AgentWall."""

        def decorator(fn: F) -> F:
            @wraps(fn)
            def wrapper(*args: Any, **kwargs: Any) -> Any:
                call = self._infer_tool_call(fn, args, kwargs, tool_name=tool)
                decision = self.check_tool(call)
                if decision.action == Decision.BLOCK:
                    raise PermissionError(
                        f"AgentWall blocked tool call: {decision}"
                    )
                if decision.action == Decision.REVIEW:
                    raise PermissionError(
                        f"AgentWall requires confirmation: {decision}"
                    )
                return fn(*args, **kwargs)

            return wrapper  # type: ignore[return-value]

        if func is not None:
            return decorator(func)
        return decorator

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------

    def _as_envelope(
        self,
        content: str | ContentEnvelope,
        *,
        source: str | ContentSource | None,
        trust: str | TrustLevel | None,
    ) -> ContentEnvelope:
        if isinstance(content, ContentEnvelope):
            env = content
            if source is not None:
                env.source = source  # type: ignore[assignment]
            if trust is not None:
                env.trust = trust  # type: ignore[assignment]
            env.__post_init__()
            return env

        src = ContentSource(source) if isinstance(source, str) else (source or ContentSource.UNKNOWN)
        if trust is not None:
            tr = TrustLevel(trust) if isinstance(trust, str) else trust
        elif src in _UNTRUSTED_SOURCES:
            tr = TrustLevel.UNTRUSTED
        elif src in {ContentSource.USER, ContentSource.SYSTEM}:
            tr = TrustLevel.TRUSTED
        else:
            tr = TrustLevel.UNKNOWN
        return ContentEnvelope(content=content, source=src, trust=tr)

    def _is_untrusted(self, envelope: ContentEnvelope) -> bool:
        if envelope.trust == TrustLevel.UNTRUSTED:
            return True
        if envelope.trust == TrustLevel.TRUSTED:
            return False
        return envelope.source in _UNTRUSTED_SOURCES

    @staticmethod
    def _unique_threats(matches: list[ThreatMatch]) -> list[ThreatType]:
        seen: list[ThreatType] = []
        for m in matches:
            if m.threat not in seen:
                seen.append(m.threat)
        return seen

    def _dict_to_tool(self, data: dict[str, Any]) -> ToolCall:
        return ToolCall(
            tool=str(data.get("tool", data.get("name", "unknown"))),
            arguments=dict(data.get("arguments", data.get("args", {}))),
            command=data.get("command"),
            path=data.get("path"),
            url=data.get("url"),
            metadata=dict(data.get("metadata", {})),
        )

    def _infer_tool_call(
        self,
        fn: Callable[..., Any],
        args: tuple[Any, ...],
        kwargs: dict[str, Any],
        *,
        tool_name: str | None,
    ) -> ToolCall:
        name = tool_name or fn.__name__
        arguments = dict(kwargs)
        if args:
            arguments["arg0"] = args[0]
            if name in {"shell", "bash", "run", "execute"} and "command" not in arguments:
                arguments["command"] = str(args[0])
            if name in {"read_file", "write_file", "read", "open"} and "path" not in arguments:
                arguments["path"] = str(args[0])
        return ToolCall(tool=name, arguments=arguments)

    def _audit_scan(self, event_type: str, result: ScanResult) -> None:
        self.audit.log(
            event_type,
            action=result.action.value,
            risk=result.risk,
            risk_level=result.risk_level.value,
            threats=[t.value for t in result.threats],
            reasons=result.reasons[:5],
            detail=result.metadata,
        )

    def _audit_tool(self, decision: ToolDecision) -> None:
        self.audit.log(
            "tool_check",
            action=decision.action.value,
            risk=decision.risk,
            risk_level=decision.risk_level.value,
            threats=[t.value for t in decision.threats],
            reasons=decision.reasons[:5],
            resource=decision.resource,
            rule=decision.rule,
        )
