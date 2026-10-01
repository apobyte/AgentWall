"""Policy engine — deterministic allow/review/block decisions."""

from __future__ import annotations

import fnmatch
from dataclasses import dataclass

from agentwall.models.types import Decision, ThreatMatch, ThreatType
from agentwall.policy.parser import Policy, default_policy
from agentwall.tools.filesystem import expand_path, path_matches_glob
from agentwall.tools.network import extract_host


@dataclass
class PolicyVerdict:
    action: Decision
    rule: str | None = None
    resource: str | None = None
    reason: str | None = None
    require_confirmation: bool = False
    matches: list[ThreatMatch] | None = None


def _shell_glob_match(command: str, pattern: str) -> bool:
    """Match a shell command against allow/deny patterns (fnmatch + prefix)."""
    cmd = command.strip()
    pat = pattern.strip()
    if fnmatch.fnmatch(cmd, pat):
        return True
    # Also allow exact binary/prefix allows like "git status" matching "git status --short"
    if pat.endswith("*"):
        return fnmatch.fnmatch(cmd, pat)
    # Prefix match when pattern has no wildcards: "npm test" allows "npm test --watch"
    if "*" not in pat and "?" not in pat:
        if cmd == pat or cmd.startswith(pat + " "):
            return True
    return False


class PolicyEngine:
    """Evaluate filesystem, shell, and network requests against a YAML policy."""

    def __init__(self, policy: Policy | None = None) -> None:
        self.policy = policy or default_policy()

    def check_filesystem(self, path: str) -> PolicyVerdict:
        resource = expand_path(path)

        for pattern in self.policy.filesystem.deny:
            if path_matches_glob(resource, pattern) or path_matches_glob(path, pattern):
                return PolicyVerdict(
                    action=Decision.BLOCK,
                    rule="filesystem.deny",
                    resource=resource,
                    reason=f"Path denied by policy pattern '{pattern}'",
                    matches=[
                        ThreatMatch(
                            threat=ThreatType.POLICY_VIOLATION,
                            score=1.0,
                            detail=f"Denied by filesystem.deny: {pattern}",
                            evidence=resource,
                            rule="filesystem.deny",
                        ),
                        ThreatMatch(
                            threat=ThreatType.UNAUTHORIZED_FILE_ACCESS,
                            score=0.95,
                            detail="Unauthorized file access",
                            evidence=resource,
                            rule="filesystem.deny",
                        ),
                    ],
                )

        if self.policy.filesystem.allow:
            allowed = any(
                path_matches_glob(resource, pattern) or path_matches_glob(path, pattern)
                for pattern in self.policy.filesystem.allow
            )
            if not allowed:
                return PolicyVerdict(
                    action=Decision.BLOCK,
                    rule="filesystem.allow",
                    resource=resource,
                    reason="Path not in filesystem allow list",
                    matches=[
                        ThreatMatch(
                            threat=ThreatType.POLICY_VIOLATION,
                            score=0.85,
                            detail="Path outside allow list",
                            evidence=resource,
                            rule="filesystem.allow",
                        ),
                        ThreatMatch(
                            threat=ThreatType.UNAUTHORIZED_FILE_ACCESS,
                            score=0.80,
                            detail="Unauthorized file access",
                            evidence=resource,
                            rule="filesystem.allow",
                        ),
                    ],
                )

        return PolicyVerdict(
            action=Decision.ALLOW,
            rule="filesystem.allow",
            resource=resource,
            reason="Path permitted by policy",
        )

    def check_shell(self, command: str) -> PolicyVerdict:
        cmd = command.strip()

        for pattern in self.policy.shell.deny:
            if _shell_glob_match(cmd, pattern):
                return PolicyVerdict(
                    action=Decision.BLOCK,
                    rule="shell.deny",
                    resource=cmd,
                    reason=f"Command denied by policy pattern '{pattern}'",
                    matches=[
                        ThreatMatch(
                            threat=ThreatType.POLICY_VIOLATION,
                            score=1.0,
                            detail=f"Denied by shell.deny: {pattern}",
                            evidence=cmd[:160],
                            rule="shell.deny",
                        ),
                        ThreatMatch(
                            threat=ThreatType.DANGEROUS_SHELL,
                            score=0.90,
                            detail="Dangerous shell command blocked by policy",
                            evidence=cmd[:160],
                            rule="shell.deny",
                        ),
                    ],
                )

        for pattern in self.policy.shell.require_confirmation:
            if _shell_glob_match(cmd, pattern):
                return PolicyVerdict(
                    action=Decision.REVIEW,
                    rule="shell.require_confirmation",
                    resource=cmd,
                    reason=f"Command requires confirmation ('{pattern}')",
                    require_confirmation=True,
                )

        if self.policy.shell.allow:
            allowed = any(_shell_glob_match(cmd, pattern) for pattern in self.policy.shell.allow)
            if allowed:
                return PolicyVerdict(
                    action=Decision.ALLOW,
                    rule="shell.allow",
                    resource=cmd,
                    reason="Command permitted by allow list",
                )
            # Not on allow list → review (not hard block) so risk engine can escalate
            return PolicyVerdict(
                action=Decision.REVIEW,
                rule="shell.allow",
                resource=cmd,
                reason="Command not on shell allow list",
                require_confirmation=True,
                matches=[
                    ThreatMatch(
                        threat=ThreatType.DANGEROUS_SHELL,
                        score=0.45,
                        detail="Command not explicitly allowed",
                        evidence=cmd[:160],
                        rule="shell.allow",
                    )
                ],
            )

        return PolicyVerdict(
            action=Decision.ALLOW,
            rule="shell.default",
            resource=cmd,
            reason="No shell allow-list configured",
        )

    def check_network(self, url_or_host: str) -> PolicyVerdict:
        host = extract_host(url_or_host)
        resource = host or url_or_host

        for pattern in self.policy.network.deny:
            if fnmatch.fnmatch(host, pattern) or host == pattern:
                return PolicyVerdict(
                    action=Decision.BLOCK,
                    rule="network.deny",
                    resource=resource,
                    reason=f"Host denied by policy pattern '{pattern}'",
                    matches=[
                        ThreatMatch(
                            threat=ThreatType.UNAUTHORIZED_NETWORK,
                            score=1.0,
                            detail=f"Denied by network.deny: {pattern}",
                            evidence=resource,
                            rule="network.deny",
                        )
                    ],
                )

        if self.policy.network.allow:
            allowed = any(
                fnmatch.fnmatch(host, pattern) or host == pattern or host.endswith("." + pattern)
                for pattern in self.policy.network.allow
            )
            if not allowed:
                return PolicyVerdict(
                    action=Decision.BLOCK,
                    rule="network.allow",
                    resource=resource,
                    reason="Host not in network allow list",
                    matches=[
                        ThreatMatch(
                            threat=ThreatType.UNAUTHORIZED_NETWORK,
                            score=0.85,
                            detail="Host outside network allow list",
                            evidence=resource,
                            rule="network.allow",
                        )
                    ],
                )

        return PolicyVerdict(
            action=Decision.ALLOW,
            rule="network.allow",
            resource=resource,
            reason="Host permitted by policy",
        )

    def secrets_action(self) -> Decision:
        mapping = {
            "block": Decision.BLOCK,
            "review": Decision.REVIEW,
            "allow": Decision.ALLOW,
        }
        return mapping.get(self.policy.secrets.action, Decision.BLOCK)
