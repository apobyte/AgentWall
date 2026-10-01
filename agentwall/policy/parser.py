"""YAML policy parsing for AgentWall."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml


@dataclass
class FilesystemPolicy:
    allow: list[str] = field(default_factory=list)
    deny: list[str] = field(default_factory=list)


@dataclass
class ShellPolicy:
    allow: list[str] = field(default_factory=list)
    deny: list[str] = field(default_factory=list)
    require_confirmation: list[str] = field(default_factory=list)


@dataclass
class NetworkPolicy:
    allow: list[str] = field(default_factory=list)
    deny: list[str] = field(default_factory=list)


@dataclass
class SecretsPolicy:
    action: str = "block"  # block | review | allow
    scan_output: bool = True


@dataclass
class RiskPolicy:
    allow_below: float = 30.0
    review_below: float = 60.0
    block_at: float = 80.0


@dataclass
class Policy:
    version: int = 1
    filesystem: FilesystemPolicy = field(default_factory=FilesystemPolicy)
    shell: ShellPolicy = field(default_factory=ShellPolicy)
    network: NetworkPolicy = field(default_factory=NetworkPolicy)
    secrets: SecretsPolicy = field(default_factory=SecretsPolicy)
    risk: RiskPolicy = field(default_factory=RiskPolicy)
    raw: dict[str, Any] = field(default_factory=dict)


def _as_list(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, str):
        return [value]
    return [str(v) for v in value]


def parse_policy_dict(data: dict[str, Any]) -> Policy:
    fs = data.get("filesystem") or {}
    sh = data.get("shell") or {}
    net = data.get("network") or {}
    secrets = data.get("secrets") or {}
    risk = data.get("risk") or {}

    return Policy(
        version=int(data.get("version", 1)),
        filesystem=FilesystemPolicy(
            allow=_as_list(fs.get("allow")),
            deny=_as_list(fs.get("deny")),
        ),
        shell=ShellPolicy(
            allow=_as_list(sh.get("allow")),
            deny=_as_list(sh.get("deny")),
            require_confirmation=_as_list(sh.get("require_confirmation")),
        ),
        network=NetworkPolicy(
            allow=_as_list(net.get("allow")),
            deny=_as_list(net.get("deny")),
        ),
        secrets=SecretsPolicy(
            action=str(secrets.get("action", "block")).lower(),
            scan_output=bool(secrets.get("scan_output", True)),
        ),
        risk=RiskPolicy(
            allow_below=float(risk.get("allow_below", 30)),
            review_below=float(risk.get("review_below", 60)),
            block_at=float(risk.get("block_at", 80)),
        ),
        raw=data,
    )


def load_policy(path: str | Path) -> Policy:
    policy_path = Path(path)
    text = policy_path.read_text(encoding="utf-8")
    data = yaml.safe_load(text) or {}
    if not isinstance(data, dict):
        raise ValueError(f"Policy file must contain a YAML mapping: {policy_path}")
    return parse_policy_dict(data)


def default_policy() -> Policy:
    """Built-in safe-by-default policy."""
    return parse_policy_dict(
        {
            "version": 1,
            "filesystem": {
                "allow": ["**", "./workspace/**", "./**"],
                "deny": [
                    "~/.ssh/**",
                    "~/.aws/**",
                    "~/.gnupg/**",
                    "**/.env",
                    "**/.env.*",
                    "**/id_rsa",
                    "**/id_ed25519",
                    "**/credentials.json",
                    "/etc/shadow",
                    "/etc/passwd",
                ],
            },
            "shell": {
                "allow": [
                    "npm test",
                    "npm run build",
                    "npm run lint",
                    "pytest",
                    "python -m pytest",
                    "git status",
                    "git diff",
                    "git log",
                    "ls",
                    "dir",
                    "pwd",
                    "echo",
                    "cat",
                    "type",
                    "head",
                    "tail",
                    "rg",
                    "grep",
                    "find",
                ],
                "deny": [
                    "rm -rf /",
                    "rm -rf /*",
                    "mkfs*",
                    "dd if=*",
                    "curl *| sh",
                    "curl *| bash",
                    "wget *| sh",
                    "sudo *",
                ],
                "require_confirmation": [
                    "git push*",
                    "git push",
                    "npm publish",
                    "pip install*",
                    "rm *",
                ],
            },
            "network": {
                "allow": [
                    "api.github.com",
                    "pypi.org",
                    "files.pythonhosted.org",
                    "registry.npmjs.org",
                ],
                "deny": [],
            },
            "secrets": {"action": "block", "scan_output": True},
            "risk": {"allow_below": 30, "review_below": 60, "block_at": 80},
        }
    )


def policy_to_dict(policy: Policy) -> dict[str, Any]:
    return {
        "version": policy.version,
        "filesystem": {
            "allow": policy.filesystem.allow,
            "deny": policy.filesystem.deny,
        },
        "shell": {
            "allow": policy.shell.allow,
            "deny": policy.shell.deny,
            "require_confirmation": policy.shell.require_confirmation,
        },
        "network": {
            "allow": policy.network.allow,
            "deny": policy.network.deny,
        },
        "secrets": {
            "action": policy.secrets.action,
            "scan_output": policy.secrets.scan_output,
        },
        "risk": {
            "allow_below": policy.risk.allow_below,
            "review_below": policy.risk.review_below,
            "block_at": policy.risk.block_at,
        },
    }
