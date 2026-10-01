"""Shell command analysis and danger detection."""

from __future__ import annotations

import re
import shlex
from dataclasses import dataclass

from agentwall.models.types import ThreatMatch, ThreatType


@dataclass(frozen=True)
class ShellFinding:
    matches: list[ThreatMatch]
    normalized: str
    tokens: list[str]


_DESTRUCTIVE = [
    (
        re.compile(r"(?i)\brm\s+(-[a-zA-Z]*f[a-zA-Z]*\s+)?(/|~|\./|\.\./|\*)"),
        0.98,
        "Destructive rm targeting broad path",
        "shell.rm_force",
    ),
    (
        re.compile(r"(?i)\brm\s+-rf\b"),
        0.95,
        "Force recursive delete",
        "shell.rm_rf",
    ),
    (
        re.compile(r"(?i)\bmkfs\b|\bdd\s+if=.*of=/dev/"),
        0.99,
        "Disk wipe / raw device write",
        "shell.disk_wipe",
    ),
    (
        re.compile(r"(?i)\b(shutdown|reboot|halt|poweroff)\b"),
        0.80,
        "System power control",
        "shell.power",
    ),
    (
        re.compile(r"(?i)\bchmod\s+777\b"),
        0.70,
        "World-writable permissions",
        "shell.chmod_777",
    ),
    (
        re.compile(r"(?i)\bcurl\b.+\|\s*(ba)?sh\b|\bwget\b.+\|\s*(ba)?sh\b"),
        0.95,
        "Pipe remote script to shell",
        "shell.curl_pipe_sh",
    ),
    (
        re.compile(r"(?i)\b(nc|ncat|netcat)\b.+\s-e\s"),
        0.95,
        "Netcat reverse shell",
        "shell.reverse_shell",
    ),
    (
        re.compile(r"(?i)\bbase64\s+-d\b.+\|\s*(ba)?sh\b"),
        0.90,
        "Decode-and-execute payload",
        "shell.b64_exec",
    ),
    (
        re.compile(r"(?i)\bsudo\b"),
        0.60,
        "Elevated privilege execution",
        "shell.sudo",
    ),
    (
        re.compile(r"(?i)\b(kill\s+-9|pkill\s+-9)\b"),
        0.55,
        "Force-kill processes",
        "shell.force_kill",
    ),
]

_CREDENTIAL_SHELL = re.compile(
    r"(?i)(~/?\.ssh|/id_rsa|/id_ed25519|\.aws/credentials|\.env\b|/etc/shadow)"
)

_NETWORK_EXFIL = re.compile(
    r"(?i)\b(curl|wget|nc|ncat|scp|rsync|ftp)\b"
)


def _tokenize(command: str) -> list[str]:
    try:
        return shlex.split(command, posix=True)
    except ValueError:
        return command.split()


class ShellGuard:
    """Parse and risk-assess shell commands requested by an agent."""

    def analyze(self, command: str) -> ShellFinding:
        normalized = command.strip()
        tokens = _tokenize(normalized)
        matches: list[ThreatMatch] = []

        for pattern, score, detail, rule in _DESTRUCTIVE:
            if pattern.search(normalized):
                threat = (
                    ThreatType.DESTRUCTIVE_COMMAND
                    if "rm" in rule or "disk" in rule or "curl_pipe" in rule
                    else ThreatType.DANGEROUS_SHELL
                )
                matches.append(
                    ThreatMatch(
                        threat=threat,
                        score=score,
                        detail=detail,
                        evidence=normalized[:160],
                        rule=rule,
                    )
                )

        if _CREDENTIAL_SHELL.search(normalized):
            matches.append(
                ThreatMatch(
                    threat=ThreatType.CREDENTIAL_EXFILTRATION,
                    score=0.90,
                    detail="Shell command touches credential paths",
                    evidence=normalized[:160],
                    rule="shell.credential_path",
                )
            )

        if _CREDENTIAL_SHELL.search(normalized) and _NETWORK_EXFIL.search(normalized):
            matches.append(
                ThreatMatch(
                    threat=ThreatType.CREDENTIAL_EXFILTRATION,
                    score=0.98,
                    detail="Credential read combined with network transfer",
                    evidence=normalized[:160],
                    rule="shell.exfil_combo",
                )
            )

        # Fork bombs / eval of untrusted input
        if ":(){ :|:& };:" in normalized.replace(" ", ""):
            matches.append(
                ThreatMatch(
                    threat=ThreatType.DESTRUCTIVE_COMMAND,
                    score=1.0,
                    detail="Fork bomb detected",
                    evidence=normalized[:80],
                    rule="shell.fork_bomb",
                )
            )

        return ShellFinding(matches=matches, normalized=normalized, tokens=tokens)
