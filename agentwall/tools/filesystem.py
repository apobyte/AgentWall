"""Filesystem path analysis and protection."""

from __future__ import annotations

import os
import re
from pathlib import Path, PurePosixPath, PureWindowsPath

from agentwall.models.types import ThreatMatch, ThreatType


# Always-sensitive path fragments (checked after expansion)
_PROTECTED_FRAGMENTS = [
    re.compile(r"(?i)(^|[\\/])\.ssh([\\/]|$)"),
    re.compile(r"(?i)(^|[\\/])\.aws([\\/]|$)"),
    re.compile(r"(?i)(^|[\\/])\.gnupg([\\/]|$)"),
    re.compile(r"(?i)(^|[\\/])\.env(\.\w+)?$"),
    re.compile(r"(?i)id_rsa$"),
    re.compile(r"(?i)id_ed25519$"),
    re.compile(r"(?i)id_ecdsa$"),
    re.compile(r"(?i)credentials\.json$"),
    re.compile(r"(?i)service[_-]?account\.json$"),
    re.compile(r"(?i)(^|[\\/])\.git([\\/]config)?$"),
]


def expand_path(path: str) -> str:
    """Expand ~ and environment variables; normalize separators for matching."""
    expanded = os.path.expandvars(os.path.expanduser(path.strip()))
    return expanded.replace("\\", "/")


def _glob_to_regex(pattern: str) -> str:
    i = 0
    regex = "^"
    while i < len(pattern):
        if pattern.startswith("**/", i):
            regex += "(?:.*/)?"
            i += 3
        elif pattern.startswith("**", i):
            regex += ".*"
            i += 2
        elif pattern[i] == "*":
            regex += "[^/]*"
            i += 1
        elif pattern[i] == "?":
            regex += "[^/]"
            i += 1
        else:
            regex += re.escape(pattern[i])
            i += 1
    regex += "$"
    return regex


def path_matches_glob(path: str, pattern: str) -> bool:
    """Match a path against a simple glob (** , * , ?)."""
    path_n = expand_path(path).lstrip("./")
    candidates = {
        expand_path(path),
        path_n,
        expand_path(path).replace("\\", "/"),
        "./" + path_n if not path_n.startswith("/") else path_n,
    }
    pat_n = expand_path(pattern)
    regex = _glob_to_regex(pat_n)
    # Also try pattern without leading **/
    patterns = {regex, _glob_to_regex(pat_n.lstrip("./"))}
    if pat_n.startswith("**/"):
        patterns.add(_glob_to_regex(pat_n[3:]))

    for candidate in candidates:
        for rx in patterns:
            if re.match(rx, candidate, re.IGNORECASE):
                return True
            if re.match(rx, candidate.lstrip("./"), re.IGNORECASE):
                return True
    return False


class FilesystemGuard:
    """Assess file-access requests for sensitive / out-of-policy paths."""

    def analyze(self, path: str) -> list[ThreatMatch]:
        if not path:
            return []

        expanded = expand_path(path)
        matches: list[ThreatMatch] = []

        for frag in _PROTECTED_FRAGMENTS:
            if frag.search(expanded):
                matches.append(
                    ThreatMatch(
                        threat=ThreatType.UNAUTHORIZED_FILE_ACCESS,
                        score=0.95,
                        detail="Access to protected credential/config path",
                        evidence=expanded,
                        rule="filesystem.protected_credentials",
                    )
                )
                # Also escalate as credential exfiltration intent
                matches.append(
                    ThreatMatch(
                        threat=ThreatType.CREDENTIAL_EXFILTRATION,
                        score=0.90,
                        detail="Target resembles a credential store",
                        evidence=expanded,
                        rule="filesystem.credential_target",
                    )
                )
                break

        # Absolute paths outside a typical workspace can be higher risk
        pure = PureWindowsPath(expanded) if re.match(r"^[A-Za-z]:/", expanded) else PurePosixPath(expanded)
        if pure.is_absolute() and not any(
            frag.search(expanded) for frag in _PROTECTED_FRAGMENTS
        ):
            # Mild signal only — policy engine decides allow/deny
            if any(
                expanded.startswith(p)
                for p in ("/etc/", "/root/", "/var/", "C:/Windows", "C:/Users")
            ):
                matches.append(
                    ThreatMatch(
                        threat=ThreatType.UNAUTHORIZED_FILE_ACCESS,
                        score=0.55,
                        detail="Absolute path into sensitive system location",
                        evidence=expanded,
                        rule="filesystem.system_path",
                    )
                )

        return matches

    def is_within(self, path: str, roots: list[str]) -> bool:
        expanded = Path(expand_path(path)).resolve() if os.path.exists(expand_path(path)) else Path(expand_path(path))
        for root in roots:
            root_exp = Path(expand_path(root))
            try:
                expanded.relative_to(root_exp)
                return True
            except ValueError:
                # Fallback string prefix for non-existent paths
                if str(expanded).replace("\\", "/").startswith(
                    str(root_exp).replace("\\", "/")
                ):
                    return True
        return False
