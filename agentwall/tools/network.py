"""Network destination analysis."""

from __future__ import annotations

import re
from urllib.parse import urlparse

from agentwall.models.types import ThreatMatch, ThreatType


_PRIVATE_HOSTS = re.compile(
    r"(?i)^(localhost|127\.0\.0\.1|0\.0\.0\.0|::1|"
    r"10\.\d+\.\d+\.\d+|"
    r"192\.168\.\d+\.\d+|"
    r"172\.(1[6-9]|2\d|3[0-1])\.\d+\.\d+)$"
)

_SUSPICIOUS_TLDS = re.compile(r"(?i)\.(xyz|top|gq|tk|ml|cf|buzz|click)$")


def extract_host(url_or_host: str) -> str:
    value = url_or_host.strip()
    if "://" not in value:
        # host[:path] or host:port
        return value.split("/")[0].split(":")[0].lower()
    parsed = urlparse(value)
    return (parsed.hostname or "").lower()


class NetworkGuard:
    """Assess network destinations requested by an agent."""

    def analyze(self, url_or_host: str) -> list[ThreatMatch]:
        if not url_or_host:
            return []

        host = extract_host(url_or_host)
        matches: list[ThreatMatch] = []

        if not host:
            matches.append(
                ThreatMatch(
                    threat=ThreatType.UNAUTHORIZED_NETWORK,
                    score=0.60,
                    detail="Could not parse network destination",
                    evidence=url_or_host[:120],
                    rule="network.parse_error",
                )
            )
            return matches

        if _PRIVATE_HOSTS.match(host):
            matches.append(
                ThreatMatch(
                    threat=ThreatType.UNAUTHORIZED_NETWORK,
                    score=0.50,
                    detail="Request targets private/loopback address",
                    evidence=host,
                    rule="network.private_host",
                )
            )

        if _SUSPICIOUS_TLDS.search(host):
            matches.append(
                ThreatMatch(
                    threat=ThreatType.UNAUTHORIZED_NETWORK,
                    score=0.45,
                    detail="Destination uses a commonly abused TLD",
                    evidence=host,
                    rule="network.suspicious_tld",
                )
            )

        # Raw IP destinations are slightly elevated
        if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", host):
            matches.append(
                ThreatMatch(
                    threat=ThreatType.UNAUTHORIZED_NETWORK,
                    score=0.40,
                    detail="Destination is a raw IP address",
                    evidence=host,
                    rule="network.raw_ip",
                )
            )

        return matches
