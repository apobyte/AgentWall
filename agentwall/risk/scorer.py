"""Risk scoring engine for AgentWall."""

from __future__ import annotations

from agentwall.models.types import Decision, RiskLevel, ThreatMatch, ThreatType


# Default contribution weights (0–100 scale additives, capped at 100)
DEFAULT_WEIGHTS: dict[ThreatType, float] = {
    ThreatType.PROMPT_INJECTION: 30.0,
    ThreatType.SECRET_EXPOSURE: 40.0,
    ThreatType.CREDENTIAL_EXFILTRATION: 50.0,
    ThreatType.DANGEROUS_SHELL: 35.0,
    ThreatType.UNAUTHORIZED_FILE_ACCESS: 40.0,
    ThreatType.UNAUTHORIZED_NETWORK: 25.0,
    ThreatType.PII_LEAKAGE: 30.0,
    ThreatType.DESTRUCTIVE_COMMAND: 50.0,
    ThreatType.POLICY_VIOLATION: 45.0,
}

UNTRUSTED_SOURCE_BONUS = 10.0


class RiskScorer:
    """Combine threat matches into a 0–100 risk score and decision."""

    def __init__(
        self,
        weights: dict[ThreatType, float] | None = None,
        allow_below: float = 30.0,
        review_below: float = 60.0,
        block_at: float = 80.0,
    ) -> None:
        self.weights = dict(DEFAULT_WEIGHTS)
        if weights:
            self.weights.update(weights)
        self.allow_below = allow_below
        self.review_below = review_below
        self.block_at = block_at

    def score(
        self,
        matches: list[ThreatMatch],
        *,
        untrusted_source: bool = False,
        base: float = 0.0,
    ) -> float:
        total = base
        seen: set[ThreatType] = set()
        for match in matches:
            if match.threat in seen:
                continue
            seen.add(match.threat)
            weight = self.weights.get(match.threat, 20.0)
            confidence = match.score if match.score <= 1.0 else match.score / 100.0
            total += weight * confidence

        if untrusted_source and matches:
            total += UNTRUSTED_SOURCE_BONUS

        return min(100.0, max(0.0, total))

    def level(self, risk: float) -> RiskLevel:
        if risk >= 80:
            return RiskLevel.CRITICAL
        if risk >= 60:
            return RiskLevel.HIGH
        if risk >= 30:
            return RiskLevel.MEDIUM
        return RiskLevel.LOW

    def decide(self, risk: float, *, force_block: bool = False) -> Decision:
        if force_block or risk >= self.block_at:
            return Decision.BLOCK
        if risk >= self.review_below:
            return Decision.REVIEW
        if risk >= self.allow_below:
            return Decision.REVIEW
        return Decision.ALLOW

    def decision_for_policy(
        self,
        risk: float,
        *,
        policy_action: Decision | None = None,
        require_confirmation: bool = False,
    ) -> Decision:
        """Merge scored risk with an explicit policy verdict."""
        if policy_action == Decision.BLOCK:
            return Decision.BLOCK
        if policy_action == Decision.REVIEW or require_confirmation:
            return Decision.REVIEW
        return self.decide(risk)
