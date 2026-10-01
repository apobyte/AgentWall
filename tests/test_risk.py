from agentwall.risk import RiskScorer
from agentwall.models.types import Decision, RiskLevel, ThreatMatch, ThreatType


def test_risk_levels():
    scorer = RiskScorer()
    assert scorer.level(10) == RiskLevel.LOW
    assert scorer.level(40) == RiskLevel.MEDIUM
    assert scorer.level(70) == RiskLevel.HIGH
    assert scorer.level(90) == RiskLevel.CRITICAL


def test_score_combines_threats():
    scorer = RiskScorer()
    matches = [
        ThreatMatch(ThreatType.PROMPT_INJECTION, 1.0, "inj"),
        ThreatMatch(ThreatType.CREDENTIAL_EXFILTRATION, 1.0, "cred"),
    ]
    risk = scorer.score(matches, untrusted_source=True)
    assert risk >= 80
    assert scorer.decide(risk) == Decision.BLOCK


def test_empty_matches_allow():
    scorer = RiskScorer()
    assert scorer.score([]) == 0
    assert scorer.decide(0) == Decision.ALLOW
