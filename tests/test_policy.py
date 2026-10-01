from agentwall.policy import PolicyEngine, default_policy, parse_policy_dict
from agentwall.models.types import Decision


def test_default_policy_denies_ssh():
    engine = PolicyEngine(default_policy())
    verdict = engine.check_filesystem("~/.ssh/id_rsa")
    assert verdict.action == Decision.BLOCK
    assert verdict.rule == "filesystem.deny"


def test_custom_policy_shell_allow():
    policy = parse_policy_dict(
        {
            "version": 1,
            "shell": {"allow": ["echo hello"], "deny": [], "require_confirmation": []},
            "filesystem": {"allow": ["**"], "deny": []},
            "network": {"allow": [], "deny": []},
        }
    )
    engine = PolicyEngine(policy)
    assert engine.check_shell("echo hello").action == Decision.ALLOW
    assert engine.check_shell("rm -rf ./").require_confirmation or engine.check_shell(
        "rm -rf ./"
    ).action in {Decision.REVIEW, Decision.BLOCK}


def test_load_policy_yaml(tmp_path):
    from agentwall.policy import load_policy

    path = tmp_path / "policy.yaml"
    path.write_text(
        """
version: 1
filesystem:
  allow: ["**"]
  deny: ["**/secrets/**"]
shell:
  allow: ["ls"]
  deny: []
  require_confirmation: ["rm *"]
network:
  allow: ["example.com"]
  deny: []
secrets:
  action: block
""",
        encoding="utf-8",
    )
    policy = load_policy(path)
    engine = PolicyEngine(policy)
    assert engine.check_filesystem("secrets/key.pem").action == Decision.BLOCK
    assert engine.check_shell("ls").action == Decision.ALLOW
    assert engine.check_shell("rm file").require_confirmation
    assert engine.check_network("example.com").action == Decision.ALLOW
    assert engine.check_network("evil.com").action == Decision.BLOCK
