"""Run AgentWall security benchmarks."""

from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any

from agentwall.models.types import ContentEnvelope, Decision
from agentwall.shield import Shield

# Bundled sample suites live next to this module's package data, or under repo benchmarks/
_PACKAGE_ROOT = Path(__file__).resolve().parents[2]
_DEFAULT_DIR = _PACKAGE_ROOT / "benchmarks"


def _load_jsonl(path: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    with path.open(encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            rows.append(json.loads(line))
    return rows


def _evaluate_scan(shield: Shield, row: dict[str, Any]) -> bool:
    """Return True if the verdict matches the expected malicious/benign label."""
    expect_block = bool(row.get("malicious", row.get("expect_block", False)))
    source = row.get("source", "user")
    trust = row.get("trust")
    text = row["text"]

    if trust or source in {"web", "document", "email", "tool"}:
        result = shield.scan(
            ContentEnvelope(
                content=text,
                source=source,
                trust=trust or ("untrusted" if source != "user" else "trusted"),
            )
        )
    else:
        result = shield.scan(text)

    blocked = result.action in {Decision.BLOCK, Decision.REVIEW} and (
        result.action == Decision.BLOCK or expect_block
    )
    # For detection metrics: malicious should be BLOCK (or at least REVIEW with threats)
    if expect_block:
        return result.action == Decision.BLOCK or (
            result.action == Decision.REVIEW and len(result.threats) > 0
        )
    # Benign should be ALLOW
    return result.action == Decision.ALLOW


def _evaluate_tool(shield: Shield, row: dict[str, Any]) -> bool:
    expect_block = bool(row.get("malicious", row.get("expect_block", False)))
    kind = row.get("kind", "shell")
    if kind == "shell":
        decision = shield.check_shell(row["command"])
    elif kind == "filesystem":
        decision = shield.check_filesystem(row["path"])
    elif kind == "network":
        decision = shield.check_network(row["url"])
    else:
        decision = shield.check_tool(row)

    if expect_block:
        return decision.action in {Decision.BLOCK, Decision.REVIEW}
    return decision.action == Decision.ALLOW


def run_benchmarks(
    directory: Path | None = None,
    *,
    policy: str | Path | None = None,
) -> dict[str, Any]:
    bench_dir = directory or _DEFAULT_DIR
    shield = Shield(policy=policy, audit=False)

    suites: list[dict[str, Any]] = []
    total = 0
    detected = 0
    fp = 0
    benign_total = 0
    start = time.perf_counter()

    if not bench_dir.exists():
        return {
            "suites": [],
            "total": 0,
            "overall_detection": 0.0,
            "overall_false_positive": 0.0,
            "elapsed_s": 0.0,
            "error": f"Benchmark directory not found: {bench_dir}",
        }

    for path in sorted(bench_dir.glob("*.jsonl")):
        rows = _load_jsonl(path)
        name = path.stem
        is_tool = name.endswith("_attacks") and name.split("_")[0] in {
            "shell",
            "filesystem",
            "network",
        }
        # Also treat shell/filesystem named suites as tool checks when rows have command/path
        suite_detected = 0
        suite_malicious = 0
        suite_fp = 0
        suite_benign = 0

        for row in rows:
            malicious = bool(row.get("malicious", row.get("expect_block", False)))
            use_tool = (
                "command" in row or "path" in row or row.get("kind") in {"shell", "filesystem", "network"}
            ) and name not in {
                "prompt_injection",
                "indirect_injection",
                "secret_exfiltration",
                "safe_prompts",
            }

            ok = _evaluate_tool(shield, row) if use_tool else _evaluate_scan(shield, row)

            if malicious:
                suite_malicious += 1
                if ok:
                    suite_detected += 1
            else:
                suite_benign += 1
                if not ok:
                    suite_fp += 1

        detection_rate = (suite_detected / suite_malicious) if suite_malicious else 1.0
        fp_rate = (suite_fp / suite_benign) if suite_benign else 0.0

        suites.append(
            {
                "name": name,
                "total": len(rows),
                "malicious": suite_malicious,
                "benign": suite_benign,
                "detection_rate": detection_rate,
                "false_positive_rate": fp_rate,
            }
        )
        total += len(rows)
        detected += suite_detected
        fp += suite_fp
        benign_total += suite_benign

    malicious_total = sum(s["malicious"] for s in suites)
    elapsed = time.perf_counter() - start
    return {
        "suites": suites,
        "total": total,
        "overall_detection": (detected / malicious_total) if malicious_total else 1.0,
        "overall_false_positive": (fp / benign_total) if benign_total else 0.0,
        "elapsed_s": elapsed,
    }
