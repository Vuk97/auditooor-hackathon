#!/usr/bin/env python3
"""Candidate debate dispatcher for auditooor toolkit.

Runs an attacker/defender/referee 3-perspective triad on candidate findings.
Leverages existing adversarial-copilot.py and defender-narrative-simulator.py
if available; otherwise emits deterministic-stub verdicts.

CLI:
  python3 tools/candidate-debate-dispatcher.py --workspace <path> \\
      --candidate-file <path> --output <path>

Output JSON schema (auditooor.candidate_debate.v1):
  {
    "schema_id": "auditooor.candidate_debate.v1",
    "candidate_id": str,
    "attacker_claim": str,
    "defender_rebuttal": str,
    "referee_verdict": "candidate-stands" | "walked-back" | "dropped",
    "reasoning": str
  }
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from pathlib import Path
from typing import Any

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

SCHEMA_ID = "auditooor.candidate_debate.v1"
EXIT_OK = 0
EXIT_INPUT = 1
EXIT_INFRA = 2

COPILOT = "tools/adversarial-copilot.py"
DEFENDER = "tools/defender-narrative-simulator.py"


# ---------------------------------------------------------------------------
# Tool discovery
# ---------------------------------------------------------------------------

def _tool_exists(workspace: Path, rel: str) -> Path | None:
    p = workspace / rel
    return p if p.is_file() else None


def _run_subprocess(cmd: list[str], timeout: int = 120) -> dict[str, Any] | None:
    """Run *cmd*, return parsed JSON stdout or None on any failure."""
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        if r.returncode == 0 and r.stdout.strip():
            return json.loads(r.stdout)
    except (subprocess.TimeoutExpired, json.JSONDecodeError, OSError):
        pass
    return None


# ---------------------------------------------------------------------------
# Debate phases
# ---------------------------------------------------------------------------

def run_attacker(workspace: Path, candidate: dict[str, Any]) -> str:
    """Produce attacker claim via copilot or stub."""
    copilot = _tool_exists(workspace, COPILOT)
    if copilot:
        res = _run_subprocess([
            sys.executable, str(copilot),
            "--workspace", str(workspace),
            "--candidate-json", json.dumps(candidate),
        ])
        if res and "claim" in res:
            return res["claim"]
    # Deterministic stub
    desc = candidate.get("description", candidate.get("summary", ""))
    return f"[STUB-ATTACKER] Exploit vector: {desc[:200]}"


def run_defender(workspace: Path, candidate: dict[str, Any], claim: str) -> str:
    """Produce defender rebuttal via simulator or stub."""
    defender = _tool_exists(workspace, DEFENDER)
    if defender:
        res = _run_subprocess([
            sys.executable, str(defender),
            "--workspace", str(workspace),
            "--candidate-json", json.dumps(candidate),
            "--attacker-claim", claim,
        ])
        if res and "rebuttal" in res:
            return res["rebuttal"]
    # Deterministic stub
    return f"[STUB-DEFENDER] Claim addresses design intent; mitigated by existing controls."


def run_referee(candidate: dict[str, Any], claim: str, rebuttal: str) -> dict[str, str]:
    """Determine referee verdict and reasoning."""
    # Heuristic: count rebuttal strength signals
    strength_signals = len(re.findall(
        r"(?i)(mitigated|designed|intended|by design|not vulnerable|invalid)",
        rebuttal,
    ))
    weakness_signals = len(re.findall(
        r"(?i)(valid|confirmed|exploitable|unmitigated|bypass)",
        rebuttal,
    ))

    if strength_signals >= 2 and weakness_signals == 0:
        verdict = "walked-back"
        reasoning = (
            f"Defender rebuttal ({len(rebuttal)} chars) raised {strength_signals} "
            f"mitigation signals with 0 concession signals."
        )
    elif weakness_signals >= 1 and strength_signals <= 1:
        verdict = "candidate-stands"
        reasoning = (
            f"Defender raised {weakness_signals} concession signals vs "
            f"{strength_signals} mitigation signals; attacker claim holds."
        )
    else:
        verdict = "dropped"
        reasoning = (
            f"Ambiguous rebuttal (strength={strength_signals}, "
            f"weakness={weakness_signals}); candidate dropped pending manual review."
        )

    return {"verdict": verdict, "reasoning": reasoning}


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> int:
    ap = argparse.ArgumentParser(
        description="Run attacker/defender/referee triad on a candidate finding."
    )
    ap.add_argument("--workspace", required=True, help="Path to workspace root")
    ap.add_argument("--candidate-file", required=True, help="Path to candidate JSON file")
    ap.add_argument("--output", required=True, help="Path to write output JSON")
    args = ap.parse_args()

    workspace = Path(args.workspace)
    candidate_path = Path(args.candidate_file)
    output_path = Path(args.output)

    if not candidate_path.is_file():
        print(f"error: candidate file not found: {candidate_path}", file=sys.stderr)
        return EXIT_INPUT

    try:
        candidate: dict[str, Any] = json.loads(candidate_path.read_text())
    except (json.JSONDecodeError, OSError) as exc:
        print(f"error: cannot read candidate file: {exc}", file=sys.stderr)
        return EXIT_INPUT

    candidate_id = candidate.get("candidate_id") or candidate.get("id") or "unknown"

    # Run triad
    claim = run_attacker(workspace, candidate)
    rebuttal = run_defender(workspace, candidate, claim)
    ref = run_referee(candidate, claim, rebuttal)

    result: dict[str, Any] = {
        "schema_id": SCHEMA_ID,
        "candidate_id": candidate_id,
        "attacker_claim": claim,
        "defender_rebuttal": rebuttal,
        "referee_verdict": ref["verdict"],
        "reasoning": ref["reasoning"],
    }

    try:
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(json.dumps(result, indent=2, ensure_ascii=False) + "\n")
    except OSError as exc:
        print(f"error: cannot write output: {exc}", file=sys.stderr)
        return EXIT_INFRA

    # Also print to stdout
    print(json.dumps(result, indent=2, ensure_ascii=False))
    return EXIT_OK


if __name__ == "__main__":
    sys.exit(main())
