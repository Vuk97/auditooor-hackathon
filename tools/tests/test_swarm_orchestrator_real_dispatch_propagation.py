#!/usr/bin/env python3
"""FIX-7B — failure propagation tests for tools/swarm-orchestrator.py.

Two hermetic subprocess tests that lock the Codex fix-spec for
`dispatch()` + `main()` exit-code propagation:
  1. `SWARM_REAL_DISPATCH=1` without consent → non-zero exit from main.
  2. Default printer mode (env var unset) → exit 0 (regression lock).

Both tests run `swarm-orchestrator.py` as a subprocess so they exercise
`sys.exit(main())` directly. No network: the consent test fails at the
consent gate in `llm-dispatch.py` before any urlopen call, and the
default-mode test never shells out.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
SWARM_TOOL = ROOT / "tools" / "swarm-orchestrator.py"


def _scrub_env() -> dict:
    """Strip every variable that could inject consent / keys into the subprocess."""
    drop = {
        "SWARM_REAL_DISPATCH", "SWARM_REAL_DISPATCH_MODEL",
        "SWARM_REAL_DISPATCH_MAX_TOKENS", "ANTHROPIC_API_KEY",
        "ANTHROPIC_AUTH_TOKEN", "ANTHROPIC_BASE_URL", "ANTHROPIC_MODEL",
        "KIMI_API_KEY", "KIMI_ANTHROPIC_BASE_URL", "KIMI_MODEL",
        "MINIMAX_API_KEY", "MINIMAX_ANTHROPIC_BASE_URL", "MINIMAX_MODEL",
        "AUDITOOOR_LLM_PROVIDER", "AUDITOOOR_LLM_AUTH_HEADER",
        "AUDITOOOR_LLM_NETWORK_CONSENT", "ADVERSARIAL_LIVE_CONSENT",
    }
    return {k: v for k, v in os.environ.items() if k not in drop}


def _write_workspace(tmp: Path) -> None:
    swarm_dir = tmp / "swarm"
    swarm_dir.mkdir(parents=True, exist_ok=True)
    manifest = {
        "workspace": str(tmp),
        "generated_at": "2026-04-24",
        "total_contracts": 1,
        "briefs_written": 1,
        "groups": {},
        "brief_metadata": {
            "TestContract": {
                "contract": "TestContract",
                "has_mining_proof_context": False,
            }
        },
    }
    (swarm_dir / "manifest.json").write_text(json.dumps(manifest))
    (swarm_dir / "brief_TestContract.md").write_text("# stub\n")


def _write_blocked_workspace(tmp: Path) -> None:
    swarm_dir = tmp / "swarm"
    swarm_dir.mkdir(parents=True, exist_ok=True)
    manifest = {
        "workspace": str(tmp),
        "generated_at": "2026-04-24",
        "total_contracts": 1,
        "briefs_written": 1,
        "groups": {},
        "brief_metadata": {
            "BlockedContract": {
                "contract": "BlockedContract",
                "has_mining_proof_context": True,
                "impact_contract_required": True,
                "impact_contract_id": "",
                "dispatch_blocked_missing_impact_contract": True,
                "impact_contract_gate_sources": ["swarm/mining_briefs/brief_001_A-RACE.md"],
            }
        },
    }
    (swarm_dir / "manifest.json").write_text(json.dumps(manifest))
    (swarm_dir / "brief_BlockedContract.md").write_text("# blocked\n")


class RealDispatchNoConsentPropagationTest(unittest.TestCase):
    """Test #7 — SWARM_REAL_DISPATCH=1 without consent → non-zero exit."""

    def test_real_dispatch_with_no_consent_exits_nonzero(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            _write_workspace(tmp_path)
            env = _scrub_env()
            # Turn on real-dispatch but deliberately withhold consent.
            env["SWARM_REAL_DISPATCH"] = "1"
            # Supply a fake key so we reach past the no-api-key path and
            # specifically exercise the consent gate.
            env["ANTHROPIC_API_KEY"] = "sk-test"
            cmd = [sys.executable, str(SWARM_TOOL), str(tmp_path), "--dispatch"]
            proc = subprocess.run(cmd, capture_output=True, text=True, env=env)
            self.assertNotEqual(
                proc.returncode, 0,
                f"expected non-zero exit; stdout={proc.stdout!r} stderr={proc.stderr!r}",
            )
            # Stderr (from llm-dispatch) should mention the no-consent reason.
            self.assertIn("cannot-run: no-consent", proc.stderr)


class DefaultPrinterModeReturnsZeroTest(unittest.TestCase):
    """Test #8 — default printer path returns 0 (regression lock)."""

    def test_default_printer_mode_returns_zero(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            _write_workspace(tmp_path)
            env = _scrub_env()
            # Explicitly no SWARM_REAL_DISPATCH.
            cmd = [sys.executable, str(SWARM_TOOL), str(tmp_path), "--dispatch"]
            proc = subprocess.run(cmd, capture_output=True, text=True, env=env)
            self.assertEqual(
                proc.returncode, 0,
                f"expected 0; stdout={proc.stdout!r} stderr={proc.stderr!r}",
            )
            # Default printer should still produce the anchor line.
            self.assertIn(
                "COPY AND PASTE THE FOLLOWING INTO YOUR Claude Code CONVERSATION",
                proc.stdout,
            )


class ImpactContractDispatchGateTest(unittest.TestCase):
    """Missing impact_contract blocks source-mining/swarm dispatch before agent work."""

    def test_missing_impact_contract_blocks_default_dispatch(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            _write_blocked_workspace(tmp_path)
            env = _scrub_env()
            cmd = [sys.executable, str(SWARM_TOOL), str(tmp_path), "--dispatch"]
            proc = subprocess.run(cmd, capture_output=True, text=True, env=env)
            self.assertEqual(
                proc.returncode, 2,
                f"expected impact-contract gate rc=2; stdout={proc.stdout!r} stderr={proc.stderr!r}",
            )
            self.assertIn("REFUSING dispatch: impact_contract is missing", proc.stdout)
            self.assertIn("BlockedContract", proc.stdout)
            self.assertNotIn(
                "COPY AND PASTE THE FOLLOWING INTO YOUR Claude Code CONVERSATION",
                proc.stdout,
            )


if __name__ == "__main__":
    unittest.main()
