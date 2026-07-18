#!/usr/bin/env python3
# r36-rebuttal: lane GAP-INTEG-1 registered in .auditooor/agent_pathspec.json via tools/agent-pathspec-register.py
"""Integration tests for orient-prefilter Gap #30 platform-OOS hook.

Verifies the GAP-INTEG-1 deliverable: orient-prefilter.py now invokes
tools/always-escalate-platform-oos-check.py per-candidate and surfaces
the verdict in the per-candidate gate_results array. When the candidate
framing matches platform OOS clauses, the candidate is downgraded by 2
tiers (or marked extreme at the boundary).

Test strategy: build a synthetic candidates JSON with controlled framing,
run orient-prefilter against a temp workspace that has either a
Hyperbridge-style SCOPE.md (with "theoretical without proof" OOS clause)
or a clean control workspace, and assert verdict deltas.
"""

from __future__ import annotations

import importlib.util
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
TOOL = ROOT / "tools" / "orient-prefilter.py"


# Hyperbridge-style SCOPE.md that triggers the Gap #30 OOS clause.
HYPERBRIDGE_STYLE_SCOPE_MD = """# SCOPE.md

## In scope

- bridge dispatcher
- intent gateway
- Optimism / Arbitrum verifier paths

## Out of scope

- Theoretical vulnerabilities without any proof or demonstration are excluded.
- Centralization risks acknowledged by design.
- Gas optimizations only - excluded.
- Compromise of off-chain infrastructure operated by the team is out of scope.
"""


# Clean control SCOPE.md without any OOS phrases.
CLEAN_CONTROL_SCOPE_MD = """# SCOPE.md

## In scope

- main protocol contracts
"""


def _build_candidates_json(candidates: list[dict]) -> dict:
    """Build a minimal orient-output JSON the prefilter accepts."""
    return {
        "schema_version": "auditooor.orient_output.v1",
        "generated_at_utc": "2026-05-26T00:00:00Z",
        "candidates": candidates,
    }


def _run_prefilter(
    candidates_path: Path,
    workspace: Path,
    audit_pin: str = "deadbeefcafe",
) -> tuple[int, dict]:
    proc = subprocess.run(
        [
            sys.executable,
            str(TOOL),
            "--candidates", str(candidates_path),
            "--workspace", str(workspace),
            "--audit-pin", audit_pin,
            "--json",
        ],
        capture_output=True,
        text=True,
        check=False,
        env=dict(os.environ),
    )
    if not proc.stdout.strip():
        raise AssertionError(
            f"orient-prefilter emitted no stdout. stderr: {proc.stderr[:600]}"
        )
    return proc.returncode, json.loads(proc.stdout)


class OrientPrefilterPlatformOosIntegrationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.tmp_path = Path(self.tmp.name)

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def _make_workspace(self, scope_md_content: str | None) -> Path:
        ws = self.tmp_path / "ws"
        ws.mkdir(parents=True, exist_ok=True)
        if scope_md_content is not None:
            (ws / "SCOPE.md").write_text(scope_md_content, encoding="utf-8")
        return ws

    def _make_candidates_file(self, candidates: list[dict]) -> Path:
        p = self.tmp_path / "candidates.json"
        p.write_text(json.dumps(_build_candidates_json(candidates)), encoding="utf-8")
        return p

    # ------------------------------------------------------------------
    # Gate is invoked + present in gate_results
    # ------------------------------------------------------------------

    def test_gap30_gate_present_in_per_candidate_gate_results(self) -> None:
        ws = self._make_workspace(CLEAN_CONTROL_SCOPE_MD)
        candidates_path = self._make_candidates_file([
            {
                "id": "CAND-1",
                "name": "Real on-chain bug with file:line proof",
                "files": ["src/Bridge.sol:42"],
                "attack_class": "theft",
                "severity_estimate": "high",
                "hypothesis_seeds": [
                    "Bridge.sol:42 missing access control on settle()."
                ],
            },
        ])
        rc, payload = _run_prefilter(candidates_path, ws)
        self.assertEqual(rc, 0, msg=f"prefilter exit={rc} payload={payload}")
        self.assertEqual(len(payload["per_candidate"]), 1)
        gates = payload["per_candidate"][0]["gate_results"]
        gate_names = [g["gate"] for g in gates]
        self.assertIn("GAP30-PLATFORM-OOS", gate_names)
        # Per-candidate gate-kill-risk map also carries it.
        self.assertIn("GAP30-PLATFORM-OOS", payload["per_candidate"][0]["per_gate_kill_risk"])

    # ------------------------------------------------------------------
    # Downgrade fires when framing matches OOS clause
    # ------------------------------------------------------------------

    def test_theoretical_framing_against_hyperbridge_scope_downgrades(self) -> None:
        """Candidate framed as 'theoretical vulnerability without demonstration'
        on a Hyperbridge-style workspace should be downgraded to
        fail-high-kill-risk (extreme via downgrade)."""
        ws = self._make_workspace(HYPERBRIDGE_STYLE_SCOPE_MD)
        candidates_path = self._make_candidates_file([
            {
                "id": "CAND-OOS",
                # Framing explicitly matches "theoretical ... without ... demonstration".
                "name": "Theoretical vulnerability without any proof or demonstration in verifier path",
                "files": ["ismp-optimism/src/lib.rs:256"],
                "attack_class": "theft",
                "severity_estimate": "high",
                "hypothesis_seeds": [
                    "Theoretical vulnerability without proof - speculative attack on the verifier acceptance path."
                ],
            },
        ])
        rc, payload = _run_prefilter(candidates_path, ws)
        self.assertEqual(rc, 0, msg=f"stderr details would surface in CI")
        c = payload["per_candidate"][0]
        # GAP30 gate must have fired with extreme kill-risk.
        gap30 = next(g for g in c["gate_results"] if g["gate"] == "GAP30-PLATFORM-OOS")
        self.assertEqual(gap30["verdict"], "fail-candidate-framing-matches-platform-oos")
        self.assertIn(gap30["kill_risk"], {"high", "extreme"})
        # Final verdict must be fail-high-kill-risk (Gap #30 alone forces
        # this when kill-risk is extreme, even if no other gate fired).
        self.assertEqual(c["verdict"], "fail-high-kill-risk")
        # gap30_downgrade_applied is True only when the explicit downgrade
        # CHANGES the verdict; if other gates (R45 etc) already raised the
        # verdict to fail-high-kill-risk, the downgrade is a no-op. Either
        # way the gate having fired is the load-bearing assertion - verify
        # via the per_gate_kill_risk map.
        self.assertEqual(c["per_gate_kill_risk"]["GAP30-PLATFORM-OOS"], gap30["kill_risk"])

    # ------------------------------------------------------------------
    # Control: clean framing passes without downgrade
    # ------------------------------------------------------------------

    def test_clean_framing_no_downgrade(self) -> None:
        ws = self._make_workspace(CLEAN_CONTROL_SCOPE_MD)
        candidates_path = self._make_candidates_file([
            {
                "id": "CAND-CLEAN",
                "name": "Concrete reentrancy bug in withdraw() with PoC at Vault.sol:88",
                "files": ["src/Vault.sol:88"],
                "attack_class": "theft",
                "severity_estimate": "high",
                "hypothesis_seeds": [
                    "Vault.sol:88 calls externalToken.transfer before updating state."
                ],
            },
        ])
        rc, payload = _run_prefilter(candidates_path, ws)
        self.assertEqual(rc, 0)
        c = payload["per_candidate"][0]
        # GAP30 gate present but should be low.
        gap30 = next(g for g in c["gate_results"] if g["gate"] == "GAP30-PLATFORM-OOS")
        self.assertEqual(gap30["kill_risk"], "low")
        self.assertFalse(c["gap30_downgrade_applied"])
        # No downgrade applied: verdict matches what other gates produced
        # (and the verdict-before-gap30 field equals verdict).
        self.assertEqual(c["verdict"], c["verdict_before_gap30_downgrade"])

    # ------------------------------------------------------------------
    # Workspace without SCOPE.md still runs the default-seed phrase match
    # ------------------------------------------------------------------

    def test_default_seed_matches_speculative_framing_without_scope_file(self) -> None:
        ws = self._make_workspace(None)  # no SCOPE.md
        candidates_path = self._make_candidates_file([
            {
                "id": "CAND-SPEC",
                "name": "speculative attack on the verifier - hypothetical exploit without a proof",
                "files": ["x.sol:1"],
                "attack_class": "theft",
                "severity_estimate": "high",
                "hypothesis_seeds": ["speculative attack scenario."],
            },
        ])
        rc, payload = _run_prefilter(candidates_path, ws)
        self.assertEqual(rc, 0)
        c = payload["per_candidate"][0]
        gap30 = next(g for g in c["gate_results"] if g["gate"] == "GAP30-PLATFORM-OOS")
        # Default seed includes "speculative attack" + "hypothetical ... without a proof".
        self.assertEqual(gap30["verdict"], "fail-candidate-framing-matches-platform-oos")
        self.assertTrue(c["gap30_downgrade_applied"])

    # ------------------------------------------------------------------
    # Top-level verdict-before-gap30 field present + exposed
    # ------------------------------------------------------------------

    def test_verdict_before_gap30_field_exposed_in_payload(self) -> None:
        ws = self._make_workspace(HYPERBRIDGE_STYLE_SCOPE_MD)
        candidates_path = self._make_candidates_file([
            {
                "id": "CAND-A",
                "name": "Theoretical vulnerability without demonstration",
                "files": ["src/A.sol:1"],
                "attack_class": "theft",
                "severity_estimate": "high",
                "hypothesis_seeds": ["Theoretical attack without proof."],
            },
        ])
        rc, payload = _run_prefilter(candidates_path, ws)
        self.assertEqual(rc, 0)
        c = payload["per_candidate"][0]
        self.assertIn("verdict_before_gap30_downgrade", c)
        self.assertIn("gap30_downgrade_applied", c)


if __name__ == "__main__":
    unittest.main()
