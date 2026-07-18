#!/usr/bin/env python3
"""Regression tests for tools/impact-contract-preflight.py."""
from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import textwrap
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
TOOL = ROOT / "tools" / "impact-contract-preflight.py"


def _run(path: Path, route: str = "filing") -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(TOOL), str(path), "--route", route],
        capture_output=True,
        text=True,
    )


class ImpactContractPreflightTests(unittest.TestCase):
    def test_proof_grade_draft_without_explicit_contract_is_blocked(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            draft = Path(tmp) / "draft.md"
            draft.write_text(
                textwrap.dedent(
                    """
                    # Vault accounting bug

                    **Severity:** High

                    ## Exploit Goal
                    Drain the vault by replaying `withdraw()`.
                    """
                ).strip()
                + "\n",
                encoding="utf-8",
            )
            proc = _run(draft, "filing")
            self.assertEqual(proc.returncode, 2, proc.stdout)
            payload = json.loads(proc.stdout)
            self.assertTrue(payload["decision"]["blocked"])
            self.assertEqual(payload["decision"]["code"], "impact-contract-missing")

    def test_explicit_markdown_contract_allows_filing(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            draft = Path(tmp) / "draft.md"
            draft.write_text(
                textwrap.dedent(
                    """
                    # Vault accounting bug

                    ## Impact Contract
                    - Victim: vault LPs
                    - Source proof: src/Vault.sol:101-144
                    - Exploit memory: attacker replays `withdraw()` before accounting settles
                    - selected_impact: Direct theft of user funds
                    - severity_tier: Critical
                    - listed_impact_proven: true
                    - evidence_class: forge_test
                    - oos_traps: admin-only path excluded by public withdraw caller
                    - stop_condition: stop if the forge PoC no longer drains LP assets
                    """
                ).strip()
                + "\n",
                encoding="utf-8",
            )
            proc = _run(draft, "filing")
            self.assertEqual(proc.returncode, 0, proc.stdout)
            payload = json.loads(proc.stdout)
            self.assertFalse(payload["decision"]["blocked"])
            self.assertTrue(payload["impact_contract"]["explicit"])
            self.assertIn("victim", payload["impact_contract"]["actor_fields_present"])
            self.assertIn("source-proof", payload["impact_contract"]["anchor_fields_present"])
            self.assertEqual(payload["impact_contract"]["missing_l27_directives"], [])

    def test_planning_json_gets_advisory_bypass(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            artifact = Path(tmp) / "candidate.json"
            artifact.write_text(
                json.dumps(
                    {
                        "kind": "poc_plan",
                        "contract": "Vault",
                        "angle_id": "A-RACE",
                        "exploit_goal": "Need live proof first",
                    },
                    indent=2,
                ),
                encoding="utf-8",
            )
            proc = _run(artifact, "promotion")
            self.assertEqual(proc.returncode, 0, proc.stdout)
            payload = json.loads(proc.stdout)
            self.assertFalse(payload["decision"]["blocked"])
            self.assertTrue(payload["decision"]["advisory_bypass"])
            self.assertEqual(
                payload["decision"]["code"],
                "planning-artifact-advisory-bypass",
            )

    def test_explicit_json_contract_allows_promotion(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            artifact = Path(tmp) / "candidate.json"
            artifact.write_text(
                json.dumps(
                    {
                        "kind": "candidate_finding",
                        "impact_contract": {
                            "victim": "vault LPs",
                            "harness_scaffold": "poc-tests/VaultRacePlan.t.sol",
                            "selected_impact": "Temporary freezing of user funds",
                            "severity_tier": "High",
                            "listed_impact_proven": True,
                            "evidence_class": "forge_test",
                            "oos_traps": ["admin-only path", "oracle-only path"],
                            "stop_condition": "Stop if the harness no longer freezes withdrawals.",
                        },
                    },
                    indent=2,
                ),
                encoding="utf-8",
            )
            proc = _run(artifact, "promotion")
            self.assertEqual(proc.returncode, 0, proc.stdout)
            payload = json.loads(proc.stdout)
            self.assertEqual(payload["decision"]["code"], "impact-contract-explicit")
            self.assertIn("harness-scaffold", payload["impact_contract"]["anchor_fields_present"])
            self.assertEqual(payload["impact_contract"]["missing_l27_directives"], [])

    def test_actor_and_anchor_without_l27_directives_is_blocked(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            draft = Path(tmp) / "draft.md"
            draft.write_text(
                textwrap.dedent(
                    """
                    # Vault accounting bug

                    ## Impact Contract
                    - Victim: vault LPs
                    - Source proof: src/Vault.sol:101-144
                    """
                ).strip()
                + "\n",
                encoding="utf-8",
            )
            proc = _run(draft, "filing")
            self.assertEqual(proc.returncode, 2, proc.stdout)
            payload = json.loads(proc.stdout)
            self.assertTrue(payload["decision"]["blocked"])
            self.assertEqual(payload["decision"]["code"], "impact-contract-missing")
            self.assertEqual(
                payload["impact_contract"]["missing_l27_directives"],
                [
                    "evidence-class",
                    "listed-impact-proven",
                    "oos-traps",
                    "selected-impact",
                    "severity-tier",
                    "stop-condition",
                ],
            )

    def test_missing_evidence_class_is_reported_as_l27_directive_gap(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            draft = Path(tmp) / "draft.md"
            draft.write_text(
                textwrap.dedent(
                    """
                    # Vault accounting bug

                    ## Impact Contract
                    - Victim: vault LPs
                    - Source proof: src/Vault.sol:101-144
                    - selected_impact: Direct theft of user funds
                    - severity_tier: Critical
                    - listed_impact_proven: true
                    - oos_traps: admin-only path excluded
                    - stop_condition: stop if proof no longer drains funds
                    """
                ).strip()
                + "\n",
                encoding="utf-8",
            )
            proc = _run(draft, "filing")
            self.assertEqual(proc.returncode, 2, proc.stdout)
            payload = json.loads(proc.stdout)
            self.assertEqual(payload["impact_contract"]["missing_l27_directives"], ["evidence-class"])

    def test_listed_impact_proven_must_be_truthy_for_proof_grade_artifact(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            draft = Path(tmp) / "draft.md"
            draft.write_text(
                textwrap.dedent(
                    """
                    # Vault accounting bug

                    ## Impact Contract
                    - Victim: vault LPs
                    - Source proof: src/Vault.sol:101-144
                    - selected_impact: Direct theft of user funds
                    - severity_tier: Critical
                    - listed_impact_proven: false
                    - evidence_class: forge_test
                    - oos_traps: admin-only path excluded
                    - stop_condition: stop if proof no longer drains funds
                    """
                ).strip()
                + "\n",
                encoding="utf-8",
            )
            proc = _run(draft, "filing")
            self.assertEqual(proc.returncode, 2, proc.stdout)
            payload = json.loads(proc.stdout)
            self.assertEqual(
                payload["impact_contract"]["missing_l27_directives"],
                ["listed-impact-proven"],
            )

    def test_multiline_oos_traps_list_counts_as_directive(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            draft = Path(tmp) / "draft.md"
            draft.write_text(
                textwrap.dedent(
                    """
                    # Vault accounting bug

                    ## Impact Contract
                    - Victim: vault LPs
                    - Source proof: src/Vault.sol:101-144
                    - selected_impact: Direct theft of user funds
                    - severity_tier: Critical
                    - listed_impact_proven: true
                    - evidence_class: forge_test
                    - oos_traps:
                      - admin-only path excluded
                      - oracle-only path excluded
                    - stop_condition: stop if proof no longer drains funds
                    """
                ).strip()
                + "\n",
                encoding="utf-8",
            )
            proc = _run(draft, "filing")
            self.assertEqual(proc.returncode, 0, proc.stdout)
            payload = json.loads(proc.stdout)
            self.assertEqual(payload["impact_contract"]["missing_l27_directives"], [])

    def test_placeholder_oos_traps_is_blocked(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            draft = Path(tmp) / "draft.md"
            draft.write_text(
                textwrap.dedent(
                    """
                    # Vault accounting bug

                    ## Impact Contract
                    - Victim: vault LPs
                    - Source proof: src/Vault.sol:101-144
                    - selected_impact: Direct theft of user funds
                    - severity_tier: Critical
                    - listed_impact_proven: true
                    - evidence_class: forge_test
                    - oos_traps: none
                    - stop_condition: stop if proof no longer drains funds
                    """
                ).strip()
                + "\n",
                encoding="utf-8",
            )
            proc = _run(draft, "filing")
            self.assertEqual(proc.returncode, 2, proc.stdout)
            payload = json.loads(proc.stdout)
            self.assertEqual(payload["impact_contract"]["missing_l27_directives"], ["oos-traps"])

    def test_json_contract_missing_stop_condition_is_blocked(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            artifact = Path(tmp) / "candidate.json"
            artifact.write_text(
                json.dumps(
                    {
                        "kind": "candidate_finding",
                        "impact_contract": {
                            "victim": "vault LPs",
                            "harness_scaffold": "poc-tests/VaultRacePlan.t.sol",
                            "selected_impact": "Temporary freezing of user funds",
                            "severity_tier": "High",
                            "listed_impact_proven": True,
                            "evidence_class": "forge_test",
                            "oos_traps": ["admin-only path"],
                        },
                    },
                    indent=2,
                ),
                encoding="utf-8",
            )
            proc = _run(artifact, "promotion")
            self.assertEqual(proc.returncode, 2, proc.stdout)
            payload = json.loads(proc.stdout)
            self.assertEqual(payload["impact_contract"]["missing_l27_directives"], ["stop-condition"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
