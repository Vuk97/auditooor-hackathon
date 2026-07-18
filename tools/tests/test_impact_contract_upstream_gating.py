"""Upstream impact-contract gating for mining priorities and briefs.

These tests pin the PR560/P0 rule that reportable or direct-submit work must
carry the exact listed impact, required evidence class, OOS traps, and stop
condition before harness/report work starts.
"""
from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


REPO = Path(__file__).resolve().parents[2]
PRIORITIZER = REPO / "tools" / "mining-prioritizer.py"
BRIEF_GENERATOR = REPO / "tools" / "mining-brief-generator.py"

SEVERITY = """# Test Severity

## High-tier listed impacts
- Temporary freezing of user funds (recoverable within a finalization window)

## Medium-tier listed impacts
- Griefing of a single RPC endpoint
"""


def _write_workspace(ws: Path) -> None:
    (ws / "SEVERITY.md").write_text(SEVERITY, encoding="utf-8")
    (ws / "ccia_report.json").write_text(
        json.dumps(
            {
                "ccia": {},
                "attack_angles": [
                    {
                        "id": "A-AUTH",
                        "severity": "HIGH",
                        "title": "Unauthenticated Vault.freeze",
                        "contracts": ["Vault"],
                    }
                ],
            },
            indent=2,
        ),
        encoding="utf-8",
    )


def _run(cmd: list[str], cwd: Path = REPO) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        cmd,
        cwd=cwd,
        capture_output=True,
        text=True,
        timeout=30,
    )


class UpstreamImpactContractGatingTest(unittest.TestCase):
    def test_prioritizer_marks_high_angle_not_submit_ready_without_contract(self) -> None:
        with tempfile.TemporaryDirectory(prefix="impact-upstream-") as tmp:
            ws = Path(tmp)
            _write_workspace(ws)
            out = ws / "swarm" / "mining_priorities.json"

            proc = _run(
                [
                    sys.executable,
                    str(PRIORITIZER),
                    str(ws),
                    "--top",
                    "1",
                    "--out",
                    str(out),
                    "--no-outcome-reweight",
                ]
            )

            self.assertEqual(proc.returncode, 0, proc.stderr)
            row = json.loads(out.read_text(encoding="utf-8"))[0]
            contract = row["impact_contract"]
            self.assertTrue(contract["required"])
            self.assertEqual(contract["status"], "missing_contract")
            self.assertEqual(contract["submission_posture"], "in_scope_not_submit_ready")
            self.assertEqual(contract["selected_impact"], "")
            self.assertIn("impact_contract_missing", contract["reasons"])

    def test_prioritizer_carries_locked_contract_fields(self) -> None:
        with tempfile.TemporaryDirectory(prefix="impact-upstream-") as tmp:
            ws = Path(tmp)
            _write_workspace(ws)
            aud = ws / ".auditooor"
            aud.mkdir()
            (aud / "impact_contracts.json").write_text(
                json.dumps(
                    {
                        "contracts": [
                            {
                                "candidate_id": "A-AUTH",
                                "impact_contract_id": "impact-contract-vault-freeze",
                                "angle_id": "A-AUTH",
                                "contract": "Vault",
                                "selected_impact": (
                                    "Temporary freezing of user funds "
                                    "(recoverable within a finalization window)"
                                ),
                                "severity_tier": "High",
                                "listed_impact_proven": True,
                                "evidence_class": "executed_with_manifest",
                                "oos_traps": ["admin-only path", "project inaction"],
                                "stop_condition": (
                                    "Stop if the executed manifest does not freeze "
                                    "a non-privileged user's funds."
                                ),
                            }
                        ]
                    },
                    indent=2,
                ),
                encoding="utf-8",
            )
            out = ws / "swarm" / "mining_priorities.json"

            proc = _run(
                [
                    sys.executable,
                    str(PRIORITIZER),
                    str(ws),
                    "--top",
                    "1",
                    "--out",
                    str(out),
                    "--no-outcome-reweight",
                ]
            )

            self.assertEqual(proc.returncode, 0, proc.stderr)
            row = json.loads(out.read_text(encoding="utf-8"))[0]
            contract = row["impact_contract"]
            self.assertEqual(contract["status"], "mapped", contract)
            self.assertEqual(contract["impact_contract_id"], "impact-contract-vault-freeze")
            self.assertEqual(contract["evidence_class"], "executed_with_manifest")
            self.assertEqual(contract["oos_traps"], ["admin-only path", "project inaction"])
            self.assertIn("Temporary freezing", contract["selected_impact"])
            self.assertIn("non-privileged", contract["stop_condition"])

    def test_mining_brief_surfaces_missing_contract_stop_condition(self) -> None:
        with tempfile.TemporaryDirectory(prefix="impact-brief-") as tmp:
            ws = Path(tmp)
            _write_workspace(ws)
            out_dir = ws / "briefs"

            proc = _run(
                [
                    sys.executable,
                    str(BRIEF_GENERATOR),
                    str(ws),
                    "--top",
                    "1",
                    "--out-dir",
                    str(out_dir),
                ]
            )

            self.assertEqual(proc.returncode, 0, proc.stderr)
            briefs = sorted(out_dir.glob("*.md"))
            self.assertEqual(len(briefs), 1)
            body = briefs[0].read_text(encoding="utf-8")
            self.assertIn("## Impact Contract Gate", body)
            self.assertIn("Submission posture: `in_scope_not_submit_ready`", body)
            self.assertIn("Exact listed impact: `none`", body)
            self.assertIn("Required evidence class: `missing`", body)
            self.assertIn("Stop condition: `missing`", body)
            self.assertIn("`impact_contract_missing`", body)


if __name__ == "__main__":
    unittest.main()
