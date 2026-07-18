#!/usr/bin/env python3
"""Tests for the control-plane candidate registry."""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from tools.control.candidates import Candidate, discover_candidates, paste_ready_blockers


class ControlCandidateRegistryTests(unittest.TestCase):
    def test_revert_like_submitted_markdown_is_discovered(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            submission_dir = ws / "submissions" / "cantina_paste"
            submission_dir.mkdir(parents=True)
            draft = submission_dir / "revert-dynamic-fee-sentinel.md"
            draft.write_text(
                "\n".join(
                    [
                        "# Factory accepts Uniswap v4 dynamic-fee sentinel as StableSwap LP fee",
                        "",
                        "Severity: Medium",
                        "Likelihood: Low to Medium",
                        "Impact: Denial of normal pool function",
                        "OOS: checked",
                        "",
                        "## Proof of Concept",
                        "```bash",
                        "forge test --match-path test/DynamicFeeSentinelPoC.t.sol -vv",
                        "```",
                        "",
                        "Expected output: 4 passed, 0 failed, 0 skipped",
                        "",
                        "## Recommended Fix",
                        "Reject the dynamic-fee sentinel during StableSwap pool creation.",
                    ]
                )
                + "\n",
                encoding="utf-8",
            )

            candidates = discover_candidates(ws)

            self.assertEqual(len(candidates), 1)
            candidate = candidates[0]
            self.assertEqual(candidate.id, "revert-dynamic-fee-sentinel")
            self.assertEqual(candidate.status, "submitted")
            self.assertEqual(candidate.severity, "Medium")
            self.assertEqual(candidate.likelihood, "Low to Medium")
            self.assertEqual(candidate.impact, "Denial of normal pool function")
            self.assertTrue(candidate.oos_checked)
            self.assertTrue(candidate.inline_poc_ready)
            self.assertIn("forge test", candidate.poc_command)
            self.assertEqual(candidate.poc_result, "4 passed, 0 failed, 0 skipped")
            self.assertEqual(candidate.proof_state, "executed")
            self.assertEqual(paste_ready_blockers(candidate), [])

    def test_paste_ready_blockers_surface_missing_prerequisites(self) -> None:
        candidate = Candidate(
            id="partial",
            title="Partial candidate",
            status="candidate",
            severity="Medium",
            impact="Temporary denial of service",
        )

        blockers = paste_ready_blockers(candidate)

        self.assertIn("missing_likelihood", blockers)
        self.assertIn("missing_oos_check", blockers)
        self.assertIn("missing_inline_poc", blockers)
        self.assertIn("missing_poc_command", blockers)
        self.assertIn("missing_poc_result", blockers)
        self.assertIn("missing_recommended_fix", blockers)
        self.assertNotIn("missing_severity", blockers)
        self.assertNotIn("missing_impact", blockers)

    def test_control_json_and_yaml_rows_are_normalized(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            control_dir = ws / ".auditooor" / "control" / "candidates"
            control_dir.mkdir(parents=True)
            (control_dir / "json-row.json").write_text(
                json.dumps(
                    {
                        "schema": "auditooor.candidate.v1",
                        "id": "json-row",
                        "title": "JSON row",
                        "status": "candidate",
                        "severity": "High",
                        "likelihood": "Medium",
                        "impact_contract": {"listed_impact": "Loss of user funds"},
                        "oos": {"checked": True},
                        "poc": {
                            "inline_ready": True,
                            "command": "forge test --match-test testJson -vv",
                            "result": "1 passed, 0 failed, 0 skipped",
                        },
                        "recommended_fix": "Add validation",
                    }
                ),
                encoding="utf-8",
            )
            (control_dir / "yaml-row.yaml").write_text(
                "\n".join(
                    [
                        "schema: auditooor.candidate.v1",
                        "id: yaml-row",
                        "title: YAML row",
                        "status: oos_checked",
                        "severity: Medium",
                        "likelihood: High",
                        "impact: Pool creation DoS",
                        "oos:",
                        "  checked: true",
                        "poc:",
                        "  inline_ready: true",
                        "  command: forge test --match-test testYaml -vv",
                        "  result: 2 passed, 0 failed, 0 skipped",
                        "recommended_fix: Add validation",
                    ]
                )
                + "\n",
                encoding="utf-8",
            )

            by_id = {candidate.id: candidate for candidate in discover_candidates(ws)}

            self.assertEqual(by_id["json-row"].impact, "Loss of user funds")
            self.assertEqual(by_id["json-row"].proof_state, "executed")
            self.assertEqual(by_id["yaml-row"].title, "YAML row")
            self.assertTrue(by_id["yaml-row"].oos_checked)
            self.assertEqual(paste_ready_blockers(by_id["yaml-row"]), [])

    def test_poc_execution_manifest_is_discovered(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            manifest_dir = ws / "poc_execution" / "amp-zero"
            manifest_dir.mkdir(parents=True)
            manifest = manifest_dir / "execution_manifest.json"
            manifest.write_text(
                json.dumps(
                    {
                        "candidate_id": "amp-zero",
                        "title": "Amplification factor can be zero",
                        "command": "forge test --match-path test/AmpZeroPoC.t.sol -vv",
                        "result": "proved",
                    }
                ),
                encoding="utf-8",
            )

            candidates = discover_candidates(ws)

            self.assertEqual(len(candidates), 1)
            self.assertEqual(candidates[0].id, "amp-zero")
            self.assertEqual(candidates[0].status, "poc_executed")
            self.assertEqual(candidates[0].proof_state, "proved")
            self.assertEqual(candidates[0].poc_result, "proved")


if __name__ == "__main__":
    unittest.main()
