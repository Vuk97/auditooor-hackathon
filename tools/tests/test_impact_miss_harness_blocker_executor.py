#!/usr/bin/env python3
"""Tests for Impact-Miss harness/blocker execution materialization."""

from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
EXECUTOR = ROOT / "tools" / "impact-miss-harness-blocker-executor.py"


def _write_queue_fixture(ws: Path, queue: Path) -> None:
    tiers = ["Critical"] * 48 + ["High"] * 48 + ["Low"] * 48 + ["Medium"] * 48
    rows = []
    for idx, tier in enumerate(tiers):
        benchmark_id = f"imo-{tier.lower()}-route-{idx + 1:03d}"
        if idx == 0:
            benchmark_id = "imo-critical-asset-custody-01"
        elif idx == 1:
            benchmark_id = "imo-critical-access-control-01"
        artifacts = []
        if idx < 176:
            artifacts.append({"artifact": "funds_flow_poc_or_fork_replay"})
        if idx < 80:
            artifacts.append({"artifact": "poc_execution_manifest"})
            brief = ws / ".auditooor" / "impact_miss_harness_briefs" / f"{benchmark_id}.md"
            brief.parent.mkdir(parents=True, exist_ok=True)
            brief.write_text(f"# {benchmark_id}\n\nNeutral blocker fixture.\n", encoding="utf-8")
        if idx < 48:
            artifacts.append({"artifact": "source_proof"})
        rows.append(
            {
                "task_id": f"impact-miss-{benchmark_id}",
                "benchmark_id": benchmark_id,
                "tier": tier,
                "route_family": "asset-custody" if idx == 0 else "access-control",
                "asset_category": "base",
                "harness_family": "neutral-blocker",
                "required_artifacts": artifacts,
            }
        )
    queue.parent.mkdir(parents=True, exist_ok=True)
    queue.write_text(json.dumps({"rows": rows}, indent=2) + "\n", encoding="utf-8")


class ImpactMissHarnessBlockerExecutorTests(unittest.TestCase):
    def test_materializes_cross_tier_next_steps_without_proof_claims(self) -> None:
        with tempfile.TemporaryDirectory(prefix="imo_executor_") as tmp:
            ws = Path(tmp)
            queue = ws / ".auditooor" / "impact_miss_harness_blocker_queue.json"
            _write_queue_fixture(ws, queue)

            out = ws / ".auditooor" / "execution.json"
            proc = subprocess.run(
                [
                    sys.executable,
                    str(EXECUTOR),
                    "--workspace",
                    str(ws),
                    "--queue",
                    str(queue),
                    "--execute-safe",
                    "--out-json",
                    str(out),
                ],
                cwd=ROOT,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )
            self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
            payload = json.loads(out.read_text(encoding="utf-8"))
            self.assertEqual(payload["schema"], "auditooor.pr560.impact_miss_harness_blocker_execution.v1")
            self.assertEqual(payload["summary"]["processed"], 192)
            self.assertFalse(payload["promotion_allowed"])
            self.assertEqual(payload["submission_posture"], "NOT_SUBMIT_READY")
            self.assertEqual(payload["summary"]["tier_counts"], {"Critical": 48, "High": 48, "Low": 48, "Medium": 48})
            self.assertEqual(payload["summary"]["action_counts"]["executable_harness_scaffold"], 176)
            self.assertEqual(payload["summary"]["action_counts"]["source_proof_next_step"], 48)
            self.assertEqual(payload["summary"]["action_counts"]["blocked_path_execution_manifest"], 80)

            harness = ws / "poc-tests" / "imo-critical-asset-custody-01" / "run_harness.sh"
            self.assertTrue(harness.is_file())
            self.assertIn("blocked_missing_target_project", harness.read_text(encoding="utf-8"))
            manifest = ws / "poc_execution" / "imo-critical-asset-custody-01" / "execution_manifest.json"
            self.assertTrue(manifest.is_file())
            manifest_payload = json.loads(manifest.read_text(encoding="utf-8"))
            self.assertEqual(manifest_payload["final_result"], "blocked_path")
            self.assertEqual(manifest_payload["impact_assertion"], "not_demonstrated")
            self.assertNotEqual(manifest_payload["final_result"], "proved")

            source_proof = ws / "source_proofs" / "imo-critical-access-control-01-source-proof" / "source_proof.json"
            self.assertTrue(source_proof.is_file())
            self.assertIn("blocked_missing_project_source_citation", source_proof.read_text(encoding="utf-8"))
            contracts = json.loads((ws / ".auditooor" / "impact_contracts.json").read_text(encoding="utf-8"))
            self.assertEqual(len(contracts["contracts"]), 192)
            self.assertFalse(any(contract.get("listed_impact_proven") for contract in contracts["contracts"]))


if __name__ == "__main__":
    unittest.main()
