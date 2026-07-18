#!/usr/bin/env python3
"""Tests for tools/base-critical-hunt.py orchestrator (PR #544 Lane H).

Synthetic workspace fixture:
  - 1 proved (executable) row with exact-impact proof
  - 1 killed (kill_or_reframe) row
  - 1 blocked (blocked_real_component) row

Exercises:
  - Orchestrator exits 0 on the synthetic fixture.
  - Writes hunt_run.json with all orchestrator step entries.
  - Queue summary lists each status bucket.
  - Step 1 (matrix) is hard-enforced even in non-strict mode.
"""
from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import textwrap
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
TOOL = ROOT / "tools" / "base-critical-hunt.py"


SEVERITY_TEMPLATE = textwrap.dedent(
    """\
    # Severity Rubric

    ## Critical

    - Permanent freeze of user funds
    - Direct theft of user funds without user interaction
    """
)


def _run(args: list, *, cwd=None) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, str(TOOL), *args],
        capture_output=True,
        text=True,
        timeout=60,
        cwd=str(cwd) if cwd else None,
    )


def _make_three_row_workspace() -> Path:
    ws = Path(tempfile.mkdtemp(prefix="bch_ws_"))
    (ws / "SEVERITY.md").write_text(SEVERITY_TEMPLATE, encoding="utf-8")
    cand_dir = ws / "critical_hunt" / "candidates"
    cand_dir.mkdir(parents=True)

    # Row 1 — proved/executable: explicit rubric impact + execution manifest.
    proved = {
        "candidate_id": "C-PROVED",
        "scope_asset": "vault",
        "impact_mapping": "Direct theft of user funds without user interaction",
        "listed_impact_selected": "Direct theft of user funds without user interaction",
        "listed_impact_proven": True,
        "production_path": "external/base-azul/src/Vault.sol:120",
        "required_proof": "forge test --match-test testDrain",
        "artifact_refs": ["external/base-azul/src/Vault.sol"],
    }
    (cand_dir / "proved.json").write_text(json.dumps(proved), encoding="utf-8")
    manifest_dir = ws / "poc_execution" / "C-PROVED"
    manifest_dir.mkdir(parents=True)
    (manifest_dir / "execution_manifest.json").write_text(
        json.dumps(
            {
                "candidate_id": "C-PROVED",
                "final_result": "proved",
                "impact_assertion": "exploit_impact",
                "schema": "auditooor.poc_execution.v1",
            }
        ),
        encoding="utf-8",
    )

    # Row 2 — killed: Critical wording but rubric does not list it.
    killed = {
        "candidate_id": "C-KILLED",
        "scope_asset": "settlement",
        "severity": "Critical",
        "impact_mapping": "Theoretical governance signature replay",
        "production_path": "src/Gov.sol:99",
    }
    (cand_dir / "killed.json").write_text(json.dumps(killed), encoding="utf-8")

    # Row 3 — blocked: rubric-matched impact, but mock-only evidence.
    blocked = {
        "candidate_id": "C-BLOCKED",
        "scope_asset": "bridge",
        "impact_mapping": "Permanent freeze of user funds",
        "production_path": "test/MockBridge.sol:10",
        "artifact_refs": ["test/mocks/MockVerifier.sol"],
        "found_by": "Claude source-reading agent",
        "detector_hits": [],
        "durable_route": "invariant_or_harness",
    }
    (cand_dir / "blocked.json").write_text(json.dumps(blocked), encoding="utf-8")

    return ws


class TestBaseCriticalHunt(unittest.TestCase):
    def test_orchestrator_runs_clean_on_three_row_fixture(self):
        ws = _make_three_row_workspace()
        result = _run(["--workspace", str(ws)])
        # rc=0 because step 1 succeeds; downstream steps are advisory.
        self.assertEqual(result.returncode, 0, result.stderr)
        run_path = ws / "critical_hunt" / "hunt_run.json"
        self.assertTrue(run_path.is_file(), "hunt_run.json must be written")
        payload = json.loads(run_path.read_text(encoding="utf-8"))
        self.assertEqual(payload["schema"], "auditooor.base_critical_hunt_run.v1")
        steps = [r["step"] for r in payload["results"]]
        self.assertEqual(
            steps,
            [
                "candidate_matrix",
                "severity_claim_guard",
                "invariant_ledger_check",
                "program_impact_mapping_check",
                "audit_closeout",
                "consensus_patch_scan",
                "queue_summary",
                "coverage_inventory",
            ],
        )

    def test_queue_summary_reflects_all_three_buckets(self):
        ws = _make_three_row_workspace()
        rc = _run(["--workspace", str(ws)]).returncode
        self.assertEqual(rc, 0)
        summary = (ws / "critical_hunt" / "queue_summary.md").read_text(
            encoding="utf-8"
        )
        self.assertIn("executable", summary)
        self.assertIn("kill_or_reframe", summary)
        self.assertIn("blocked_real_component", summary)
        self.assertIn("C-PROVED", summary)
        self.assertIn("C-KILLED", summary)
        self.assertIn("C-BLOCKED", summary)

    def test_matrix_status_counts(self):
        ws = _make_three_row_workspace()
        _run(["--workspace", str(ws)])
        matrix = json.loads(
            (ws / "critical_hunt" / "base_critical_candidate_matrix.json").read_text(
                encoding="utf-8"
            )
        )
        self.assertEqual(matrix["status_counts"]["executable"], 1)
        self.assertEqual(matrix["status_counts"]["kill_or_reframe"], 1)
        self.assertEqual(matrix["status_counts"]["blocked_real_component"], 1)

    def test_coverage_inventory_surfaces_agent_gap_and_worklists(self):
        ws = _make_three_row_workspace()
        rc = _run(["--workspace", str(ws)]).returncode
        self.assertEqual(rc, 0)
        json_path = ws / ".auditooor" / "coverage_inventory.json"
        md_path = ws / ".auditooor" / "coverage_inventory.md"
        self.assertTrue(json_path.is_file())
        self.assertTrue(md_path.is_file())
        payload = json.loads(json_path.read_text(encoding="utf-8"))
        self.assertEqual(payload["schema"], "auditooor.coverage_inventory.v1")
        self.assertIn("impact_family_worklists", payload)
        self.assertIn("agent_found_not_detector_found", payload)
        gap_ids = {row["behavior_id"] for row in payload["agent_found_not_detector_found"]}
        self.assertIn("C-BLOCKED", gap_ids)
        self.assertEqual(payload["snappy_exact_impact_state"]["state"], "not_present")

    def test_coverage_inventory_records_snappy_not_submit_ready(self):
        ws = Path(tempfile.mkdtemp(prefix="bch_snappy_ws_"))
        (ws / "SEVERITY.md").write_text(
            textwrap.dedent(
                """\
                # Severity Rubric

                ## Critical

                - Node resource consumption >=30%
                """
            ),
            encoding="utf-8",
        )
        cand_dir = ws / "critical_hunt" / "candidates"
        cand_dir.mkdir(parents=True)
        (cand_dir / "snappy.json").write_text(
            json.dumps(
                {
                    "candidate_id": "C-SNAPPY",
                    "scope_asset": "base-reth gossip snappy decode",
                    "severity": "Critical",
                    "impact_mapping": "Node resource consumption >=30%",
                    "listed_impact_selected": "Node resource consumption >=30%",
                    "listed_impact_proven": True,
                    "network_level_evidence": "absent",
                    "component_poc_only": True,
                    "node_resource_consumption_pct": 12,
                    "realistic_non_bruteforce": False,
                    "notes": "mempool impact is not applicable here",
                }
            ),
            encoding="utf-8",
        )
        _run(["--workspace", str(ws)])
        payload = json.loads(
            (ws / ".auditooor" / "coverage_inventory.json").read_text(encoding="utf-8")
        )
        snappy = payload["snappy_exact_impact_state"]
        self.assertEqual(snappy["state"], "NOT_SUBMIT_READY/kill_or_reframe")
        self.assertFalse(snappy["mempool_impact_applicable"])
        self.assertEqual(snappy["rows"][0]["verdict"], "NOT_SUBMIT_READY/kill_or_reframe")

    def test_strict_propagates_matrix_failure(self):
        # Add a Critical-wording-only candidate -> --strict on matrix fails.
        ws = _make_three_row_workspace()
        cand_dir = ws / "critical_hunt" / "candidates"
        (cand_dir / "wordy.json").write_text(
            json.dumps(
                {
                    "candidate_id": "C-WORDY",
                    "severity": "Critical",
                    "impact_mapping": "Hypothetical critical loss",
                }
            ),
            encoding="utf-8",
        )
        rc = _run(["--workspace", str(ws), "--strict"]).returncode
        # rc=1 because matrix --strict fails on critical-wording downgrade.
        self.assertEqual(rc, 1)

    def test_consensus_patch_scan_runs_as_advisory_step(self):
        """rank33-base-consensus: base-consensus-patch-scan is wired as an
        advisory orchestrator step.

        Guard: the consensus_patch_scan step must appear between audit_closeout
        and queue_summary, record a real rc, and never abort the orchestrator
        (rc=0 overall even though the scanner may emit rows). Fails before the
        wiring (step absent / wrong order); passes after.
        """
        ws = _make_three_row_workspace()
        result = _run(["--workspace", str(ws)])
        self.assertEqual(result.returncode, 0, result.stderr)
        payload = json.loads(
            (ws / "critical_hunt" / "hunt_run.json").read_text(encoding="utf-8")
        )
        steps = [r["step"] for r in payload["results"]]
        self.assertIn("consensus_patch_scan", steps)
        # Order: directly after audit_closeout, directly before queue_summary.
        self.assertEqual(
            steps.index("consensus_patch_scan"),
            steps.index("audit_closeout") + 1,
        )
        self.assertEqual(
            steps.index("queue_summary"),
            steps.index("consensus_patch_scan") + 1,
        )
        # The step records the scanner's actual exit code (advisory: 0 or 1,
        # never aborts the run).
        scan_step = next(
            r for r in payload["results"] if r["step"] == "consensus_patch_scan"
        )
        self.assertIn(scan_step["rc"], (0, 1))
        self.assertIn("stdout", scan_step)
        self.assertIn("stderr", scan_step)

    def test_consensus_patch_scan_advisory_not_in_strict_gate(self):
        """The patch-scan step is advisory: --strict only propagates the
        non-zero exit of steps 3-5 (invariant/program-impact/closeout), never
        the patch-scan step's exit. Guard: even when --strict propagates an
        upstream advisory failure, the patch-scan step still ran and was
        recorded, and its own rc is never the cause of the overall exit code.
        """
        ws = _make_three_row_workspace()
        result = _run(["--workspace", str(ws), "--strict"])
        payload = json.loads(
            (ws / "critical_hunt" / "hunt_run.json").read_text(encoding="utf-8")
        )
        results = payload["results"]
        steps = [r["step"] for r in results]
        self.assertIn("consensus_patch_scan", steps)
        # The strict gate covers exactly the three advisory steps at index 2-4.
        # Confirm the patch-scan step is positioned AFTER that gated range, so
        # its exit code can never propagate as the overall return code.
        self.assertGreater(steps.index("consensus_patch_scan"), 4)
        # Overall rc, if non-zero under strict, must come from one of the three
        # gated steps - not from the advisory patch-scan step.
        if result.returncode not in (0, 2):
            gated_rcs = [results[i]["rc"] for i in (2, 3, 4)]
            self.assertIn(result.returncode, gated_rcs)

    def test_missing_workspace_returns_2(self):
        result = _run(["--workspace", "/nonexistent/path/xyz"])
        self.assertEqual(result.returncode, 2)


if __name__ == "__main__":
    unittest.main()
