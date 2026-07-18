#!/usr/bin/env python3
"""Tests for tools/high-impact-impact-contract-skeletons.py."""
from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
TOOL = ROOT / "tools" / "high-impact-impact-contract-skeletons.py"


def _row(
    rid: str,
    family: str,
    statement: str,
    *,
    status: str = "missing_harness",
    production_path: str = "",
    required_engine: str = "manual",
    severity: str = "High",
) -> dict:
    return {
        "id": rid,
        "scope_asset": "synthetic",
        "invariant_family": family,
        "statement": statement,
        "source_citations": ["docs/test.md"],
        "attacker_capability": "user input",
        "trusted_boundary": "none",
        "oos_boundary": "in scope",
        "production_path": production_path or f"src/{rid.lower()}.rs",
        "required_engine": required_engine,
        "status": status,
        "artifacts": [],
        "owner": "Codex",
        "severity": severity,
    }


def _write_ledger(ws: Path, rows: list[dict]) -> None:
    auditooor_dir = ws / ".auditooor"
    auditooor_dir.mkdir(parents=True, exist_ok=True)
    (auditooor_dir / "invariant_ledger.json").write_text(
        json.dumps(
            {
                "schema_version": "auditooor.invariant_ledger.v1",
                "schema_source": "test",
                "workspace": str(ws),
                "generated_by": "test_high_impact_impact_contract_skeletons",
                "generated_at": "2026-05-02T00:00:00Z",
                "rows": rows,
            },
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )


def _write_impact_contracts(ws: Path, contracts: list[dict]) -> None:
    auditooor_dir = ws / ".auditooor"
    auditooor_dir.mkdir(parents=True, exist_ok=True)
    (auditooor_dir / "impact_contracts.json").write_text(
        json.dumps({"contracts": contracts}, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


class HighImpactImpactContractSkeletonTests(unittest.TestCase):
    def test_generates_fail_closed_skeletons_for_blocked_rows(self) -> None:
        with tempfile.TemporaryDirectory(prefix="hi_contract_skels_") as tmp:
            ws = Path(tmp)
            _write_ledger(
                ws,
                [
                    _row(
                        "BASE-SC-I01",
                        "BASE-SC-PROOF-DOMAIN",
                        "proof domain mismatch must not drain funds",
                        required_engine="forge",
                        production_path="external/contracts/src/AggregateVerifier.sol:12",
                    )
                ],
            )
            proc = subprocess.run(
                [sys.executable, str(TOOL), "--workspace", str(ws), "--print-json"],
                cwd=ROOT,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )
            self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
            payload = json.loads(proc.stdout)
            self.assertEqual(payload["schema_version"], "auditooor.high_impact_impact_contract_skeletons.v1")
            self.assertEqual(payload["processed_rows"], 1)
            self.assertEqual(payload["summary"]["generated_skeletons"], 1)
            self.assertEqual(payload["summary"]["validated_skeletons"], 1)
            row = payload["rows"][0]
            skeleton_path = Path(row["skeleton_path"])
            self.assertTrue(skeleton_path.is_file())
            skeleton = json.loads(skeleton_path.read_text(encoding="utf-8"))
            self.assertEqual(skeleton["status"], "required_not_collected")
            self.assertFalse(skeleton["promotion_allowed"])
            self.assertFalse(skeleton["listed_impact_proven"])
            self.assertEqual(skeleton["selected_impact"], "")
            self.assertEqual(skeleton["evidence_class"], "")
            self.assertEqual(skeleton["oos_traps"], [])
            self.assertIn("selected_impact", skeleton["required_missing_fields"])
            self.assertIn("make impact-contract-check", "\n".join(skeleton["next_commands"]))
            task_md = Path(row["task_md_path"])
            self.assertTrue(task_md.is_file())
            self.assertIn("Manual Follow-Up", task_md.read_text(encoding="utf-8"))

    def test_validate_existing_fails_on_unsafe_skeleton_mutation(self) -> None:
        with tempfile.TemporaryDirectory(prefix="hi_contract_skels_") as tmp:
            ws = Path(tmp)
            _write_ledger(
                ws,
                [
                    _row(
                        "BASE-SC-I01",
                        "BASE-SC-PROOF-DOMAIN",
                        "proof domain mismatch must not drain funds",
                        required_engine="forge",
                    )
                ],
            )
            first = subprocess.run(
                [sys.executable, str(TOOL), "--workspace", str(ws)],
                cwd=ROOT,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )
            self.assertEqual(first.returncode, 0, first.stdout + first.stderr)
            skel = (
                ws
                / ".auditooor"
                / "high_impact_impact_contract_skeletons"
                / "skeletons"
                / "base-sc-i01.json"
            )
            payload = json.loads(skel.read_text(encoding="utf-8"))
            payload["selected_impact"] = "Temporary freezing of user funds"
            payload["promotion_allowed"] = True
            skel.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
            second = subprocess.run(
                [sys.executable, str(TOOL), "--workspace", str(ws), "--validate-existing", "--print-json"],
                cwd=ROOT,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )
            self.assertEqual(second.returncode, 1, second.stdout + second.stderr)
            out = json.loads(second.stdout)
            self.assertEqual(out["summary"]["invalid_skeletons"], 1)
            self.assertIn("selected_impact_must_be_blank", out["rows"][0]["validation_errors"])
            self.assertIn("promotion_allowed_must_be_false", out["rows"][0]["validation_errors"])

    def test_mapped_guardrailed_rows_do_not_emit_skeletons(self) -> None:
        with tempfile.TemporaryDirectory(prefix="hi_contract_skels_") as tmp:
            ws = Path(tmp)
            _write_ledger(
                ws,
                [
                    _row(
                        "BASE-DLT-I01",
                        "BASE-DLT-WITHDRAWALS-ROOT",
                        "withdrawals root divergence must be rejected",
                        required_engine="cargo",
                        production_path="crates/engine/tree/src/tree/mod.rs:88",
                    )
                ],
            )
            _write_impact_contracts(
                ws,
                [
                    {
                        "impact_contract_id": "impact-contract-base-dlt-i01",
                        "candidate_id": "BASE-DLT-I01",
                        "selected_impact": "Temporary freezing of user funds (recoverable within a finalization window)",
                        "severity_tier": "High",
                        "exact_impact_row": True,
                        "listed_impact_proven": True,
                        "evidence_class": "executed_with_manifest",
                        "oos_traps": ["admin-only path"],
                        "stop_condition": "Stop if the negative control is not rejected.",
                    }
                ],
            )
            (ws / "SEVERITY.md").write_text(
                "# Test Severity\n\n"
                "## High-tier listed impacts\n"
                "- Temporary freezing of user funds (recoverable within a finalization window)\n",
                encoding="utf-8",
            )
            proc = subprocess.run(
                [sys.executable, str(TOOL), "--workspace", str(ws), "--print-json"],
                cwd=ROOT,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )
            self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
            payload = json.loads(proc.stdout)
            self.assertEqual(payload["processed_rows"], 0)
            self.assertEqual(payload["summary"]["generated_skeletons"], 0)


if __name__ == "__main__":
    unittest.main()
