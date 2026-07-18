from __future__ import annotations

import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
TOOL_PATH = ROOT / "tools" / "p3-tp-poc-pass-measure.py"
CATALOG_ROOT = ROOT / "obsidian-vault" / "anti-patterns" / "v2"


def _import_tool():
    spec = importlib.util.spec_from_file_location("p3_tp_poc_pass_measure", TOOL_PATH)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


mod = _import_tool()


class P3TpPocPassMeasureTests(unittest.TestCase):
    def _workspace(self) -> Path:
        root = Path(tempfile.mkdtemp(prefix="p3_tp_poc_"))
        (root / ".auditooor").mkdir()
        (root / "source_proofs" / "C1").mkdir(parents=True)
        (root / "source_proofs" / "C2").mkdir(parents=True)
        (root / "poc_execution" / "C1").mkdir(parents=True)
        (root / "poc_execution" / "C2").mkdir(parents=True)
        return root

    def test_explicit_pattern_tp_and_poc_pass_are_counted(self) -> None:
        ws = self._workspace()
        (ws / ".auditooor" / "exploit_queue.source_mined.json").write_text(
            json.dumps({
                "queue": [
                    {
                        "lead_id": "C1",
                        "title": "explicit pattern row",
                        "root_cause_hypothesis": (
                            "semantic anchor: solidity.reentrancy-without-modifier"
                        ),
                    },
                    {
                        "lead_id": "C2",
                        "title": "proved but not P3 attributed",
                    },
                ]
            }),
            encoding="utf-8",
        )
        (ws / "source_proofs" / "C1" / "source_proof.json").write_text(
            json.dumps({
                "candidate_id": "C1",
                "final_verdict": "proved_source_only",
                "notes": "solidity.reentrancy-without-modifier",
            }),
            encoding="utf-8",
        )
        (ws / "source_proofs" / "C2" / "source_proof.json").write_text(
            json.dumps({
                "candidate_id": "C2",
                "final_verdict": "proved_source_only",
            }),
            encoding="utf-8",
        )
        manifest = {
            "candidate_id": "C1",
            "final_result": "proved",
            "impact_assertion": "exploit_impact",
            "commands_attempted": [{"status": "pass", "exit_code": 0}],
        }
        (ws / "poc_execution" / "C1" / "execution_manifest.json").write_text(
            json.dumps(manifest),
            encoding="utf-8",
        )
        manifest["candidate_id"] = "C2"
        (ws / "poc_execution" / "C2" / "execution_manifest.json").write_text(
            json.dumps(manifest),
            encoding="utf-8",
        )

        payload = mod.build_measurement(
            workspace=ws,
            catalog_root=CATALOG_ROOT,
            poc_execution_root=ws / "poc_execution",
            live_target_reports=[],
        )

        self.assertEqual(payload["summary"]["candidate_count"], 2)
        self.assertEqual(payload["summary"]["tp_evidence_count"], 1)
        self.assertEqual(payload["summary"]["poc_pass_count"], 1)
        self.assertEqual(payload["summary"]["tp_poc_pass_rate"], 1.0)
        self.assertEqual(
            payload["summary"]["unknown_unattributed_tp_evidence_count"],
            1,
        )
        rows = {r["candidate_id"]: r for r in payload["candidates"]}
        self.assertEqual(rows["C1"]["tp_status"], "semantic_tp_attributed")
        self.assertEqual(
            rows["C2"]["tp_status"],
            "unknown_unattributed_tp_evidence",
        )

    def test_p5_category_join_does_not_count_as_semantic_tp(self) -> None:
        ws = self._workspace()
        report = ws / "p5.json"
        report.write_text(
            json.dumps({
                "workspace": str(ws.resolve()),
                "entry_points": [
                    {
                        "cluster_id": "go.crypto.race.unsynchronized",
                        "file_line": "x.go:1",
                        "matched_anti_patterns": [
                            "go.concurrent-map-write-no-sync"
                        ],
                    }
                ],
            }),
            encoding="utf-8",
        )

        payload = mod.build_measurement(
            workspace=ws,
            catalog_root=CATALOG_ROOT,
            poc_execution_root=ws / "poc_execution",
            live_target_reports=[report],
        )

        self.assertEqual(payload["summary"]["category_join_only_count"], 1)
        self.assertEqual(payload["summary"]["tp_evidence_count"], 0)
        self.assertIsNone(payload["summary"]["tp_poc_pass_rate"])
        self.assertEqual(
            payload["summary"]["tp_poc_pass_rate_state"],
            "unknown_no_semantic_tp_denominator",
        )

    def test_accepted_sidecar_counts_but_suggested_and_category_rows_do_not(self) -> None:
        ws = self._workspace()
        (ws / ".auditooor" / "p3_semantic_attribution_sidecar.json").write_text(
            json.dumps({
                "schema": "auditooor.p3_semantic_attribution_sidecar.v1",
                "mappings": [
                    {
                        "candidate_id": "C1",
                        "p3_pattern_id": "solidity.reentrancy-without-modifier",
                        "attribution_status": "accepted_by_local_review",
                        "evidence": "local proof maps this candidate to the pattern",
                    },
                    {
                        "candidate_id": "C2",
                        "p3_pattern_id": "go.concurrent-map-write-no-sync",
                        "attribution_status": "accepted_by_local_review",
                        "category_only": True,
                        "evidence": "category join only",
                    },
                    {
                        "candidate_id": "C3",
                        "p3_pattern_id": "go.concurrent-map-write-no-sync",
                        "attribution_status": "suggested",
                        "suggested_only": True,
                        "evidence": "provider suggestion only",
                    },
                ],
            }),
            encoding="utf-8",
        )
        (ws / "source_proofs" / "C1" / "source_proof.json").write_text(
            json.dumps({
                "candidate_id": "C1",
                "final_verdict": "proved_source_only",
            }),
            encoding="utf-8",
        )
        (ws / "source_proofs" / "C2" / "source_proof.json").write_text(
            json.dumps({
                "candidate_id": "C2",
                "final_verdict": "proved_source_only",
            }),
            encoding="utf-8",
        )
        manifest = {
            "candidate_id": "C1",
            "final_result": "proved",
            "impact_assertion": "exploit_impact",
            "commands_attempted": [{"status": "pass", "exit_code": 0}],
        }
        (ws / "poc_execution" / "C1" / "execution_manifest.json").write_text(
            json.dumps(manifest),
            encoding="utf-8",
        )

        payload = mod.build_measurement(
            workspace=ws,
            catalog_root=CATALOG_ROOT,
            poc_execution_root=ws / "poc_execution",
            live_target_reports=[],
        )

        rows = {r["candidate_id"]: r for r in payload["candidates"]}
        self.assertEqual(rows["C1"]["tp_status"], "semantic_tp_attributed")
        self.assertEqual(rows["C2"]["tp_status"], "unknown_unattributed_tp_evidence")
        self.assertEqual(rows["C3"]["tp_status"], "category_join_only_not_semantic_tp")
        self.assertEqual(payload["summary"]["tp_evidence_count"], 1)
        self.assertEqual(payload["summary"]["poc_pass_count"], 1)
        self.assertEqual(payload["summary"]["tp_poc_pass_rate"], 1.0)


if __name__ == "__main__":
    unittest.main()
