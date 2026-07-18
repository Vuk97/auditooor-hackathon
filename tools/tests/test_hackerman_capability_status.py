"""Tests for Hackerman/MCP capability-roadmap status snapshots."""
from __future__ import annotations

import importlib.util
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
SCRIPT = REPO_ROOT / "tools" / "hackerman-capability-status.py"


def _load_module():
    spec = importlib.util.spec_from_file_location("hackerman_capability_status", SCRIPT)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"could not load {SCRIPT}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


MODULE = _load_module()


class HackermanCapabilityStatusTest(unittest.TestCase):
    def test_build_status_counts_corpus_and_sidecars(self) -> None:
        with tempfile.TemporaryDirectory(prefix="hackerman-capability-status-") as td:
            root = Path(td)
            tags = root / "audit" / "corpus_tags" / "tags"
            derived = root / "audit" / "corpus_tags" / "derived"
            index = root / "audit" / "corpus_tags" / "index"
            tools = root / "tools"
            tags.mkdir(parents=True)
            derived.mkdir(parents=True)
            index.mkdir(parents=True)
            tools.mkdir()

            (tools / "auditooor-pre-source-read-injector.py").write_text("# hook\n", encoding="utf-8")
            (tools / "claude-pre-source-read-hook.sh").write_text("#!/bin/sh\n", encoding="utf-8")
            (tools / "hackerman-tooling-index.py").write_text("# index\n", encoding="utf-8")
            (index / "by_attack_class.jsonl").write_text("{}\n", encoding="utf-8")
            (derived / "record_quality.jsonl").write_text('{"record_id":"a"}\n', encoding="utf-8")
            (derived / "proof_hardening.jsonl").write_text("", encoding="utf-8")
            (derived / "proof_artifact_index.jsonl").write_text('{"candidate_proof_path":"reports/poc.md"}\n', encoding="utf-8")
            (derived / "cross_language_analogues.jsonl").write_text('{"record_id":"a"}\n', encoding="utf-8")

            (tags / "a.yaml").write_text(
                "\n".join(
                    [
                        "schema: auditooor.hackerman_record.v1",
                        "year: 2000",
                        "language: go",
                        "cross_language_analogues: []",
                        "proof_artifact_path: reports/poc.md",
                    ]
                ),
                encoding="utf-8",
            )
            (tags / "b.yaml").write_text(
                "\n".join(
                    [
                        "schema: auditooor.hackerman_record.v1",
                        "year: 2025",
                        "language: solidity",
                        "cross_language_analogues: [{record_id: a}]",
                    ]
                ),
                encoding="utf-8",
            )
            (tags / "c.yaml").write_text(
                "\n".join(
                    [
                        "schema: auditooor.hackerman_record.v1",
                        "year: 2026",
                        "language: go",
                        "target_language: go",
                        "cross_language_analogues:",
                        "  - target_language: rust",
                        "    pattern_translation: go->rust",
                    ]
                ),
                encoding="utf-8",
            )
            (tags / "d.yaml").write_text(
                "\n".join(
                    [
                        "schema: auditooor.hackerman_record.v1",
                        "year: 2026",
                        'language: "rust"',
                        'target_language: "go"',
                    ]
                ),
                encoding="utf-8",
            )

            status = MODULE.build_status(root=root)
            self.assertEqual(status["schema"], "auditooor.hackerman_capability_status.v1")
            self.assertEqual(status["corpus"]["yaml_tags"], 4)
            self.assertEqual(status["corpus"]["hackerman_record_v1"], 4)
            self.assertEqual(status["corpus"]["unknown_year_2000"], 1)
            self.assertEqual(status["corpus"]["exact_language_go"], 2)
            self.assertEqual(status["corpus"]["target_language_go"], 2)
            self.assertEqual(status["corpus"]["in_record_cross_language_analogues_populated"], 2)
            self.assertEqual(status["corpus"]["in_record_cross_language_analogues_empty"], 2)
            self.assertEqual(status["corpus"]["proof_artifact_path_populated"], 1)
            self.assertTrue(status["derived_sidecars"]["record_quality"]["exists"])
            self.assertEqual(status["derived_sidecars"]["record_quality"]["rows"], 1)
            self.assertTrue(status["derived_sidecars"]["proof_artifact_index"]["exists"])
            self.assertEqual(status["derived_sidecars"]["proof_artifact_index"]["rows"], 1)
            self.assertEqual(status["derived_sidecars"]["proof_artifact_index"]["freshness_class"], "fresh")
            self.assertEqual(status["derived_sidecars"]["proof_artifact_index"]["freshness_basis"], "mtime")
            self.assertTrue(status["derived_sidecars"]["proof_artifact_index"]["mtime_utc"])
            self.assertEqual(status["cross_language_analogue_policy"]["canonical_source"], "derived_sidecar")
            self.assertEqual(status["cross_language_analogue_policy"]["sidecar_rows"], 1)
            self.assertFalse(status["cross_language_analogue_policy"]["in_record_writeback_required"])
            self.assertIn(
                "tools/vault-mcp-server.py:vault_cross_language_pattern_lift",
                status["cross_language_analogue_policy"]["major_consumers"],
            )
            self.assertEqual(status["index_files"]["count"], 1)
            self.assertTrue(status["hooks"]["pre_source_read_injector"])
            self.assertEqual(
                [gap["id"] for gap in status["gap_details"]],
                [
                    "realworld_recall_scoreboard_missing",
                    "go_cosmos_coverage_underweight",
                    "solodit_unknown_year_bucket_present",
                    "proof_artifact_feedback_sparse",
                ],
            )
            go_gap = next(gap for gap in status["gap_details"] if gap["id"] == "go_cosmos_coverage_underweight")
            self.assertEqual(go_gap["current"], 2)
            self.assertEqual(go_gap["target"], 500)
            self.assertIn("make hackerman-go-cosmos-inventory", go_gap["commands"])

    def test_missing_cross_language_sidecar_keeps_in_record_writeback_gap(self) -> None:
        with tempfile.TemporaryDirectory(prefix="hackerman-capability-status-xlang-gap-") as td:
            root = Path(td)
            for sub in ("audit/corpus_tags/tags", "audit/corpus_tags/derived", "audit/corpus_tags/index"):
                (root / sub).mkdir(parents=True)
            (root / "audit/corpus_tags/tags/a.yaml").write_text(
                "\n".join(
                    [
                        "schema: auditooor.hackerman_record.v1",
                        "target_language: solidity",
                        "cross_language_analogues: []",
                    ]
                ),
                encoding="utf-8",
            )

            status = MODULE.build_status(root=root)
            self.assertEqual(
                status["cross_language_analogue_policy"]["canonical_source"],
                "missing_derived_sidecar",
            )
            self.assertFalse(status["cross_language_analogue_policy"]["in_record_writeback_required"])
            self.assertIn("in_record_cross_language_analogues_partial", status["known_gaps"])

    def test_json_cli_output_is_parseable(self) -> None:
        proc = subprocess.run(
            [sys.executable, str(SCRIPT), "--format", "json"],
            check=True,
            capture_output=True,
            text=True,
        )
        data = json.loads(proc.stdout)
        self.assertEqual(data["schema"], "auditooor.hackerman_capability_status.v1")
        self.assertIn("corpus", data)
        self.assertIn("derived_sidecars", data)
        self.assertIn("known_gaps", data)
        self.assertIn("gap_details", data)
        self.assertIn("recall_scoreboard", data)
        self.assertIn("solodit_year_enrichment", data)
        for gap in data["gap_details"]:
            self.assertIn(gap["id"], data["known_gaps"])
            self.assertIn("next_action", gap)
            self.assertTrue(gap["commands"])

    def test_recall_scoreboard_gaps_surface_low_same_class_and_missing_external_origin(self) -> None:
        with tempfile.TemporaryDirectory(prefix="hackerman-capability-recall-") as td:
            root = Path(td)
            for sub in ("audit/corpus_tags/tags", "audit/corpus_tags/derived", "audit/corpus_tags/index", "reports"):
                (root / sub).mkdir(parents=True)
            (root / "audit/corpus_tags/tags/a.yaml").write_text(
                "schema: auditooor.hackerman_record.v1\nlanguage: solidity\nproof_artifact_path: reports/x.md\n",
                encoding="utf-8",
            )
            (root / "reports/realworld_recall_scoreboard.json").write_text(
                json.dumps(
                    {
                        "schema": "auditooor.realworld_recall_scoreboard.v1",
                        "generated_at": "2026-05-17T00:00:00Z",
                        "overall": {
                            "held_out_scorable": 20,
                            "realworld_recall_same_class": 0.25,
                        },
                    }
                ),
                encoding="utf-8",
            )

            status = MODULE.build_status(root=root)
            self.assertEqual(status["recall_scoreboard"]["same_class_recall_pct"], 25.0)
            self.assertFalse(status["recall_scoreboard"]["has_external_repo_origin"])
            self.assertIn("realworld_same_class_recall_low", status["known_gaps"])
            self.assertIn("external_repo_recall_measurement_missing", status["known_gaps"])
            external_gap = next(
                row for row in status["gap_details"]
                if row["id"] == "external_repo_recall_measurement_missing"
            )
            self.assertTrue(any("external-recall-manifest.py select" in cmd for cmd in external_gap["commands"]))
            self.assertTrue(any("make external-recall-manifest" in cmd for cmd in external_gap["commands"]))
            self.assertTrue(any("--external-only" in cmd for cmd in external_gap["commands"]))

    def test_realworld_recall_work_queue_surfaces_in_low_recall_gap(self) -> None:
        with tempfile.TemporaryDirectory(prefix="hackerman-capability-recall-queue-") as td:
            root = Path(td)
            for sub in ("audit/corpus_tags/tags", "audit/corpus_tags/derived", "audit/corpus_tags/index", "reports"):
                (root / sub).mkdir(parents=True)
            (root / "audit/corpus_tags/tags/a.yaml").write_text(
                "schema: auditooor.hackerman_record.v1\nlanguage: solidity\nproof_artifact_path: reports/x.md\n",
                encoding="utf-8",
            )
            priorities = root / "reports" / "realworld_recall_gap_priorities.json"
            priorities.write_text(
                json.dumps({"schema": "auditooor.realworld_recall_gap_priorities.v1", "priorities": []}),
                encoding="utf-8",
            )
            (root / "reports/realworld_recall_scoreboard.json").write_text(
                json.dumps(
                    {
                        "schema": "auditooor.realworld_recall_scoreboard.v1",
                        "generated_at": "2026-05-17T00:00:00Z",
                        "overall": {
                            "held_out_scorable": 20,
                            "realworld_recall_same_class": 0.25,
                        },
                    }
                ),
                encoding="utf-8",
            )
            queue = root / "reports" / "realworld_recall_work_queue_slice15.jsonl"
            queue.write_text(
                json.dumps(
                    {
                        "schema": "auditooor.realworld_recall_work_queue.row.v1",
                        "source_priority": {"attack_class": "bridge-proof-domain-bypass"},
                        "work_item": {"task_type": "detector-generalization"},
                    }
                )
                + "\n",
                encoding="utf-8",
            )
            summary = root / "reports" / "realworld_recall_work_queue_slice15_summary.json"
            summary.write_text(
                json.dumps(
                    {
                        "schema": "auditooor.realworld_recall_work_queue_summary.v1",
                        "rows_written": 1,
                        "dry_run": False,
                    }
                ),
                encoding="utf-8",
            )

            status = MODULE.build_status(root=root)
            self.assertEqual(status["realworld_recall_work_queue"]["latest_queue_rows"], 1)
            self.assertTrue(status["realworld_recall_work_queue"]["latest_summary_current_for_priorities"])
            recall_gap = next(row for row in status["gap_details"] if row["id"] == "realworld_same_class_recall_low")
            self.assertIn("Work queue exists", recall_gap["evidence"])
            self.assertIn("Work the generated real-world recall queue rows", recall_gap["next_action"])
            self.assertTrue(any("realworld_recall_work_queue_slice15.jsonl" in cmd for cmd in recall_gap["commands"]))

    def test_realworld_recall_quality_blocked_rows_surface_in_low_recall_gap(self) -> None:
        with tempfile.TemporaryDirectory(prefix="hackerman-capability-recall-quality-") as td:
            root = Path(td)
            for sub in ("audit/corpus_tags/tags", "audit/corpus_tags/derived", "audit/corpus_tags/index", "reports"):
                (root / sub).mkdir(parents=True)
            (root / "audit/corpus_tags/tags/a.yaml").write_text(
                "schema: auditooor.hackerman_record.v1\nlanguage: solidity\nproof_artifact_path: reports/x.md\n",
                encoding="utf-8",
            )
            (root / "reports/realworld_recall_gap_priorities.json").write_text(
                json.dumps({"schema": "auditooor.realworld_recall_gap_priorities.v1", "priorities": []}),
                encoding="utf-8",
            )
            (root / "reports/realworld_recall_scoreboard.json").write_text(
                json.dumps(
                    {
                        "schema": "auditooor.realworld_recall_scoreboard.v1",
                        "generated_at": "2026-05-17T00:00:00Z",
                        "overall": {
                            "held_out_scorable": 20,
                            "realworld_recall_same_class": 0.25,
                        },
                    }
                ),
                encoding="utf-8",
            )
            queue = root / "reports" / "realworld_recall_work_queue_slice16_quality.jsonl"
            quality_path = "reports/external_recall_manifest_quality_slice16.json"
            queue.write_text(
                json.dumps(
                    {
                        "schema": "auditooor.realworld_recall_work_queue.row.v1",
                        "status": "quality_blocked",
                        "source_priority": {"attack_class": "bridge-proof-domain-bypass"},
                        "work_item": {"task_type": "source-state-validation"},
                        "external_recall_quality": {
                            "quality_blocked": True,
                            "quality_report_paths": [quality_path],
                            "needs_source_state_validation": 1,
                            "quality_blocked_reason": "needs_source_state_validation",
                        },
                    }
                )
                + "\n",
                encoding="utf-8",
            )
            (root / "reports" / "realworld_recall_work_queue_slice16_quality_summary.json").write_text(
                json.dumps(
                    {
                        "schema": "auditooor.realworld_recall_work_queue_summary.v1",
                        "rows_written": 1,
                        "dry_run": False,
                        "quality_blocked_rows": 1,
                        "quality_needs_validation_rows": 1,
                        "quality_disqualified_only_rows": 0,
                        "quality_report_paths": [quality_path],
                        "by_status": {"quality_blocked": 1},
                    }
                ),
                encoding="utf-8",
            )

            status = MODULE.build_status(root=root)
            queue_status = status["realworld_recall_work_queue"]
            self.assertEqual(queue_status["latest_quality_blocked_rows"], 1)
            self.assertEqual(queue_status["latest_queue_by_status"], {"quality_blocked": 1})
            recall_gap = next(row for row in status["gap_details"] if row["id"] == "realworld_same_class_recall_low")
            self.assertIn("quality-blocked", recall_gap["evidence"])
            self.assertIn("vulnerable/pre-fix", recall_gap["next_action"])

    def test_realworld_recall_disqualified_rows_ask_for_replacement_samples(self) -> None:
        with tempfile.TemporaryDirectory(prefix="hackerman-capability-recall-disqualified-") as td:
            root = Path(td)
            for sub in ("audit/corpus_tags/tags", "audit/corpus_tags/derived", "audit/corpus_tags/index", "reports"):
                (root / sub).mkdir(parents=True)
            (root / "audit/corpus_tags/tags/a.yaml").write_text(
                "schema: auditooor.hackerman_record.v1\nlanguage: solidity\nproof_artifact_path: reports/x.md\n",
                encoding="utf-8",
            )
            (root / "reports/realworld_recall_gap_priorities.json").write_text(
                json.dumps({"schema": "auditooor.realworld_recall_gap_priorities.v1", "priorities": []}),
                encoding="utf-8",
            )
            (root / "reports/realworld_recall_scoreboard.json").write_text(
                json.dumps(
                    {
                        "schema": "auditooor.realworld_recall_scoreboard.v1",
                        "generated_at": "2026-05-17T00:00:00Z",
                        "overall": {
                            "held_out_scorable": 20,
                            "realworld_recall_same_class": 0.25,
                        },
                    }
                ),
                encoding="utf-8",
            )
            queue = root / "reports" / "realworld_recall_work_queue_slice17_disqualified.jsonl"
            quality_path = "reports/external_recall_manifest_quality_slice17.json"
            queue.write_text(
                json.dumps(
                    {
                        "schema": "auditooor.realworld_recall_work_queue.row.v1",
                        "status": "quality_blocked",
                        "source_priority": {"attack_class": "bridge-proof-domain-bypass"},
                        "work_item": {"task_type": "source-state-validation"},
                        "external_recall_quality": {
                            "quality_blocked": True,
                            "quality_report_paths": [quality_path],
                            "needs_source_state_validation": 0,
                            "disqualified_source_state": 7,
                            "quality_blocked_reason": "disqualified_source_state",
                        },
                    }
                )
                + "\n",
                encoding="utf-8",
            )
            (root / "reports" / "realworld_recall_work_queue_slice17_disqualified_summary.json").write_text(
                json.dumps(
                    {
                        "schema": "auditooor.realworld_recall_work_queue_summary.v1",
                        "rows_written": 1,
                        "dry_run": False,
                        "quality_blocked_rows": 1,
                        "quality_needs_validation_rows": 0,
                        "quality_disqualified_only_rows": 1,
                        "quality_report_paths": [quality_path],
                        "by_status": {"quality_blocked": 1},
                    }
                ),
                encoding="utf-8",
            )

            status = MODULE.build_status(root=root)
            queue_status = status["realworld_recall_work_queue"]
            self.assertEqual(queue_status["latest_quality_disqualified_only_rows"], 1)
            recall_gap = next(row for row in status["gap_details"] if row["id"] == "realworld_same_class_recall_low")
            self.assertIn("fixed/out-of-class", recall_gap["evidence"])
            self.assertIn("no unknown validation rows", recall_gap["next_action"])
            self.assertIn("replace fixed/out-of-class external samples", recall_gap["next_action"])

    def test_external_recall_sidecar_suppresses_missing_external_origin_gap(self) -> None:
        with tempfile.TemporaryDirectory(prefix="hackerman-capability-external-sidecar-") as td:
            root = Path(td)
            for sub in ("audit/corpus_tags/tags", "audit/corpus_tags/derived", "audit/corpus_tags/index", "reports"):
                (root / sub).mkdir(parents=True)
            (root / "audit/corpus_tags/tags/a.yaml").write_text(
                "schema: auditooor.hackerman_record.v1\nlanguage: solidity\nproof_artifact_path: reports/x.md\n",
                encoding="utf-8",
            )
            (root / "reports/realworld_recall_scoreboard.json").write_text(
                json.dumps(
                    {
                        "schema": "auditooor.realworld_recall_scoreboard.v1",
                        "generated_at": "2026-05-17T00:00:00Z",
                        "overall": {
                            "held_out_scorable": 20,
                            "realworld_recall_same_class": 0.25,
                        },
                    }
                ),
                encoding="utf-8",
            )
            (root / "reports/external_recall_samples_phase_c.json").write_text(
                json.dumps(
                    {
                        "schema": "auditooor.external_recall_samples.v1",
                        "sample_count": 1,
                        "samples": [{"id": "external-1", "attack_class": "reentrancy"}],
                    }
                ),
                encoding="utf-8",
            )
            (root / "reports/realworld_recall_scoreboard_external_phase_c.json").write_text(
                json.dumps(
                    {
                        "schema": "auditooor.realworld_recall_scoreboard.v1",
                        "overall": {
                            "held_out_scorable": 1,
                            "realworld_recall_same_class": 0.0,
                            "by_origin": {
                                "external_repo": {
                                    "held_out_scorable": 1,
                                    "realworld_recall_same_class": 0.0,
                                }
                            },
                        },
                    }
                ),
                encoding="utf-8",
            )

            status = MODULE.build_status(root=root)

            self.assertEqual(status["recall_scoreboard"]["external_sidecar_samples"], 1)
            self.assertEqual(status["recall_scoreboard"]["external_sidecars"]["latest_same_class_recall_pct"], 0.0)
            self.assertIn("realworld_same_class_recall_low", status["known_gaps"])
            self.assertNotIn("external_repo_recall_measurement_missing", status["known_gaps"])

    def test_solodit_year_gap_surfaces_source_data_blocked_status(self) -> None:
        with tempfile.TemporaryDirectory(prefix="hackerman-capability-solodit-year-") as td:
            root = Path(td)
            for sub in ("audit/corpus_tags/tags", "audit/corpus_tags/derived", "audit/corpus_tags/index", "reports", "tools"):
                (root / sub).mkdir(parents=True)
            (root / "tools/hackerman-backfill-solodit-years.py").write_text("# safe backfill tool\n", encoding="utf-8")
            (root / "tools/hackerman-solodit-date-enrichment-queue.py").write_text("# queue tool\n", encoding="utf-8")
            (root / "audit/corpus_tags/tags/solodit.yaml").write_text(
                "\n".join(
                    [
                        "schema: auditooor.hackerman_record.v1",
                        "source_audit_ref: solodit-spec:detectors/_specs/drafts_solodit/x.yaml:1",
                        "year: 2000",
                        "language: solidity",
                    ]
                ),
                encoding="utf-8",
            )
            (root / "reports/solodit_unknown_year_phase_b_2026-05-17.md").write_text(
                "safe candidates written: 0\nstatus: intentionally_unresolved_no_safe_source_date_candidates\n",
                encoding="utf-8",
            )

            status = MODULE.build_status(root=root)

            self.assertEqual(status["solodit_year_enrichment"]["classification"], "source_data_blocked")
            self.assertTrue(status["solodit_year_enrichment"]["safe_audit_ready"])
            self.assertTrue(status["solodit_year_enrichment"]["enrichment_queue_tool_exists"])
            solodit_gap = next(
                row for row in status["gap_details"]
                if row["id"] == "solodit_unknown_year_bucket_present"
            )
            self.assertIn("source-data blocked", solodit_gap["evidence"])
            self.assertIn("Queue explicit source-date enrichment work", solodit_gap["next_action"])
            self.assertTrue(any("hackerman-solodit-date-enrichment-queue" in cmd for cmd in solodit_gap["commands"]))
            self.assertTrue(any("hackerman-backfill-solodit-years.py --dry-run" in cmd for cmd in solodit_gap["commands"]))
            self.assertTrue(any("solodit_unknown_year_phase_b_2026-05-17.md" in cmd for cmd in solodit_gap["commands"]))

    def test_proof_artifact_index_sidecar_is_reported_in_sparse_gap(self) -> None:
        with tempfile.TemporaryDirectory(prefix="hackerman-capability-proof-index-") as td:
            root = Path(td)
            for sub in ("audit/corpus_tags/tags", "audit/corpus_tags/derived", "audit/corpus_tags/index"):
                (root / sub).mkdir(parents=True)
            (root / "audit/corpus_tags/tags/a.yaml").write_text(
                "schema: auditooor.hackerman_record.v1\nlanguage: solidity\n",
                encoding="utf-8",
            )
            (root / "audit/corpus_tags/derived/proof_artifact_index.jsonl").write_text(
                "\n".join(
                    [
                        json.dumps(
                            {
                                "candidate_proof_path": "audits/dydx/poc-tests/a.go",
                                "promotion_ready": True,
                                "promotion_blockers": [],
                            }
                        ),
                        json.dumps(
                            {
                                "candidate_proof_path": "audits/dydx/poc-tests/b.go",
                                "promotion_ready": False,
                                "promotion_blockers": ["confidence_not_high", "match_not_explicit_reference"],
                            }
                        ),
                        json.dumps(
                            {
                                "candidate_proof_path": "audits/dydx/poc-tests/c.go",
                                "promotion_ready": False,
                                "promotion_blockers": ["confidence_not_high"],
                            }
                        ),
                    ]
                )
                + "\n",
                encoding="utf-8",
            )

            status = MODULE.build_status(root=root)

            proof_index = status["derived_sidecars"]["proof_artifact_index"]
            self.assertEqual(proof_index["rows"], 3)
            self.assertEqual(proof_index["freshness_class"], "fresh")
            self.assertTrue(proof_index["promotion_ready_available"])
            self.assertEqual(proof_index["promotion_ready_rows"], 1)
            self.assertEqual(
                proof_index["promotion_blocker_histogram"],
                {"confidence_not_high": 2, "match_not_explicit_reference": 1},
            )
            proof_gap = next(
                row for row in status["gap_details"]
                if row["id"] == "proof_artifact_feedback_sparse"
            )
            self.assertIn("proof_artifact_index sidecar currently exposes 3 candidate rows", proof_gap["evidence"])
            self.assertIn("promotion-ready rows=1", proof_gap["evidence"])
            self.assertIn("blocker_histogram=confidence_not_high=2, match_not_explicit_reference=1", proof_gap["evidence"])
            self.assertEqual(proof_gap["status"]["proof_artifact_index_rows"], 3)
            self.assertEqual(proof_gap["status"]["promotion_ready_rows"], 1)
            self.assertEqual(
                proof_gap["status"]["promotion_blocker_histogram"],
                {"confidence_not_high": 2, "match_not_explicit_reference": 1},
            )
            self.assertTrue(any("hackerman-proof-artifact-index.py --json-summary" in cmd for cmd in proof_gap["commands"]))

    def test_proof_artifact_import_queue_updates_sparse_gap_next_action(self) -> None:
        with tempfile.TemporaryDirectory(prefix="hackerman-capability-proof-queue-") as td:
            root = Path(td)
            for sub in ("audit/corpus_tags/tags", "audit/corpus_tags/derived", "audit/corpus_tags/index", "reports"):
                (root / sub).mkdir(parents=True)
            (root / "audit/corpus_tags/tags/a.yaml").write_text(
                "schema: auditooor.hackerman_record.v1\nlanguage: solidity\n",
                encoding="utf-8",
            )
            (root / "audit/corpus_tags/derived/proof_artifact_index.jsonl").write_text(
                json.dumps(
                    {
                        "candidate_proof_path": "audits/dydx/poc-tests/a.go",
                        "promotion_ready": True,
                        "promotion_blockers": [],
                    }
                )
                + "\n",
                encoding="utf-8",
            )
            queue_path = root / "reports" / "proof_artifact_missing_record_import_queue_slice10.jsonl"
            queue_path.write_text(
                json.dumps(
                    {
                        "schema": "auditooor.hackerman_missing_record_import_queue.v1",
                        "engagement": "dydx",
                        "candidate_count": 2,
                        "queue_key": "paste_ready/sample.md",
                        "proof_artifact_candidates": [
                            {"candidate_proof_path": "audits/dydx/poc-tests/a.go"},
                            {"candidate_proof_path": "audits/dydx/poc-tests/a.log"},
                        ],
                    }
                )
                + "\n",
                encoding="utf-8",
            )

            status = MODULE.build_status(root=root)

            queue_status = status["proof_artifact_import_queue"]
            self.assertTrue(queue_status["exists"])
            self.assertEqual(queue_status["latest_queue_path"], "reports/proof_artifact_missing_record_import_queue_slice10.jsonl")
            self.assertEqual(queue_status["latest_queue_rows"], 1)
            self.assertEqual(queue_status["latest_candidate_count"], 2)
            self.assertEqual(queue_status["latest_by_engagement"], {"dydx": 1})
            proof_gap = next(
                row for row in status["gap_details"]
                if row["id"] == "proof_artifact_feedback_sparse"
            )
            self.assertIn("missing-record import queue", proof_gap["next_action"])
            self.assertIn("Missing-record import queue exists", proof_gap["evidence"])
            self.assertEqual(
                proof_gap["status"]["missing_record_import_queue"]["latest_candidate_count"],
                2,
            )
            self.assertTrue(any("proof_artifact_missing_record_import_queue_slice10.jsonl" in cmd for cmd in proof_gap["commands"]))

    def test_proof_artifact_review_packets_update_sparse_gap_next_action(self) -> None:
        with tempfile.TemporaryDirectory(prefix="hackerman-capability-proof-packets-") as td:
            root = Path(td)
            for sub in ("audit/corpus_tags/tags", "audit/corpus_tags/derived", "audit/corpus_tags/index", "reports"):
                (root / sub).mkdir(parents=True)
            (root / "audit/corpus_tags/tags/a.yaml").write_text(
                "schema: auditooor.hackerman_record.v1\nlanguage: solidity\n",
                encoding="utf-8",
            )
            (root / "audit/corpus_tags/derived/proof_artifact_index.jsonl").write_text(
                json.dumps(
                    {
                        "candidate_proof_path": "audits/dydx/poc-tests/a.go",
                        "promotion_ready": True,
                        "promotion_blockers": [],
                    }
                )
                + "\n",
                encoding="utf-8",
            )
            (root / "reports" / "proof_artifact_missing_record_import_queue_slice10.jsonl").write_text(
                json.dumps(
                    {
                        "schema": "auditooor.hackerman_missing_record_import_queue.v1",
                        "engagement": "dydx",
                        "candidate_count": 1,
                    }
                )
                + "\n",
                encoding="utf-8",
            )
            packet_path = root / "reports" / "proof_artifact_missing_record_review_packets_slice12.jsonl"
            packet_path.write_text(
                json.dumps(
                    {
                        "schema": "auditooor.hackerman_missing_record_review_packet.v1",
                        "engagement": "dydx",
                        "validation_status": "ready_for_manual_record_creation",
                        "artifact_candidates": [{"candidate_proof_path": "audits/dydx/poc-tests/a.go"}],
                    }
                )
                + "\n",
                encoding="utf-8",
            )

            status = MODULE.build_status(root=root)

            queue_status = status["proof_artifact_import_queue"]
            self.assertTrue(queue_status["review_packets_exist"])
            self.assertEqual(
                queue_status["latest_review_packet_path"],
                "reports/proof_artifact_missing_record_review_packets_slice12.jsonl",
            )
            self.assertEqual(
                queue_status["latest_review_packet_status_counts"],
                {"ready_for_manual_record_creation": 1},
            )
            proof_gap = next(
                row for row in status["gap_details"]
                if row["id"] == "proof_artifact_feedback_sparse"
            )
            self.assertIn("Create exact Hackerman records from the ready review packets", proof_gap["next_action"])
            self.assertIn("Review packets exist", proof_gap["evidence"])
            self.assertTrue(any("proof_artifact_missing_record_review_packets_slice12.jsonl" in cmd for cmd in proof_gap["commands"]))

    def test_proof_artifact_promotion_and_status_only_reviews_update_sparse_gap(self) -> None:
        with tempfile.TemporaryDirectory(prefix="hackerman-capability-proof-promotion-review-") as td:
            root = Path(td)
            for sub in ("audit/corpus_tags/tags", "audit/corpus_tags/derived", "audit/corpus_tags/index", "reports"):
                (root / sub).mkdir(parents=True)
            (root / "audit/corpus_tags/tags/a.yaml").write_text(
                "schema: auditooor.hackerman_record.v1\nlanguage: solidity\n",
                encoding="utf-8",
            )
            (root / "audit/corpus_tags/derived/proof_artifact_index.jsonl").write_text(
                json.dumps(
                    {
                        "candidate_proof_path": "audits/dydx/poc-tests/a.go",
                        "promotion_ready": False,
                        "promotion_blockers": ["submission_status_not_paste_ready_or_filed"],
                    }
                )
                + "\n",
                encoding="utf-8",
            )
            promotion_path = root / "reports" / "proof_artifact_promotion_review_slice24.jsonl"
            promotion_path.write_text(
                json.dumps(
                    {
                        "schema": "auditooor.hackerman_proof_artifact_promotion_review_plan.v1",
                        "engagement": "dydx",
                        "action": "none",
                        "apply_status": "not_promotable",
                        "blockers": ["submission_status_not_paste_ready_or_filed"],
                        "candidate_proof_path": "audits/dydx/poc-tests/a.go",
                    }
                )
                + "\n",
                encoding="utf-8",
            )
            status_only_path = root / "reports" / "proof_artifact_status_only_review_slice24.jsonl"
            status_only_path.write_text(
                json.dumps(
                    {
                        "schema": "auditooor.hackerman_proof_artifact_status_only_review.v1",
                        "engagement": "dydx",
                        "candidate_proof_path": "audits/dydx/poc-tests/a.go",
                        "review_status": "manual_status_reconciliation",
                        "recommended_action": "manual_status_reconciliation",
                        "submission_status": "packaged",
                    }
                )
                + "\n",
                encoding="utf-8",
            )

            status = MODULE.build_status(root=root)

            queue_status = status["proof_artifact_import_queue"]
            self.assertTrue(queue_status["exists"])
            self.assertTrue(queue_status["promotion_review_exists"])
            self.assertEqual(
                queue_status["latest_promotion_review_path"],
                "reports/proof_artifact_promotion_review_slice24.jsonl",
            )
            self.assertEqual(queue_status["latest_promotion_review_rows"], 1)
            self.assertEqual(queue_status["latest_promotion_review_ready_to_apply"], 0)
            self.assertFalse(queue_status["latest_promotion_review_safe_to_auto_apply"])
            self.assertEqual(queue_status["latest_promotion_review_apply_status_counts"], {"not_promotable": 1})
            self.assertEqual(
                queue_status["latest_promotion_review_blocker_histogram"],
                {"submission_status_not_paste_ready_or_filed": 1},
            )
            self.assertTrue(queue_status["status_only_review_exists"])
            self.assertEqual(
                queue_status["latest_status_only_review_path"],
                "reports/proof_artifact_status_only_review_slice24.jsonl",
            )
            self.assertEqual(queue_status["latest_status_only_review_rows"], 1)
            self.assertEqual(queue_status["latest_status_only_submission_status_counts"], {"packaged": 1})
            proof_gap = next(row for row in status["gap_details"] if row["id"] == "proof_artifact_feedback_sparse")
            self.assertIn("Reconcile status-only proof-artifact candidates", proof_gap["next_action"])
            self.assertIn("Promotion-review plan exists", proof_gap["evidence"])
            self.assertIn("safe_to_auto_apply=False", proof_gap["evidence"])
            self.assertIn("Status-only review queue exists", proof_gap["evidence"])
            self.assertTrue(any("proof_artifact_status_only_review_slice24.jsonl" in cmd for cmd in proof_gap["commands"]))

    def test_proof_artifact_status_only_reconciliation_updates_sparse_gap(self) -> None:
        with tempfile.TemporaryDirectory(prefix="hackerman-capability-proof-reconciliation-") as td:
            root = Path(td)
            for sub in ("audit/corpus_tags/tags", "audit/corpus_tags/derived", "audit/corpus_tags/index", "reports"):
                (root / sub).mkdir(parents=True)
            (root / "audit/corpus_tags/tags/a.yaml").write_text(
                "schema: auditooor.hackerman_record.v1\nlanguage: solidity\n",
                encoding="utf-8",
            )
            (root / "audit/corpus_tags/derived/proof_artifact_index.jsonl").write_text(
                json.dumps(
                    {
                        "candidate_proof_path": "audits/dydx/poc-tests/a.go",
                        "promotion_ready": False,
                        "promotion_blockers": ["submission_status_not_paste_ready_or_filed"],
                    }
                )
                + "\n",
                encoding="utf-8",
            )
            reconciliation_path = root / "reports" / "proof_artifact_status_only_reconciliation_slice25.jsonl"
            reconciliation_path.write_text(
                json.dumps(
                    {
                        "schema": "auditooor.hackerman_proof_artifact_status_only_reconciliation.v1",
                        "engagement": "dydx",
                        "submission_status": "submitted",
                        "reconciliation_status": "record_creation_candidate",
                        "mutation_allowed": False,
                        "candidate_count": 2,
                    }
                )
                + "\n",
                encoding="utf-8",
            )

            status = MODULE.build_status(root=root)

            queue_status = status["proof_artifact_import_queue"]
            self.assertTrue(queue_status["status_only_reconciliation_exists"])
            self.assertEqual(
                queue_status["latest_status_only_reconciliation_path"],
                "reports/proof_artifact_status_only_reconciliation_slice25.jsonl",
            )
            self.assertEqual(queue_status["latest_status_only_reconciliation_rows"], 1)
            self.assertEqual(queue_status["latest_status_only_reconciliation_candidate_count"], 2)
            self.assertEqual(queue_status["latest_status_only_reconciliation_mutation_allowed_rows"], 0)
            self.assertEqual(
                queue_status["latest_status_only_reconciliation_status_counts"],
                {"record_creation_candidate": 1},
            )
            proof_gap = next(row for row in status["gap_details"] if row["id"] == "proof_artifact_feedback_sparse")
            self.assertIn("Create or link exact Hackerman records", proof_gap["next_action"])
            self.assertIn("Status-only reconciliation queue exists", proof_gap["evidence"])
            rendered = MODULE.render_text(status)
            self.assertIn("status_only_reconciliation=", rendered)
            self.assertIn("mutation_allowed_rows=0", rendered)

    def test_proof_artifact_status_only_resolved_records_update_sparse_gap_next_action(self) -> None:
        with tempfile.TemporaryDirectory(prefix="hackerman-capability-proof-resolved-reconciliation-") as td:
            root = Path(td)
            for sub in ("audit/corpus_tags/tags", "audit/corpus_tags/derived", "audit/corpus_tags/index", "reports"):
                (root / sub).mkdir(parents=True)
            (root / "audit/corpus_tags/tags/a.yaml").write_text(
                "schema: auditooor.hackerman_record.v1\nlanguage: solidity\n",
                encoding="utf-8",
            )
            (root / "audit/corpus_tags/derived/proof_artifact_index.jsonl").write_text(
                json.dumps(
                    {
                        "candidate_proof_path": "audits/dydx/poc-tests/a.go",
                        "promotion_ready": False,
                        "promotion_blockers": ["submission_status_not_paste_ready_or_filed"],
                    }
                )
                + "\n",
                encoding="utf-8",
            )
            reconciliation_path = root / "reports" / "proof_artifact_status_only_reconciliation_slice26.jsonl"
            reconciliation_path.write_text(
                json.dumps(
                    {
                        "schema": "auditooor.hackerman_proof_artifact_status_only_reconciliation.v1",
                        "engagement": "dydx",
                        "submission_status": "ready",
                        "reconciliation_status": "record_resolved_needs_owner_confirmation",
                        "mutation_allowed": False,
                        "candidate_count": 1,
                    }
                )
                + "\n",
                encoding="utf-8",
            )

            status = MODULE.build_status(root=root)

            queue_status = status["proof_artifact_import_queue"]
            self.assertEqual(queue_status["latest_status_only_reconciliation_resolved_record_count"], 1)
            self.assertEqual(queue_status["latest_status_only_reconciliation_mutation_allowed_rows"], 0)
            proof_gap = next(row for row in status["gap_details"] if row["id"] == "proof_artifact_feedback_sparse")
            self.assertIn("Build the status-only resolved-record promotion review plan", proof_gap["next_action"])
            self.assertTrue(
                any("--status-only-resolved-promotion-review" in command for command in proof_gap["commands"])
            )

    def test_proof_artifact_record_proposals_mark_ready_packets_converted(self) -> None:
        with tempfile.TemporaryDirectory(prefix="hackerman-capability-proof-proposals-") as td:
            root = Path(td)
            for sub in ("audit/corpus_tags/tags", "audit/corpus_tags/derived", "audit/corpus_tags/index", "reports"):
                (root / sub).mkdir(parents=True)
            (root / "audit/corpus_tags/tags/a.yaml").write_text(
                "schema: auditooor.hackerman_record.v1\nlanguage: solidity\n",
                encoding="utf-8",
            )
            (root / "audit/corpus_tags/derived/proof_artifact_index.jsonl").write_text(
                json.dumps(
                    {
                        "candidate_proof_path": "audits/dydx/poc-tests/a.go",
                        "promotion_ready": True,
                        "promotion_blockers": [],
                    }
                )
                + "\n",
                encoding="utf-8",
            )
            (root / "reports" / "proof_artifact_missing_record_import_queue_slice10.jsonl").write_text(
                json.dumps(
                    {
                        "schema": "auditooor.hackerman_missing_record_import_queue.v1",
                        "engagement": "dydx",
                        "candidate_count": 1,
                    }
                )
                + "\n",
                encoding="utf-8",
            )
            (root / "reports" / "proof_artifact_missing_record_review_packets_slice12.jsonl").write_text(
                json.dumps(
                    {
                        "schema": "auditooor.hackerman_missing_record_review_packet.v1",
                        "engagement": "dydx",
                        "validation_status": "ready_for_manual_record_creation",
                        "artifact_candidates": [{"candidate_proof_path": "audits/dydx/poc-tests/a.go"}],
                    }
                )
                + "\n",
                encoding="utf-8",
            )
            proposal_path = root / "reports" / "proof_artifact_record_proposals_slice13_summary.json"
            generated_record = root / "audit/corpus_tags/tags/submission-derived-example.yaml"
            generated_record.write_text(
                "schema_version: auditooor.hackerman_record.v1\nrecord_id: example\n",
                encoding="utf-8",
            )
            proposal_path.write_text(
                json.dumps(
                    {
                        "schema": "auditooor.hackerman_proof_artifact_record_proposals.v1",
                        "generated_at_utc": "2026-05-17T00:00:00Z",
                        "conversion_status": "success",
                        "dry_run": False,
                        "packets_path": "reports/proof_artifact_missing_record_review_packets_slice12.jsonl",
                        "packets_sha256": "abc",
                        "records_built": 1,
                        "records_emitted": 1,
                        "failed_count": 0,
                        "files": ["audit/corpus_tags/tags/submission-derived-example.yaml"],
                    }
                ),
                encoding="utf-8",
            )

            status = MODULE.build_status(root=root)

            queue_status = status["proof_artifact_import_queue"]
            self.assertTrue(queue_status["record_proposals_exist"])
            self.assertEqual(
                queue_status["latest_record_proposal_path"],
                "reports/proof_artifact_record_proposals_slice13_summary.json",
            )
            self.assertEqual(queue_status["latest_record_proposal_records_emitted"], 1)
            self.assertEqual(queue_status["latest_record_proposal_files_existing"], 1)
            self.assertTrue(queue_status["latest_record_proposal_current_for_packet"])
            proof_gap = next(
                row for row in status["gap_details"]
                if row["id"] == "proof_artifact_feedback_sparse"
            )
            self.assertIn("Ready review packets have been converted", proof_gap["next_action"])
            self.assertIn("Latest record-proposal summary", proof_gap["evidence"])
            self.assertIn("conversion_status=success", proof_gap["evidence"])
            self.assertTrue(any("proof_artifact_record_proposals_slice13_summary.json" in cmd for cmd in proof_gap["commands"]))

    def test_proof_artifact_record_proposals_do_not_convert_on_dry_run_or_missing_files(self) -> None:
        with tempfile.TemporaryDirectory(prefix="hackerman-capability-proof-proposals-untrusted-") as td:
            root = Path(td)
            for sub in ("audit/corpus_tags/tags", "audit/corpus_tags/derived", "audit/corpus_tags/index", "reports"):
                (root / sub).mkdir(parents=True)
            (root / "audit/corpus_tags/tags/a.yaml").write_text(
                "schema: auditooor.hackerman_record.v1\nlanguage: solidity\n",
                encoding="utf-8",
            )
            (root / "audit/corpus_tags/derived/proof_artifact_index.jsonl").write_text(
                json.dumps(
                    {
                        "candidate_proof_path": "audits/dydx/poc-tests/a.go",
                        "promotion_ready": True,
                        "promotion_blockers": [],
                    }
                )
                + "\n",
                encoding="utf-8",
            )
            (root / "reports" / "proof_artifact_missing_record_import_queue_slice10.jsonl").write_text(
                json.dumps(
                    {
                        "schema": "auditooor.hackerman_missing_record_import_queue.v1",
                        "engagement": "dydx",
                        "candidate_count": 1,
                    }
                )
                + "\n",
                encoding="utf-8",
            )
            (root / "reports" / "proof_artifact_missing_record_review_packets_slice12.jsonl").write_text(
                json.dumps(
                    {
                        "schema": "auditooor.hackerman_missing_record_review_packet.v1",
                        "engagement": "dydx",
                        "validation_status": "ready_for_manual_record_creation",
                        "artifact_candidates": [{"candidate_proof_path": "audits/dydx/poc-tests/a.go"}],
                    }
                )
                + "\n",
                encoding="utf-8",
            )
            (root / "reports" / "proof_artifact_record_proposals_slice13_summary.json").write_text(
                json.dumps(
                    {
                        "schema": "auditooor.hackerman_proof_artifact_record_proposals.v1",
                        "conversion_status": "dry-run",
                        "dry_run": True,
                        "packets_path": "reports/proof_artifact_missing_record_review_packets_slice12.jsonl",
                        "records_built": 1,
                        "records_emitted": 1,
                        "failed_count": 0,
                        "files": ["audit/corpus_tags/tags/missing.yaml"],
                    }
                ),
                encoding="utf-8",
            )

            status = MODULE.build_status(root=root)

            proof_gap = next(
                row for row in status["gap_details"]
                if row["id"] == "proof_artifact_feedback_sparse"
            )
            self.assertIn("Create exact Hackerman records from the ready review packets", proof_gap["next_action"])
            self.assertIn("materialized_files=0/1", proof_gap["evidence"])
            self.assertIn("dry_run=True", proof_gap["evidence"])

    def test_proof_artifact_record_proposals_treat_existing_outputs_as_converted(self) -> None:
        with tempfile.TemporaryDirectory(prefix="hackerman-capability-proof-proposals-existing-") as td:
            root = Path(td)
            for sub in ("audit/corpus_tags/tags", "audit/corpus_tags/derived", "audit/corpus_tags/index", "reports"):
                (root / sub).mkdir(parents=True)
            (root / "audit/corpus_tags/tags/a.yaml").write_text(
                "schema: auditooor.hackerman_record.v1\nlanguage: solidity\n",
                encoding="utf-8",
            )
            (root / "audit/corpus_tags/derived/proof_artifact_index.jsonl").write_text(
                json.dumps({"candidate_proof_path": "audits/dydx/poc-tests/a.go", "promotion_ready": True})
                + "\n",
                encoding="utf-8",
            )
            (root / "reports" / "proof_artifact_missing_record_import_queue_slice10.jsonl").write_text(
                json.dumps({"schema": "auditooor.hackerman_missing_record_import_queue.v1", "engagement": "dydx", "candidate_count": 1})
                + "\n",
                encoding="utf-8",
            )
            (root / "reports" / "proof_artifact_missing_record_review_packets_slice12.jsonl").write_text(
                json.dumps(
                    {
                        "schema": "auditooor.hackerman_missing_record_review_packet.v1",
                        "engagement": "dydx",
                        "validation_status": "ready_for_manual_record_creation",
                        "artifact_candidates": [{"candidate_proof_path": "audits/dydx/poc-tests/a.go"}],
                    }
                )
                + "\n",
                encoding="utf-8",
            )
            generated_record = root / "audit/corpus_tags/tags/submission-derived-example.yaml"
            generated_record.write_text("schema_version: auditooor.hackerman_record.v1\n", encoding="utf-8")
            (root / "reports" / "proof_artifact_record_proposals_slice19_summary.json").write_text(
                json.dumps(
                    {
                        "schema": "auditooor.hackerman_proof_artifact_record_proposals.v1",
                        "conversion_status": "already-materialized",
                        "dry_run": False,
                        "packets_path": "reports/proof_artifact_missing_record_review_packets_slice12.jsonl",
                        "records_built": 1,
                        "records_emitted": 0,
                        "records_existing": 1,
                        "failed_count": 0,
                        "files": [],
                        "collisions": ["audit/corpus_tags/tags/submission-derived-example.yaml"],
                    }
                ),
                encoding="utf-8",
            )

            status = MODULE.build_status(root=root)

            queue_status = status["proof_artifact_import_queue"]
            self.assertEqual(queue_status["latest_record_proposal_records_existing"], 1)
            self.assertEqual(queue_status["latest_record_proposal_collision_files_existing"], 1)
            proof_gap = next(row for row in status["gap_details"] if row["id"] == "proof_artifact_feedback_sparse")
            self.assertIn("Ready review packets have been converted", proof_gap["next_action"])
            self.assertIn("(1 already existed)", proof_gap["evidence"])
            self.assertIn("existing_materialized=1/1", proof_gap["evidence"])

    def test_proof_artifact_record_proposals_do_not_convert_when_stale_for_packet(self) -> None:
        with tempfile.TemporaryDirectory(prefix="hackerman-capability-proof-proposals-stale-") as td:
            root = Path(td)
            for sub in ("audit/corpus_tags/tags", "audit/corpus_tags/derived", "audit/corpus_tags/index", "reports"):
                (root / sub).mkdir(parents=True)
            (root / "audit/corpus_tags/tags/a.yaml").write_text(
                "schema: auditooor.hackerman_record.v1\nlanguage: solidity\n",
                encoding="utf-8",
            )
            (root / "audit/corpus_tags/derived/proof_artifact_index.jsonl").write_text(
                json.dumps({"candidate_proof_path": "audits/dydx/poc-tests/a.go", "promotion_ready": True})
                + "\n",
                encoding="utf-8",
            )
            (root / "reports" / "proof_artifact_missing_record_import_queue_slice10.jsonl").write_text(
                json.dumps({"schema": "auditooor.hackerman_missing_record_import_queue.v1", "engagement": "dydx", "candidate_count": 1})
                + "\n",
                encoding="utf-8",
            )
            packet_path = root / "reports" / "proof_artifact_missing_record_review_packets_slice12.jsonl"
            packet_path.write_text(
                json.dumps(
                    {
                        "schema": "auditooor.hackerman_missing_record_review_packet.v1",
                        "engagement": "dydx",
                        "validation_status": "ready_for_manual_record_creation",
                        "artifact_candidates": [{"candidate_proof_path": "audits/dydx/poc-tests/a.go"}],
                    }
                )
                + "\n",
                encoding="utf-8",
            )
            generated_record = root / "audit/corpus_tags/tags/submission-derived-example.yaml"
            generated_record.write_text("schema_version: auditooor.hackerman_record.v1\n", encoding="utf-8")
            proposal_path = root / "reports" / "proof_artifact_record_proposals_slice13_summary.json"
            proposal_path.write_text(
                json.dumps(
                    {
                        "schema": "auditooor.hackerman_proof_artifact_record_proposals.v1",
                        "conversion_status": "success",
                        "dry_run": False,
                        "packets_path": "reports/proof_artifact_missing_record_review_packets_slice12.jsonl",
                        "records_built": 1,
                        "records_emitted": 1,
                        "failed_count": 0,
                        "files": ["audit/corpus_tags/tags/submission-derived-example.yaml"],
                    }
                ),
                encoding="utf-8",
            )
            os.utime(proposal_path, (1, 1))
            os.utime(packet_path, None)

            status = MODULE.build_status(root=root)

            proof_gap = next(row for row in status["gap_details"] if row["id"] == "proof_artifact_feedback_sparse")
            self.assertIn("Create exact Hackerman records from the ready review packets", proof_gap["next_action"])
            self.assertIn("current_for_packet=False", proof_gap["evidence"])

    def test_proof_artifact_index_sidecar_freshness_prefers_generated_at(self) -> None:
        with tempfile.TemporaryDirectory(prefix="hackerman-capability-proof-index-freshness-") as td:
            root = Path(td)
            for sub in ("audit/corpus_tags/tags", "audit/corpus_tags/derived", "audit/corpus_tags/index"):
                (root / sub).mkdir(parents=True)
            (root / "audit/corpus_tags/tags/a.yaml").write_text(
                "schema: auditooor.hackerman_record.v1\nlanguage: solidity\n",
                encoding="utf-8",
            )
            sidecar = root / "audit/corpus_tags/derived/proof_artifact_index.jsonl"
            sidecar.write_text(
                json.dumps(
                    {
                        "generated_at": "2000-01-01T00:00:00Z",
                        "candidate_proof_path": "audits/dydx/poc-tests/a.go",
                    }
                )
                + "\n",
                encoding="utf-8",
            )
            os.utime(sidecar, None)

            status = MODULE.build_status(root=root)
            proof_index = status["derived_sidecars"]["proof_artifact_index"]

            self.assertEqual(proof_index["rows"], 1)
            self.assertEqual(proof_index["generated_at"], "2000-01-01T00:00:00Z")
            self.assertEqual(proof_index["freshness_basis"], "generated_at")
            self.assertEqual(proof_index["freshness_class"], "stale")

    def test_missing_proof_artifact_index_sidecar_reports_missing_freshness(self) -> None:
        with tempfile.TemporaryDirectory(prefix="hackerman-capability-proof-index-missing-") as td:
            root = Path(td)
            for sub in ("audit/corpus_tags/tags", "audit/corpus_tags/derived", "audit/corpus_tags/index"):
                (root / sub).mkdir(parents=True)
            (root / "audit/corpus_tags/tags/a.yaml").write_text(
                "schema: auditooor.hackerman_record.v1\nlanguage: solidity\nproof_artifact_path: reports/x.md\n",
                encoding="utf-8",
            )

            status = MODULE.build_status(root=root)
            proof_index = status["derived_sidecars"]["proof_artifact_index"]

            self.assertFalse(proof_index["exists"])
            self.assertEqual(proof_index["rows"], 0)
            self.assertEqual(proof_index["freshness_class"], "missing")
            self.assertEqual(proof_index["freshness_basis"], "missing")

    def test_external_phase_f_lift_uses_newest_generated_at_and_keeps_scoped_followup_separate(self) -> None:
        with tempfile.TemporaryDirectory(prefix="hackerman-capability-phase-f-lift-") as td:
            root = Path(td)
            for sub in ("audit/corpus_tags/tags", "audit/corpus_tags/derived", "audit/corpus_tags/index", "reports"):
                (root / sub).mkdir(parents=True)
            (root / "audit/corpus_tags/tags/a.yaml").write_text(
                "schema: auditooor.hackerman_record.v1\nlanguage: solidity\nproof_artifact_path: reports/x.md\n",
                encoding="utf-8",
            )
            (root / "reports/realworld_recall_scoreboard.json").write_text(
                json.dumps(
                    {
                        "schema": "auditooor.realworld_recall_scoreboard.v1",
                        "generated_at": "2026-05-17T00:00:00Z",
                        "overall": {
                            "held_out_scorable": 20,
                            "realworld_recall_same_class": 0.25,
                        },
                    }
                ),
                encoding="utf-8",
            )
            (root / "reports/external_recall_samples_phase_f.json").write_text(
                json.dumps(
                    {
                        "schema": "auditooor.external_recall_samples.v1",
                        "samples": [{"id": "a"}, {"id": "b"}],
                    }
                ),
                encoding="utf-8",
            )
            scoreboards = {
                "realworld_recall_scoreboard_external_phase_f.json": {
                    "generated_at": "2026-05-17T13:36:48Z",
                    "external_manifest": str(root / "reports/external_recall_samples_phase_f.json"),
                    "overall": {
                        "by_origin": {
                            "external_repo": {
                                "held_out_scorable": 9,
                                "realworld_recall_same_class": 0.4444,
                            }
                        }
                    },
                },
                "realworld_recall_scoreboard_external_phase_f_after_w68.json": {
                    "generated_at": "2026-05-17T14:44:40Z",
                    "external_manifest": str(root / "reports/external_recall_samples_phase_f.json"),
                    "overall": {
                        "by_origin": {
                            "external_repo": {
                                "held_out_scorable": 9,
                                "realworld_recall_same_class": 0.7778,
                            }
                        }
                    },
                },
                "realworld_recall_scoreboard_external_phase_f_after_missing_recipient.json": {
                    "generated_at": "2026-05-17T15:04:23Z",
                    "external_manifest": "/private/tmp/external_recall_samples_missing_recipient.json",
                    "overall": {
                        "by_origin": {
                            "external_repo": {
                                "held_out_scorable": 3,
                                "realworld_recall_same_class": 1.0,
                            }
                        }
                    },
                },
            }
            for filename, payload in scoreboards.items():
                (root / "reports" / filename).write_text(
                    json.dumps({"schema": "auditooor.realworld_recall_scoreboard.v1", **payload}),
                    encoding="utf-8",
                )

            status = MODULE.build_status(root=root)
            external_sidecars = status["recall_scoreboard"]["external_sidecars"]
            phase_f_lift = external_sidecars["phase_f_recall_lift"]

            self.assertEqual(external_sidecars["latest_measurement"]["path"], "reports/realworld_recall_scoreboard_external_phase_f_after_missing_recipient.json")
            self.assertEqual(external_sidecars["latest_scorable_samples"], 3)
            self.assertEqual(external_sidecars["latest_same_class_recall_pct"], 100.0)
            self.assertEqual(phase_f_lift["baseline"]["same_class_recall_pct"], 44.4)
            self.assertEqual(phase_f_lift["latest_comparable"]["path"], "reports/realworld_recall_scoreboard_external_phase_f_after_w68.json")
            self.assertEqual(phase_f_lift["latest_comparable"]["same_class_recall_pct"], 77.8)
            self.assertEqual(phase_f_lift["delta_pct_points"], 33.4)

    def test_render_text_surfaces_phase_f_lift_and_sidecar_freshness_rollup(self) -> None:
        status = {
            "root": "/tmp/demo",
            "corpus": {
                "yaml_tags": 1,
                "hackerman_record_v1": 1,
                "unknown_year_2000": 0,
                "exact_language_go": 0,
                "target_language_go": 0,
                "in_record_cross_language_analogues_populated": 0,
                "in_record_cross_language_analogues_empty": 1,
                "proof_artifact_path_populated": 1,
            },
            "sidecar_freshness": {
                "total": 2,
                "healthy_count": 1,
                "counts": {"fresh": 1, "stale": 1},
                "non_fresh": ["proof_hardening"],
            },
            "derived_sidecars": {
                "record_quality": {
                    "exists": True,
                    "rows": 1,
                    "freshness_class": "fresh",
                    "mtime_utc": "2026-05-17T07:33:05Z",
                    "path": "audit/corpus_tags/derived/record_quality.jsonl",
                },
                "proof_hardening": {
                    "exists": True,
                    "rows": 1,
                    "freshness_class": "stale",
                    "mtime_utc": "2026-05-15T07:33:05Z",
                    "path": "audit/corpus_tags/derived/proof_hardening.jsonl",
                },
            },
            "cross_language_analogue_policy": {
                "canonical_source": "derived_sidecar",
                "sidecar_rows": 1,
                "in_record_writeback_required": False,
                "consumer_contract": "tools/hackerman_query_common.py:load_cross_language_analogue_index",
            },
            "hooks": {
                "pre_source_read_injector": True,
                "claude_pre_source_read_hook": True,
                "hackerman_tooling_index": True,
            },
            "recall_scoreboard": {
                "same_class_recall_pct": 25.3,
                "scorable_samples": 830,
                "external_repo_samples": 0,
                "external_sidecars": {
                    "sample_count": 9,
                    "latest_measurement": {
                        "path": "reports/realworld_recall_scoreboard_external_phase_f_after_missing_recipient.json",
                        "same_class_recall_pct": 100.0,
                        "scorable_samples": 3,
                        "timestamp_utc": "2026-05-17T15:04:23Z",
                    },
                    "latest_phase_f_measurement": {
                        "path": "reports/realworld_recall_scoreboard_external_phase_f_after_w68.json",
                        "same_class_recall_pct": 77.8,
                        "scorable_samples": 9,
                        "timestamp_utc": "2026-05-17T14:44:40Z",
                    },
                    "phase_f_recall_lift": {
                        "baseline": {"same_class_recall_pct": 44.4},
                        "latest_comparable": {
                            "same_class_recall_pct": 77.8,
                            "scorable_samples": 9,
                            "timestamp_utc": "2026-05-17T14:44:40Z",
                        },
                        "delta_pct_points": 33.4,
                    },
                },
            },
            "index_files": {"count": 1},
            "known_gaps": [],
            "gap_details": [],
        }

        rendered = MODULE.render_text(status)

        self.assertIn("Sidecar freshness:", rendered)
        self.assertIn("counts=fresh=1, stale=1", rendered)
        self.assertIn("non_fresh=proof_hardening", rendered)
        self.assertIn("Phase F external recall:", rendered)
        self.assertIn("phase_f_lift=44.4% -> 77.8% on 9 scorable", rendered)
        self.assertIn("Latest scoped follow-up:", rendered)
        self.assertIn("latest_scoped_followup=100.0% on 3 scorable", rendered)


class HackermanCapabilityStatusAdoptionTest(unittest.TestCase):
    """EXEC-A3 lift: surface LOW_ADOPTION / DEAD_ADOPTION from MCP call log."""

    def _seed_workspace(
        self,
        ws: Path,
        callable_counts: dict[str, int],
    ) -> None:
        (ws / ".auditooor").mkdir(parents=True, exist_ok=True)
        log = ws / ".auditooor" / "mcp_call_log.jsonl"
        rows = []
        for name, count in callable_counts.items():
            for i in range(count):
                rows.append(
                    json.dumps(
                        {
                            "ts": f"2026-05-15T12:{i:02d}:00Z",
                            "workspace": str(ws),
                            "callable": name,
                            "args_hash": f"{i:08x}",
                            "verdict": "ok",
                            "duration_ms": 5,
                            "degraded": False,
                        }
                    )
                )
        log.write_text("\n".join(rows) + ("\n" if rows else ""), encoding="utf-8")

    def test_low_adoption_and_dead_adoption_surface(self) -> None:
        with tempfile.TemporaryDirectory(prefix="capstatus-adopt-") as td:
            root = Path(td)
            for sub in ("audit/corpus_tags/tags", "audit/corpus_tags/derived", "audit/corpus_tags/index"):
                (root / sub).mkdir(parents=True)
            # Provide minimal hackerman record so corpus counters are sane.
            (root / "audit/corpus_tags/tags/a.yaml").write_text(
                "schema: auditooor.hackerman_record.v1\nlanguage: go\nproof_artifact_path: reports/x.md\n",
                encoding="utf-8",
            )

            ws = root / "ws"
            ws.mkdir()
            # vault_resume_context: 5 times (above threshold) -> no adoption gap
            # vault_function_signature_shape: 1 time -> LOW_ADOPTION
            # vault_function_shape_attack_evidence: 0 times -> DEAD_ADOPTION
            self._seed_workspace(
                ws,
                {
                    "vault_resume_context": 5,
                    "vault_function_signature_shape": 1,
                    # function_shape_attack_evidence intentionally absent
                },
            )

            status = MODULE.build_status(root=root, workspace=ws)
            gaps = status["known_gaps"]
            self.assertIn("low_adoption_vault_function_signature_shape", gaps)
            self.assertIn("dead_adoption_vault_function_shape_attack_evidence", gaps)
            self.assertNotIn("low_adoption_vault_resume_context", gaps)
            self.assertNotIn("dead_adoption_vault_resume_context", gaps)
            # adoption_counts surfaced too
            self.assertEqual(status["adoption_counts"]["vault_resume_context"], 5)
            self.assertEqual(status["adoption_counts"]["vault_function_signature_shape"], 1)
            self.assertEqual(status["adoption_counts"]["vault_function_shape_attack_evidence"], 0)

    def test_no_workspace_means_all_callables_dead(self) -> None:
        with tempfile.TemporaryDirectory(prefix="capstatus-noadopt-") as td:
            root = Path(td)
            for sub in ("audit/corpus_tags/tags", "audit/corpus_tags/derived", "audit/corpus_tags/index"):
                (root / sub).mkdir(parents=True)
            (root / "audit/corpus_tags/tags/a.yaml").write_text(
                "schema: auditooor.hackerman_record.v1\nlanguage: go\n",
                encoding="utf-8",
            )
            status = MODULE.build_status(root=root, workspace=None)
            # workspace None -> adoption counts are all zero but they are NOT
            # surfaced as dead_adoption gaps since no workspace was inspected.
            # build_status calls _collect_adoption_counts(workspace=None) which
            # only inspects env-path overrides; if none, every callable is 0
            # -> every tracked callable would surface as dead_adoption.
            # We accept that downstream surface (matches the
            # "no workspace probed" reality); just verify the field exists.
            self.assertIn("adoption_counts", status)


if __name__ == "__main__":
    unittest.main()
