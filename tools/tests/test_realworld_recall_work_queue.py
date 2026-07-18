"""Tests for tools/audit/realworld-recall-work-queue.py."""

from __future__ import annotations

import copy
import contextlib
import io
import importlib.util
import json
import tempfile
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
TOOL = REPO_ROOT / "tools" / "audit" / "realworld-recall-work-queue.py"


def _load_module():
    spec = importlib.util.spec_from_file_location("realworld_recall_work_queue", TOOL)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


M = _load_module()


def _priority_payload() -> dict:
    return {
        "schema": M.PRIORITIES_SCHEMA,
        "generated_at": "2026-05-17T00:00:00Z",
        "priorities": [
            {
                "rank": 1,
                "attack_class": "bridge-proof-domain-bypass",
                "priority_band": "P0",
                "priority_score": 93.8,
                "same_class_recall": 0.0,
                "same_class_misses": 17,
                "gap_vs_any_pp": 76.5,
                "gap_vs_self_test_pp": 58.8,
                "external_evidence": {
                    "repo_examples": [{"repo": "snowbridge", "samples": 7}],
                },
                "miss_examples": [
                    {
                        "slug": "snowbridge/contracts/BeefyClient.sol",
                        "source": "external_repo:snowbridge",
                        "sample_origin": "external_repo",
                        "own_detector_fired": False,
                        "independent_any_fired": True,
                        "independent_firing_detectors": ["wrong-detector"],
                    }
                ],
                "top_cross_class_detectors_on_misses": [
                    {"detector": "wrong-detector", "count": 5}
                ],
                "next_tasks": [
                    {
                        "task_type": "detector-generalization",
                        "summary": "Generalize bridge proof detector.",
                    },
                    {
                        "task_type": "external-replay",
                        "summary": "Replay Snowbridge samples.",
                    },
                ],
            }
        ],
        "taxonomy_debt": [
            {
                "rank": 1,
                "attack_class": "uncategorized",
                "priority_band": "P3",
                "priority_score": 20.0,
                "same_class_recall": 0.0,
                "same_class_misses": 2,
                "next_tasks": [
                    {
                        "task_type": "taxonomy-backfill",
                        "summary": "Backfill only with evidence.",
                    }
                ],
            }
        ],
    }


class RealworldRecallWorkQueueTest(unittest.TestCase):
    def test_builds_one_row_per_next_task_without_taxonomy_by_default(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            source = root / "priorities.json"
            source.write_text(json.dumps(_priority_payload()), encoding="utf-8")
            payload, digest = M.load_priorities(source)
            rows = M.build_rows(
                payload,
                source_path=source,
                source_sha256=digest,
                top_n=10,
                include_taxonomy=False,
            )
        self.assertEqual(len(rows), 2)
        self.assertTrue(all(row["schema"] == M.ROW_SCHEMA for row in rows))
        self.assertTrue(all(row["submission_posture"] == "NOT_SUBMIT_READY" for row in rows))
        self.assertFalse(any(row["taxonomy_debt"] for row in rows))
        self.assertEqual(rows[0]["priority_source"], "attack_class_priority")
        self.assertEqual(rows[0]["source_priority"]["attack_class"], "bridge-proof-domain-bypass")
        self.assertEqual(rows[0]["candidate_miss_examples"][0]["slug"], "snowbridge/contracts/BeefyClient.sol")
        self.assertIn("NOT_SUBMIT_READY", rows[0]["submission_posture"])
        self.assertTrue(any("before/after" in item for item in rows[0]["closeout_requirements"]))
        self.assertFalse(rows[0]["provider_dispatch_ready"])
        self.assertIn("visible_own_detector_evidence_missing", rows[0]["workability_blockers"])

    def test_include_taxonomy_keeps_uncategorized_separate(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            source = root / "priorities.json"
            source.write_text(json.dumps(_priority_payload()), encoding="utf-8")
            payload, digest = M.load_priorities(source)
            rows = M.build_rows(
                payload,
                source_path=source,
                source_sha256=digest,
                top_n=1,
                include_taxonomy=True,
            )
        taxonomy_rows = [row for row in rows if row["taxonomy_debt"]]
        self.assertEqual(len(taxonomy_rows), 1)
        self.assertEqual(rows[-1]["priority_source"], "taxonomy_debt")
        self.assertEqual(taxonomy_rows[0]["work_item"]["task_type"], "taxonomy-backfill")
        self.assertIn("filename-only", " ".join(taxonomy_rows[0]["closeout_requirements"]))

    def test_ready_row_exposes_provider_dispatch_fields(self) -> None:
        payload = copy.deepcopy(_priority_payload())
        priority = payload["priorities"][0]
        priority["miss_examples"][0]["own_detector_fired"] = True
        priority["miss_examples"][0]["independent_any_fired"] = True
        priority["next_tasks"] = [
            {
                "task_type": "detector-generalization",
                "summary": "Generalize bridge proof detector from visible own-class evidence.",
            }
        ]
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            sample = root / "BeefyClient.sol"
            sample.write_text("contract BeefyClient {}\n", encoding="utf-8")
            priority["miss_examples"][0]["source_path"] = str(sample)
            source = root / "priorities.json"
            source.write_text(json.dumps(payload), encoding="utf-8")
            parsed, digest = M.load_priorities(source)
            rows = M.build_rows(
                parsed,
                source_path=source,
                source_sha256=digest,
                top_n=10,
                include_taxonomy=False,
            )
            summary = M.build_summary(
                rows=rows,
                source_path=source,
                source_sha256=digest,
                out_path=root / "queue.jsonl",
                dry_run=True,
            )

        self.assertEqual(len(rows), 1)
        self.assertTrue(rows[0]["provider_dispatch_ready"])
        self.assertEqual(rows[0]["workability_status"], "ready_for_provider_dispatch")
        self.assertEqual(rows[0]["workability_blockers"], [])
        self.assertEqual(rows[0]["workability_evidence"]["visible_source_artifact_examples"], 1)
        self.assertTrue(rows[0]["candidate_miss_examples"][0]["source_path"].endswith("BeefyClient.sol"))
        self.assertEqual(rows[0]["workability_evidence"]["visible_own_detector_examples"], 1)
        self.assertEqual(summary["provider_dispatch_ready_rows"], 1)
        self.assertEqual(summary["provider_dispatch_blocked_rows"], 0)
        self.assertEqual(summary["by_workability_status"], {"ready_for_provider_dispatch": 1})

    def test_miss_examples_include_pattern_and_fixture_source_artifacts(self) -> None:
        payload = copy.deepcopy(_priority_payload())
        priority = payload["priorities"][0]
        priority["attack_class"] = "state-corruption-via-race"
        priority["miss_examples"] = [
            {
                "slug": "erc20-approve-race-no-zero-reset",
                "source": "solodit/C0155",
                "sample_origin": "internal_fixture",
                "own_detector_fired": True,
                "independent_any_fired": True,
                "independent_firing_detectors": ["wrong-detector"],
            }
        ]
        priority["next_tasks"] = [
            {
                "task_type": "detector-generalization",
                "summary": "Generalize approve race detector from visible own-class evidence.",
            }
        ]
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            source = root / "priorities.json"
            source.write_text(json.dumps(payload), encoding="utf-8")
            parsed, digest = M.load_priorities(source)
            rows = M.build_rows(
                parsed,
                source_path=source,
                source_sha256=digest,
                top_n=10,
                include_taxonomy=False,
            )

        artifacts = rows[0]["candidate_miss_examples"][0]["source_artifacts"]
        self.assertIn("reference/patterns.dsl/erc20-approve-race-no-zero-reset.yaml", artifacts)
        self.assertIn("patterns/fixtures/erc20-approve-race-no-zero-reset_vuln.sol", artifacts)
        self.assertEqual(rows[0]["workability_evidence"]["visible_source_artifact_examples"], 1)
        self.assertTrue(rows[0]["provider_dispatch_ready"])

    def test_detector_work_without_source_artifact_blocks_provider_dispatch(self) -> None:
        payload = copy.deepcopy(_priority_payload())
        priority = payload["priorities"][0]
        priority["miss_examples"] = [
            {
                "slug": "missing-local-artifact-example",
                "source": "internal-only",
                "sample_origin": "internal_fixture",
                "own_detector_fired": True,
                "independent_any_fired": True,
            }
        ]
        priority["next_tasks"] = [
            {
                "task_type": "detector-generalization",
                "summary": "Generalize from visible own-class evidence.",
            }
        ]
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            source = root / "priorities.json"
            source.write_text(json.dumps(payload), encoding="utf-8")
            parsed, digest = M.load_priorities(source)
            rows = M.build_rows(
                parsed,
                source_path=source,
                source_sha256=digest,
                top_n=10,
                include_taxonomy=False,
            )

        self.assertFalse(rows[0]["provider_dispatch_ready"])
        self.assertEqual(rows[0]["workability_status"], "needs_candidate_evidence")
        self.assertIn("candidate_source_artifacts_missing", rows[0]["workability_blockers"])

    def test_detector_work_with_partial_source_artifacts_blocks_provider_dispatch(self) -> None:
        payload = copy.deepcopy(_priority_payload())
        priority = payload["priorities"][0]
        priority["miss_examples"] = [
            {
                "slug": "locally-backed-example",
                "source": "internal-only",
                "sample_origin": "internal_fixture",
                "own_detector_fired": True,
                "independent_any_fired": True,
            },
            {
                "slug": "missing-local-artifact-example",
                "source": "internal-only",
                "sample_origin": "internal_fixture",
                "own_detector_fired": True,
                "independent_any_fired": True,
            },
        ]
        priority["next_tasks"] = [
            {
                "task_type": "detector-generalization",
                "summary": "Generalize from visible own-class evidence.",
            }
        ]
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            sample = root / "Backed.sol"
            sample.write_text("contract Backed {}\n", encoding="utf-8")
            priority["miss_examples"][0]["source_path"] = str(sample)
            source = root / "priorities.json"
            source.write_text(json.dumps(payload), encoding="utf-8")
            parsed, digest = M.load_priorities(source)
            rows = M.build_rows(
                parsed,
                source_path=source,
                source_sha256=digest,
                top_n=10,
                include_taxonomy=False,
            )

        self.assertFalse(rows[0]["provider_dispatch_ready"])
        self.assertEqual(rows[0]["workability_status"], "needs_candidate_evidence")
        self.assertIn("candidate_source_artifacts_partial", rows[0]["workability_blockers"])
        self.assertEqual(rows[0]["workability_evidence"]["visible_source_artifact_examples"], 1)
        self.assertEqual(rows[0]["workability_evidence"]["visible_candidate_miss_examples"], 2)

    def test_sibling_detector_gap_with_hidden_own_backed_examples_blocks_provider_dispatch(self) -> None:
        payload = copy.deepcopy(_priority_payload())
        payload["priorities"][0]["next_tasks"] = [
            {
                "task_type": "sibling-detector-gap",
                "summary": (
                    "Prioritize the 10 own-detector-backed misses where the authored detector "
                    "works but no sibling same-class detector generalizes."
                ),
            }
        ]
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            source = root / "priorities.json"
            source.write_text(json.dumps(payload), encoding="utf-8")
            parsed, digest = M.load_priorities(source)
            rows = M.build_rows(
                parsed,
                source_path=source,
                source_sha256=digest,
                top_n=10,
                include_taxonomy=False,
            )
            summary = M.build_summary(
                rows=rows,
                source_path=source,
                source_sha256=digest,
                out_path=root / "queue.jsonl",
                dry_run=True,
            )

        self.assertFalse(rows[0]["provider_dispatch_ready"])
        self.assertEqual(rows[0]["workability_status"], "needs_full_miss_list")
        self.assertIn("own_detector_summary_examples_missing", rows[0]["workability_blockers"])
        self.assertEqual(rows[0]["workability_evidence"]["claimed_own_detector_backed_misses"], 10)
        self.assertEqual(summary["workability_blocker_counts"]["own_detector_summary_examples_missing"], 1)

    def test_saturated_external_replay_blocks_provider_dispatch(self) -> None:
        payload = copy.deepcopy(_priority_payload())
        priority = payload["priorities"][0]
        priority["next_tasks"] = [
            {
                "task_type": "external-replay",
                "summary": (
                    "Use measured external bridge-proof-domain-bypass samples as replay fixtures; "
                    "current external same-class recall is 100.0%."
                ),
            }
        ]
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            source = root / "priorities.json"
            source.write_text(json.dumps(payload), encoding="utf-8")
            parsed, digest = M.load_priorities(source)
            rows = M.build_rows(
                parsed,
                source_path=source,
                source_sha256=digest,
                top_n=10,
                include_taxonomy=False,
            )
            summary = M.build_summary(
                rows=rows,
                source_path=source,
                source_sha256=digest,
                out_path=root / "queue.jsonl",
                dry_run=True,
            )

        self.assertFalse(rows[0]["provider_dispatch_ready"])
        self.assertEqual(rows[0]["workability_status"], "no_recall_lift_available")
        self.assertIn("external_recall_already_saturated", rows[0]["workability_blockers"])
        self.assertIn("external_recall_quality_missing", rows[0]["workability_blockers"])
        self.assertEqual(summary["provider_dispatch_ready_rows"], 0)
        self.assertEqual(summary["provider_dispatch_blocked_rows"], 1)
        self.assertEqual(summary["workability_blocker_counts"]["external_recall_already_saturated"], 1)

    def test_bad_schema_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            source = Path(td) / "bad.json"
            source.write_text(json.dumps({"schema": "wrong", "priorities": []}), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "schema must be"):
                M.load_priorities(source)

    def test_cli_writes_jsonl_and_summary(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            source = root / "priorities.json"
            out = root / "queue.jsonl"
            source.write_text(json.dumps(_priority_payload()), encoding="utf-8")
            rc = M.main(["--priorities", str(source), "--out", str(out), "--json-summary"])
            self.assertEqual(rc, 0)
            rows = [json.loads(line) for line in out.read_text(encoding="utf-8").splitlines()]
            self.assertEqual(len(rows), 2)
            self.assertEqual(rows[0]["schema"], M.ROW_SCHEMA)

    def test_quality_blocked_external_rows_reclassify_detector_work(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            source = root / "priorities.json"
            quality = root / "quality.json"
            source.write_text(json.dumps(_priority_payload()), encoding="utf-8")
            quality.write_text(
                json.dumps(
                    {
                        "schema": M.QUALITY_SCHEMA,
                        "generated_at": "2026-05-17T00:01:00Z",
                        "manifest_path": str(root / "manifest.json"),
                        "manifest_sha256": "abc",
                        "manifest_errors": [],
                        "summary": {
                            "sample_count": 7,
                            "gap_eligible": 0,
                            "needs_source_state_validation": 7,
                            "disqualified_source_state": 0,
                            "blockers": 7,
                        },
                        "rows": [
                            {
                                "id": f"snowbridge-{idx}",
                                "attack_class": "bridge-proof-domain-bypass",
                                "quality_state": "needs_source_state_validation",
                                "gap_prioritization_eligible": False,
                                "required_actions": [
                                    "confirm vulnerable pre-fix, fixed/post-fix, or out-of-class source state"
                                ],
                            }
                            for idx in range(7)
                        ],
                    }
                ),
                encoding="utf-8",
            )

            payload, digest = M.load_priorities(source)
            quality_by_attack, loaded_paths = M.load_quality_reports([quality])
            rows = M.build_rows(
                payload,
                source_path=source,
                source_sha256=digest,
                top_n=10,
                include_taxonomy=False,
                quality_by_attack_class=quality_by_attack,
            )
            summary = M.build_summary(
                rows=rows,
                source_path=source,
                source_sha256=digest,
                out_path=root / "queue.jsonl",
                dry_run=True,
                quality_report_paths=loaded_paths,
            )

        self.assertEqual({row["status"] for row in rows}, {"quality_blocked"})
        self.assertEqual(
            {row["work_item"]["task_type"] for row in rows},
            {"source-state-validation"},
        )
        self.assertEqual(rows[0]["external_recall_quality"]["gap_eligible"], 0)
        self.assertTrue(rows[0]["external_recall_quality"]["quality_blocked"])
        self.assertEqual(
            rows[0]["external_recall_quality"]["quality_blocked_reason"],
            "needs_source_state_validation",
        )
        self.assertIn("quality", " ".join(rows[0]["closeout_requirements"]).lower())
        self.assertEqual(summary["quality_blocked_rows"], 2)
        self.assertEqual(summary["quality_needs_validation_rows"], 2)
        self.assertEqual(summary["quality_disqualified_only_rows"], 0)
        self.assertEqual(summary["by_status"], {"quality_blocked": 2})
        self.assertEqual(summary["quality_report_paths"], [str(quality.resolve())])

    def test_cli_auto_discovers_quality_reports(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            source = root / "priorities.json"
            out = root / "queue.jsonl"
            quality = root / "external_recall_manifest_quality_fixture.json"
            source.write_text(json.dumps(_priority_payload()), encoding="utf-8")
            quality.write_text(
                json.dumps(
                    {
                        "schema": M.QUALITY_SCHEMA,
                        "generated_at": "2026-05-17T00:01:00Z",
                        "manifest_path": str(root / "manifest.json"),
                        "manifest_sha256": "abc",
                        "manifest_errors": [],
                        "summary": {
                            "sample_count": 1,
                            "gap_eligible": 0,
                            "needs_source_state_validation": 0,
                            "disqualified_source_state": 1,
                            "blockers": 1,
                        },
                        "rows": [
                            {
                                "id": "snowbridge/contracts/BeefyClient.sol",
                                "attack_class": "bridge-proof-domain-bypass",
                                "quality_state": "disqualified_source_state",
                                "source_state": "fixed_post_fix",
                                "gap_prioritization_eligible": False,
                                "required_actions": ["replace with vulnerable pre-fix snapshot"],
                            }
                        ],
                    }
                ),
                encoding="utf-8",
            )

            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout):
                rc = M.main(["--priorities", str(source), "--out", str(out), "--json-summary"])
            summary = json.loads(stdout.getvalue())
            rows = [json.loads(line) for line in out.read_text(encoding="utf-8").splitlines()]

        self.assertEqual(rc, 0)
        self.assertTrue(summary["quality_report_auto_discovered"])
        self.assertEqual(summary["quality_report_paths"], [str(quality.resolve())])
        self.assertEqual(rows[0]["external_recall_quality"]["candidate_sample_quality"][0]["id"], "snowbridge/contracts/BeefyClient.sol")

    def test_quality_sample_source_path_resolves_relative_to_report_dir(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            report = root / "reports" / "quality.json"
            sample = root / "reports" / "external_recall_snapshots" / "snowbridge" / "Verification.sol"
            sample.parent.mkdir(parents=True)
            sample.write_text("contract Verification {}\n", encoding="utf-8")

            resolved = M._quality_sample_source_path(
                "external_recall_snapshots/snowbridge/Verification.sol",
                report,
            )

        self.assertTrue(Path(resolved).is_absolute())
        self.assertTrue(resolved.endswith("reports/external_recall_snapshots/snowbridge/Verification.sol"))

    def test_quality_sample_source_path_handles_repo_relative_paths(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            old_root = M.REPO_ROOT
            M.REPO_ROOT = root
            try:
                report = root / "reports" / "quality.json"
                sample = root / "reports" / "external_recall_snapshots" / "snowbridge" / "Verification.sol"
                sample.parent.mkdir(parents=True)
                sample.write_text("contract Verification {}\n", encoding="utf-8")

                resolved = M._quality_sample_source_path(
                    "reports/external_recall_snapshots/snowbridge/Verification.sol",
                    report,
                )
            finally:
                M.REPO_ROOT = old_root

        self.assertEqual(
            resolved,
            "reports/external_recall_snapshots/snowbridge/Verification.sol",
        )

    def test_quality_sample_source_path_handles_existing_absolute_repo_paths(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            old_root = M.REPO_ROOT
            M.REPO_ROOT = root
            try:
                report = root / "reports" / "quality.json"
                sample = root / "reports" / "external_recall_snapshots" / "snowbridge" / "Verification.sol"
                sample.parent.mkdir(parents=True)
                sample.write_text("contract Verification {}\n", encoding="utf-8")

                resolved = M._quality_sample_source_path(str(sample), report)
            finally:
                M.REPO_ROOT = old_root

        self.assertEqual(
            resolved,
            "reports/external_recall_snapshots/snowbridge/Verification.sol",
        )

    def test_quality_sample_source_path_preserves_missing_paths(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            report = root / "reports" / "quality.json"

            resolved = M._quality_sample_source_path(
                "external_recall_snapshots/missing.sol",
                report,
            )

        self.assertEqual(resolved, "external_recall_snapshots/missing.sol")

    def test_sample_quality_replaces_blocked_visible_examples_when_eligible_sample_exists(self) -> None:
        payload = _priority_payload()
        payload["priorities"][0]["miss_examples"] = [
            {
                "slug": "snowbridge-contracts-src/beefyclient",
                "source": "external_repo:snowbridge",
                "sample_origin": "external_repo",
                "own_detector_fired": False,
            }
        ]
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            source = root / "priorities.json"
            source.write_text(json.dumps(payload), encoding="utf-8")
            old_quality = root / "external_recall_manifest_quality_old.json"
            new_quality = root / "external_recall_manifest_quality_new.json"
            old_quality.write_text(
                json.dumps(
                    {
                        "schema": M.QUALITY_SCHEMA,
                        "generated_at": "2026-05-17T00:01:00Z",
                        "manifest_path": str(root / "old.json"),
                        "manifest_sha256": "old",
                        "manifest_errors": [],
                        "rows": [
                            {
                                "id": "snowbridge-contracts-src/beefyclient",
                                "attack_class": "bridge-proof-domain-bypass",
                                "quality_state": "disqualified_source_state",
                                "gap_prioritization_eligible": False,
                            }
                        ],
                    }
                ),
                encoding="utf-8",
            )
            new_quality.write_text(
                json.dumps(
                    {
                        "schema": M.QUALITY_SCHEMA,
                        "generated_at": "2026-05-17T00:02:00Z",
                        "manifest_path": str(root / "new.json"),
                        "manifest_sha256": "new",
                        "manifest_errors": [],
                        "rows": [
                            {
                                "id": "snowbridge/snowbridge-4855ace3-parent-contracts/src/verification",
                                "attack_class": "bridge-proof-domain-bypass",
                                "quality_state": "gap_eligible",
                                "source_state": "pre_fix",
                                "source": "external_repo:snowbridge:pre-fix-4855ace3-parent",
                                "path": "external_recall_snapshots/snowbridge_4855ace3_parent/contracts/src/Verification.sol",
                                "gap_prioritization_eligible": True,
                            }
                        ],
                    }
                ),
                encoding="utf-8",
            )
            loaded, _ = M.load_quality_reports([old_quality, new_quality])
            source_payload, digest = M.load_priorities(source)
            rows = M.build_rows(
                source_payload,
                source_path=source,
                source_sha256=digest,
                top_n=10,
                include_taxonomy=False,
                quality_by_attack_class=loaded,
            )

        self.assertEqual({row["status"] for row in rows}, {"open"})
        self.assertEqual(
            {row["work_item"]["task_type"] for row in rows},
            {"source-state-validation"},
        )
        self.assertTrue(all(row["provider_dispatch_ready"] for row in rows))
        self.assertEqual(
            rows[0]["candidate_miss_examples"][0]["slug"],
            "snowbridge/snowbridge-4855ace3-parent-contracts/src/verification",
        )
        self.assertEqual(rows[0]["candidate_miss_examples"][0]["source_state"], "pre_fix")
        self.assertEqual(
            rows[0]["external_recall_quality"]["quality_state"],
            "gap_eligible_replacements_available",
        )
        self.assertFalse(rows[0]["external_recall_quality"]["quality_blocked"])
        self.assertEqual(
            rows[0]["external_recall_quality"]["replaced_blocked_candidate_examples"][0]["slug"],
            "snowbridge-contracts-src/beefyclient",
        )

    def test_sample_quality_keeps_blocked_visible_examples_when_no_replacement_exists(self) -> None:
        payload = _priority_payload()
        payload["priorities"][0]["miss_examples"] = [
            {
                "slug": "snowbridge-contracts-src/beefyclient",
                "source": "external_repo:snowbridge",
                "sample_origin": "external_repo",
                "own_detector_fired": False,
            }
        ]
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            source = root / "priorities.json"
            source.write_text(json.dumps(payload), encoding="utf-8")
            quality = root / "external_recall_manifest_quality_old.json"
            quality.write_text(
                json.dumps(
                    {
                        "schema": M.QUALITY_SCHEMA,
                        "generated_at": "2026-05-17T00:01:00Z",
                        "manifest_path": str(root / "old.json"),
                        "manifest_sha256": "old",
                        "manifest_errors": [],
                        "rows": [
                            {
                                "id": "snowbridge-contracts-src/beefyclient",
                                "attack_class": "bridge-proof-domain-bypass",
                                "quality_state": "disqualified_source_state",
                                "source_state": "fixed_post_fix",
                                "gap_prioritization_eligible": False,
                            }
                        ],
                    }
                ),
                encoding="utf-8",
            )
            loaded, _ = M.load_quality_reports([quality])
            source_payload, digest = M.load_priorities(source)
            rows = M.build_rows(
                source_payload,
                source_path=source,
                source_sha256=digest,
                top_n=10,
                include_taxonomy=False,
                quality_by_attack_class=loaded,
            )

        self.assertEqual({row["status"] for row in rows}, {"quality_blocked"})
        self.assertEqual(
            {row["work_item"]["task_type"] for row in rows},
            {"source-state-validation"},
        )
        self.assertFalse(any(row["provider_dispatch_ready"] for row in rows))
        self.assertEqual(
            rows[0]["candidate_miss_examples"][0]["slug"],
            "snowbridge-contracts-src/beefyclient",
        )
        self.assertNotIn("replacement_candidate_examples", rows[0]["external_recall_quality"])
        self.assertNotIn("replaced_blocked_candidate_examples", rows[0]["external_recall_quality"])
        self.assertTrue(rows[0]["external_recall_quality"]["quality_blocked"])
        self.assertEqual(
            rows[0]["external_recall_quality"]["quality_blocked_reason"],
            "disqualified_source_state",
        )

    def test_disqualified_external_rows_request_replacement_samples(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            source = root / "priorities.json"
            quality = root / "quality.json"
            source.write_text(json.dumps(_priority_payload()), encoding="utf-8")
            quality.write_text(
                json.dumps(
                    {
                        "schema": M.QUALITY_SCHEMA,
                        "generated_at": "2026-05-17T00:01:00Z",
                        "manifest_path": str(root / "manifest.json"),
                        "manifest_sha256": "abc",
                        "manifest_errors": [],
                        "summary": {
                            "sample_count": 7,
                            "gap_eligible": 0,
                            "needs_source_state_validation": 0,
                            "disqualified_source_state": 7,
                            "blockers": 7,
                        },
                        "rows": [
                            {
                                "id": f"snowbridge-{idx}",
                                "attack_class": "bridge-proof-domain-bypass",
                                "quality_state": "disqualified_source_state",
                                "source_state": "out_of_class",
                                "gap_prioritization_eligible": False,
                                "required_actions": [
                                    "remove from external recall gap scoring or replace with a vulnerable pre-fix snapshot"
                                ],
                            }
                            for idx in range(7)
                        ],
                    }
                ),
                encoding="utf-8",
            )

            payload, digest = M.load_priorities(source)
            quality_by_attack, loaded_paths = M.load_quality_reports([quality])
            rows = M.build_rows(
                payload,
                source_path=source,
                source_sha256=digest,
                top_n=10,
                include_taxonomy=False,
                quality_by_attack_class=quality_by_attack,
            )
            summary = M.build_summary(
                rows=rows,
                source_path=source,
                source_sha256=digest,
                out_path=root / "queue.jsonl",
                dry_run=True,
                quality_report_paths=loaded_paths,
            )

        self.assertEqual({row["status"] for row in rows}, {"quality_blocked"})
        self.assertEqual(
            rows[0]["external_recall_quality"]["quality_blocked_reason"],
            "disqualified_source_state",
        )
        self.assertIn("replace", rows[0]["work_item"]["summary"])
        self.assertIn("fixed or out-of-class", rows[0]["work_item"]["summary"])
        self.assertEqual(summary["quality_blocked_rows"], 2)
        self.assertEqual(summary["quality_needs_validation_rows"], 0)
        self.assertEqual(summary["quality_disqualified_only_rows"], 2)

    def test_dry_run_does_not_write(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            source = root / "priorities.json"
            out = root / "queue.jsonl"
            source.write_text(json.dumps(_priority_payload()), encoding="utf-8")
            rc = M.main(["--priorities", str(source), "--out", str(out), "--dry-run"])
            self.assertEqual(rc, 0)
            self.assertFalse(out.exists())

    # -----------------------------------------------------------------------
    # Lane 2: source-completeness envelope - 8 required fields always present
    # -----------------------------------------------------------------------

    LANE2_FIELDS = [
        "source_state",
        "source_artifacts_complete",
        "source_refs",
        "quality_state",
        "external_recall_quality",
        "next_source_action",
        "provider_allowed",
        "provider_block_reason",
    ]

    def test_lane2_all_8_fields_present_on_every_row(self) -> None:
        """Every emitted row must carry all 8 source-completeness fields."""
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            source = root / "priorities.json"
            source.write_text(json.dumps(_priority_payload()), encoding="utf-8")
            payload, digest = M.load_priorities(source)
            rows = M.build_rows(
                payload,
                source_path=source,
                source_sha256=digest,
                top_n=10,
                include_taxonomy=True,
            )
        self.assertGreater(len(rows), 0)
        for row in rows:
            for field in self.LANE2_FIELDS:
                self.assertIn(
                    field,
                    row,
                    msg=f"Row {row.get('queue_id')} missing Lane 2 field '{field}'",
                )

    def test_lane2_source_incomplete_row_is_provider_blocked(self) -> None:
        """A row with no source artifacts must be provider_allowed=False and
        next_source_action='mine-source'."""
        payload = copy.deepcopy(_priority_payload())
        priority = payload["priorities"][0]
        # miss_example has no source_path, no source_artifacts that resolve
        priority["miss_examples"] = [
            {
                "slug": "no-artifact-example",
                "source": "internal-only",
                "sample_origin": "internal_fixture",
                "own_detector_fired": True,
                "independent_any_fired": True,
            }
        ]
        priority["next_tasks"] = [
            {
                "task_type": "detector-generalization",
                "summary": "Generalize from visible own-class evidence.",
            }
        ]
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            source = root / "priorities.json"
            source.write_text(json.dumps(payload), encoding="utf-8")
            parsed, digest = M.load_priorities(source)
            rows = M.build_rows(
                parsed,
                source_path=source,
                source_sha256=digest,
                top_n=10,
                include_taxonomy=False,
            )
            summary = M.build_summary(
                rows=rows,
                source_path=source,
                source_sha256=digest,
                out_path=root / "queue.jsonl",
                dry_run=True,
            )

        self.assertEqual(len(rows), 1)
        row = rows[0]
        self.assertFalse(row["provider_allowed"])
        self.assertEqual(row["next_source_action"], "mine-source")
        self.assertFalse(row["source_artifacts_complete"])
        self.assertEqual(row["source_refs"], [])
        self.assertNotEqual(row["provider_block_reason"], "")
        self.assertEqual(summary["provider_allowed_rows"], 0)
        self.assertEqual(summary["provider_blocked_rows"], 1)
        self.assertIn("mine-source", summary["by_next_source_action"])

    def test_lane2_source_complete_row_is_provider_allowed(self) -> None:
        """A row where every miss example has a resolved source artifact must be
        provider_allowed=True and next_source_action='none'."""
        payload = copy.deepcopy(_priority_payload())
        priority = payload["priorities"][0]
        priority["miss_examples"][0]["own_detector_fired"] = True
        priority["next_tasks"] = [
            {
                "task_type": "detector-generalization",
                "summary": "Generalize bridge proof detector from visible own-class evidence.",
            }
        ]
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            sample = root / "BeefyClient.sol"
            sample.write_text("contract BeefyClient {}\n", encoding="utf-8")
            priority["miss_examples"][0]["source_path"] = str(sample)
            source = root / "priorities.json"
            source.write_text(json.dumps(payload), encoding="utf-8")
            parsed, digest = M.load_priorities(source)
            rows = M.build_rows(
                parsed,
                source_path=source,
                source_sha256=digest,
                top_n=10,
                include_taxonomy=False,
            )
            summary = M.build_summary(
                rows=rows,
                source_path=source,
                source_sha256=digest,
                out_path=root / "queue.jsonl",
                dry_run=True,
            )

        self.assertEqual(len(rows), 1)
        row = rows[0]
        self.assertTrue(row["provider_allowed"])
        self.assertEqual(row["next_source_action"], "none")
        self.assertTrue(row["source_artifacts_complete"])
        self.assertGreater(len(row["source_refs"]), 0)
        self.assertEqual(row["provider_block_reason"], "")
        self.assertEqual(summary["provider_allowed_rows"], 1)
        self.assertEqual(summary["provider_blocked_rows"], 0)
        self.assertIn("none", summary["by_next_source_action"])

    def test_lane2_no_source_artifact_justification_allows_provider(self) -> None:
        """A row whose example has source_state='NO_SOURCE_ARTIFACT' must be
        provider_allowed=True even without a resolved source artifact file."""
        payload = copy.deepcopy(_priority_payload())
        priority = payload["priorities"][0]
        priority["miss_examples"] = [
            {
                "slug": "redacted-proprietary-example",
                "source": "proprietary",
                "sample_origin": "external_repo",
                "own_detector_fired": True,
                "independent_any_fired": True,
                # Explicit operator override: source artifact cannot exist.
                "source_state": "NO_SOURCE_ARTIFACT:redacted-proprietary-code",
            }
        ]
        priority["next_tasks"] = [
            {
                "task_type": "detector-generalization",
                "summary": "Generalize from documented proprietary example.",
            }
        ]
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            source = root / "priorities.json"
            source.write_text(json.dumps(payload), encoding="utf-8")
            parsed, digest = M.load_priorities(source)
            rows = M.build_rows(
                parsed,
                source_path=source,
                source_sha256=digest,
                top_n=10,
                include_taxonomy=False,
            )

        self.assertEqual(len(rows), 1)
        row = rows[0]
        self.assertTrue(row["provider_allowed"])
        self.assertEqual(row["next_source_action"], "none")
        self.assertTrue(row["source_artifacts_complete"])
        self.assertEqual(row["provider_block_reason"], "")

    def test_lane2_quality_blocked_row_is_provider_blocked(self) -> None:
        """A quality-blocked row must be provider_allowed=False regardless of
        source artifact presence."""
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            source = root / "priorities.json"
            quality = root / "quality.json"
            source.write_text(json.dumps(_priority_payload()), encoding="utf-8")
            quality.write_text(
                json.dumps(
                    {
                        "schema": M.QUALITY_SCHEMA,
                        "generated_at": "2026-05-17T00:01:00Z",
                        "manifest_path": str(root / "manifest.json"),
                        "manifest_sha256": "abc",
                        "manifest_errors": [],
                        "rows": [
                            {
                                "id": "snowbridge/contracts/BeefyClient.sol",
                                "attack_class": "bridge-proof-domain-bypass",
                                "quality_state": "disqualified_source_state",
                                "source_state": "fixed_post_fix",
                                "gap_prioritization_eligible": False,
                            }
                        ],
                    }
                ),
                encoding="utf-8",
            )
            quality_by_attack, _ = M.load_quality_reports([quality])
            payload, digest = M.load_priorities(source)
            rows = M.build_rows(
                payload,
                source_path=source,
                source_sha256=digest,
                top_n=10,
                include_taxonomy=False,
                quality_by_attack_class=quality_by_attack,
            )
            summary = M.build_summary(
                rows=rows,
                source_path=source,
                source_sha256=digest,
                out_path=root / "queue.jsonl",
                dry_run=True,
            )

        # Both tasks for the attack class must be provider-blocked.
        self.assertTrue(all(not row["provider_allowed"] for row in rows))
        self.assertTrue(all(row["next_source_action"] == "mine-source" for row in rows))
        self.assertTrue(all("quality_blocked" in row["provider_block_reason"] for row in rows))
        self.assertEqual(summary["provider_allowed_rows"], 0)
        self.assertEqual(summary["provider_blocked_rows"], len(rows))

    def test_lane2_summary_has_provider_gate_fields(self) -> None:
        """build_summary must emit provider_allowed_rows, provider_blocked_rows,
        by_next_source_action, and by_provider_block_reason."""
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            source = root / "priorities.json"
            source.write_text(json.dumps(_priority_payload()), encoding="utf-8")
            payload, digest = M.load_priorities(source)
            rows = M.build_rows(
                payload,
                source_path=source,
                source_sha256=digest,
                top_n=10,
                include_taxonomy=False,
            )
            summary = M.build_summary(
                rows=rows,
                source_path=source,
                source_sha256=digest,
                out_path=root / "queue.jsonl",
                dry_run=True,
            )

        self.assertIn("provider_allowed_rows", summary)
        self.assertIn("provider_blocked_rows", summary)
        self.assertIn("by_next_source_action", summary)
        self.assertIn("by_provider_block_reason", summary)
        # No row-ready-lacking-source invariant: provider_allowed + provider_blocked == total
        self.assertEqual(
            summary["provider_allowed_rows"] + summary["provider_blocked_rows"],
            summary["rows_built"],
        )

    def test_lane2_done_condition_no_provider_ready_row_lacks_source_metadata(self) -> None:
        """Plan done condition: no row marked provider_allowed=True may lack all
        8 source-completeness fields or have empty source_refs without the
        NO_SOURCE_ARTIFACT justification."""
        payload = copy.deepcopy(_priority_payload())
        priority = payload["priorities"][0]
        priority["miss_examples"][0]["own_detector_fired"] = True
        priority["next_tasks"] = [
            {
                "task_type": "detector-generalization",
                "summary": "Generalize with own-class evidence.",
            }
        ]
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            sample = root / "Artifact.sol"
            sample.write_text("contract Artifact {}\n", encoding="utf-8")
            priority["miss_examples"][0]["source_path"] = str(sample)
            source = root / "priorities.json"
            source.write_text(json.dumps(payload), encoding="utf-8")
            parsed, digest = M.load_priorities(source)
            rows = M.build_rows(
                parsed,
                source_path=source,
                source_sha256=digest,
                top_n=10,
                include_taxonomy=False,
            )

        provider_ready = [row for row in rows if row.get("provider_allowed")]
        for row in provider_ready:
            # All 8 fields must be present.
            for field in self.LANE2_FIELDS:
                self.assertIn(field, row, msg=f"provider_allowed row missing '{field}'")
            # source_refs must be non-empty unless NO_SOURCE_ARTIFACT justification present.
            has_justification = any(
                "NO_SOURCE_ARTIFACT" in str(ex.get("source_state", "")).upper()
                for ex in row.get("candidate_miss_examples", [])
            )
            if not has_justification:
                self.assertGreater(
                    len(row["source_refs"]),
                    0,
                    msg="provider_allowed row has empty source_refs with no NO_SOURCE_ARTIFACT justification",
                )
            # next_source_action must be 'none' for provider-ready rows.
            self.assertEqual(row["next_source_action"], "none")
            # provider_block_reason must be empty.
            self.assertEqual(row["provider_block_reason"], "")


if __name__ == "__main__":
    unittest.main()
