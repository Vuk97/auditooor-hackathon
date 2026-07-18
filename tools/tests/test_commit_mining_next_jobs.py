#!/usr/bin/env python3
from __future__ import annotations

import importlib.util
import json
import tempfile
import types
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
TOOL = ROOT / "tools" / "commit-mining-next-jobs.py"


def _load_module() -> types.ModuleType:
    spec = importlib.util.spec_from_file_location("commit_mining_next_jobs", TOOL)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


MOD = _load_module()
FULL_SHA = "a" * 40


class CommitMiningNextJobsTest(unittest.TestCase):
    def _write_json(self, root: Path, relpath: str, payload: object) -> None:
        path = root / relpath
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(payload, indent=2), encoding="utf-8")

    def test_requires_lifecycle_ledger(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaises(FileNotFoundError):
                MOD.build_next_jobs(Path(tmp))

    def test_classifies_ready_source_blocked_and_detector_jobs(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self._write_json(
                root,
                "reports/commit_lifecycle_ledger_2026-05-05.json",
                {
                    "schema": "auditooor.commit_lifecycle_ledger.v1",
                    "proof_boundary": "Rows are routing only.",
                    "rows": [{"row_id": "ROW-READY"}, {"row_id": "ROW-SOURCE"}],
                    "concrete_queue": [
                        {
                            "item_id": "Q-wire-source-ref",
                            "priority": "high",
                            "lane": "source_review_only",
                            "title": "Materialize source refs",
                            "detail": "persist source-ref facts before checkout",
                            "row_ids": ["ROW-SOURCE"],
                            "evidence_paths": ["reports/source.json"],
                        },
                        {
                            "item_id": "Q-keep-closed",
                            "priority": "low",
                            "lane": "self_learning_or_no_action",
                            "title": "Keep closed",
                            "detail": "blocked until operator reopens",
                            "row_ids": ["ROW-CLOSED"],
                        },
                        {
                            "item_id": "Q-self-learning",
                            "priority": "low",
                            "lane": "self_learning_or_no_action",
                            "title": "Keep self-learning rows out of active exploit hunting",
                            "detail": "usable for detector calibration only",
                            "row_ids": ["ROW-CLOSED-2"],
                        },
                        {
                            "item_id": "Q-source-ref",
                            "priority": "low",
                            "lane": "source_review_only",
                            "title": "Wire source-ref persistence",
                            "detail": "persist source-ref facts before detector replay path",
                            "row_ids": [],
                        },
                    ],
                },
            )
            self._write_json(
                root,
                "reports/source_mirror_queue_2026-05-05.json",
                {
                    "queue_rows": [
                        {
                            "source_row_id": "ROW-READY",
                            "repo_url": "https://github.com/acme/vault",
                            "ref": FULL_SHA,
                            "ref_kind": "full_sha",
                            "mirror_status": "queued_for_local_mirror_verification",
                            "safe_local_command_template": "git -C mirrors/acme/vault rev-parse --verify "
                            + FULL_SHA
                            + "^{commit}",
                            "priority": "medium",
                            "target": "Acme",
                        },
                        {
                            "source_row_id": "ROW-SOURCE",
                            "ref": "abc1234",
                            "ref_kind": "short_sha",
                            "mirror_status": "blocked_missing_repo_identity",
                            "blocker": "repo identity missing",
                            "priority": "low",
                            "target": "Acme",
                        },
                    ]
                },
            )
            self._write_json(
                root,
                "reports/source_mirror_verify_2026-05-05.json",
                {
                    "results": [
                        {
                            "id": "ROW-READY",
                            "status": "verified",
                            "checks": {
                                "git_root": "/tmp/acme",
                                "matched_repo_identity": "github.com/acme/vault",
                                "ref_verified": True,
                            },
                        }
                    ]
                },
            )
            self._write_json(
                root,
                "reports/detector_proof_gap_queue_2026-05-05.json",
                {
                    "rust_lift_needed": {
                        "rows": [
                            {
                                "queue_id": "DRAFT_acme",
                                "section": "rust_lift_needed",
                                "suggested_next_action": "add runtime proof",
                                "blockers": ["source_shape_only"],
                                "detector_paths": ["detectors/rust_wave1/DRAFT_acme.py"],
                            }
                        ]
                    }
                },
            )

            report = MOD.build_next_jobs(root)

        counts = report["summary"]["class_counts"]
        self.assertEqual(counts["ready_jobs"], 1)
        self.assertEqual(counts["source_needed_jobs"], 3)
        self.assertEqual(counts["blocked_jobs"], 2)
        self.assertEqual(counts["detector_needed_jobs"], 1)
        ready = [job for job in report["jobs"] if job["job_class"] == "ready_jobs"][0]
        self.assertIn("rev-parse --verify", ready["commands"][0])
        self.assertEqual(ready["lane"], "mirror_verified_scan_task_candidate")
        self.assertEqual(ready["source_mirror_verify"]["status"], "verified")
        self.assertEqual(ready["proof_boundary"], "Rows are routing only.")

    def test_blocked_source_mirror_verify_demotes_ready_row_to_source_needed(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self._write_json(
                root,
                "reports/commit_lifecycle_ledger_2026-05-05.json",
                {"schema": "auditooor.commit_lifecycle_ledger.v1", "rows": [], "concrete_queue": []},
            )
            self._write_json(
                root,
                "reports/source_mirror_queue_2026-05-05.json",
                {
                    "queue_rows": [
                        {
                            "source_row_id": "ROW-MISSING",
                            "repo_url": "https://github.com/acme/vault",
                            "ref": FULL_SHA,
                            "mirror_status": "queued_for_local_mirror_verification",
                            "safe_local_command_template": "git -C mirrors/acme/vault rev-parse --verify "
                            + FULL_SHA
                            + "^{commit}",
                            "priority": "medium",
                        }
                    ]
                },
            )
            self._write_json(
                root,
                "reports/source_mirror_verify_2026-05-05.json",
                {
                    "results": [
                        {
                            "id": "ROW-MISSING",
                            "status": "blocked",
                            "blockers": ["ref_not_found_locally: " + FULL_SHA],
                            "checks": {"matched_repo_identity": "github.com/acme/vault", "ref_verified": False},
                        }
                    ]
                },
            )

            report = MOD.build_next_jobs(root)

        self.assertEqual(report["summary"]["class_counts"]["ready_jobs"], 0)
        self.assertEqual(report["summary"]["class_counts"]["source_needed_jobs"], 1)
        job = report["jobs"][0]
        self.assertEqual(job["lane"], "local_mirror_verification_blocked")
        self.assertIn("ref_not_found_locally", job["blocker"])

    def test_rust_coverage_adds_non_duplicate_detector_jobs(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self._write_json(
                root,
                "reports/commit_lifecycle_ledger_2026-05-05.json",
                {"schema": "auditooor.commit_lifecycle_ledger.v1", "rows": [], "concrete_queue": []},
            )
            self._write_json(
                root,
                "reports/detector_proof_gap_queue_2026-05-05.json",
                {
                    "rust_lift_needed": {
                        "rows": [{"queue_id": "DRAFT_seen", "section": "rust_lift_needed"}]
                    }
                },
            )
            self._write_json(
                root,
                "reports/rust_detector_coverage_2026-05-05.json",
                {
                    "missing_fixture": {
                        "detectors": [
                            {"detector_id": "DRAFT_seen"},
                            {
                                "detector_id": "DRAFT_new",
                                "detector_path": "detectors/rust_wave1/DRAFT_new.py",
                                "next_commands": ["make rust-fixture-detector DETECTOR=DRAFT_new"],
                            },
                        ]
                    }
                },
            )

            report = MOD.build_next_jobs(root)

        detector_ids = [job["row_ids"][0] for job in report["jobs"]]
        self.assertEqual(detector_ids.count("DRAFT_seen"), 1)
        self.assertIn("DRAFT_new", detector_ids)
        self.assertEqual(report["summary"]["class_counts"]["detector_needed_jobs"], 2)

    def test_markdown_renders_counts_and_inputs(self) -> None:
        report = {
            "proof_boundary": "Routing only.",
            "summary": {
                "job_count": 1,
                "class_counts": {
                    "ready_jobs": 1,
                    "blocked_jobs": 0,
                    "detector_needed_jobs": 0,
                    "source_needed_jobs": 0,
                },
            },
            "jobs": [
                {
                    "job_id": "ready-1",
                    "job_class": "ready_jobs",
                    "priority": "medium",
                    "title": "Verify local mirror",
                    "next_action": "Run local verification.",
                }
            ],
            "input_reports": {"commit_lifecycle_ledger": "reports/ledger.json"},
        }

        rendered = MOD.render_markdown(report)

        self.assertIn("# Commit Mining Next Jobs", rendered)
        self.assertIn("- ready_jobs: 1", rendered)
        self.assertIn("`ready-1`", rendered)
        self.assertIn("reports/ledger.json", rendered)


if __name__ == "__main__":
    unittest.main()
