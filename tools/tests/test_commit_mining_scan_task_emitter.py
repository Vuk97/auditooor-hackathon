#!/usr/bin/env python3
from __future__ import annotations

import importlib.util
import json
import tempfile
import types
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
TOOL = ROOT / "tools" / "commit-mining-scan-task-emitter.py"
FULL_SHA = "a" * 40
OTHER_SHA = "b" * 40


def _load_module() -> types.ModuleType:
    spec = importlib.util.spec_from_file_location("commit_mining_scan_task_emitter", TOOL)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


MOD = _load_module()


class CommitMiningScanTaskEmitterTest(unittest.TestCase):
    def _write_json(self, root: Path, relpath: str, payload: object) -> Path:
        path = root / relpath
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        return path

    def test_emits_only_jobs_verified_in_both_inputs(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            next_jobs_path = self._write_json(
                root,
                "reports/commit_mining_next_jobs_2026-05-05.json",
                {
                    "jobs": [
                        {
                            "job_id": "ready-good",
                            "job_class": "ready_jobs",
                            "lane": "mirror_verified_scan_task_candidate",
                            "row_ids": ["ROW-GOOD"],
                            "target": "Base Azul",
                            "repo": "https://github.com/base/base",
                            "ref": FULL_SHA,
                            "ref_kind": "full_sha",
                            "source_mirror_verify": {
                                "status": "verified",
                                "ref_verified": True,
                            },
                            "evidence_paths": ["reports/source.json"],
                        },
                        {
                            "job_id": "ready-blocked",
                            "job_class": "ready_jobs",
                            "lane": "mirror_verified_scan_task_candidate",
                            "row_ids": ["ROW-BLOCKED"],
                            "repo": "https://github.com/base/base",
                            "ref": OTHER_SHA,
                            "source_mirror_verify": {
                                "status": "verified",
                                "ref_verified": True,
                            },
                        },
                        {
                            "job_id": "detector-gap",
                            "job_class": "detector_needed_jobs",
                            "lane": "rust_lift_needed",
                            "row_ids": ["DRAFT-x"],
                        },
                    ]
                },
            )
            verify_path = self._write_json(
                root,
                "reports/source_mirror_verify_2026-05-05.json",
                {
                    "results": [
                        {
                            "id": "ROW-GOOD",
                            "status": "verified",
                            "blockers": [],
                            "checks": {
                                "git_root": "/tmp/base",
                                "matched_repo_identity": "github.com/base/base",
                                "ref_verified": True,
                                "refs": [FULL_SHA],
                                "resolved_ref": FULL_SHA,
                                "head": FULL_SHA,
                                "branch": "audit",
                            },
                        },
                        {
                            "id": "ROW-BLOCKED",
                            "status": "blocked",
                            "blockers": ["ref_not_found_locally"],
                            "checks": {
                                "git_root": "/tmp/base",
                                "matched_repo_identity": "github.com/base/base",
                                "ref_verified": False,
                                "refs": [OTHER_SHA],
                                "resolved_ref": None,
                            },
                        },
                    ]
                },
            )

            report = MOD.build_scan_tasks(
                repo_root=root,
                next_jobs_path=next_jobs_path,
                verify_path=verify_path,
            )

        self.assertEqual(report["summary"]["emitted_task_count"], 1)
        self.assertEqual(report["summary"]["skipped_job_count"], 2)
        task = report["tasks"][0]
        self.assertEqual(task["task_id"], "scan-task-ROW-GOOD")
        self.assertEqual(task["source_job_id"], "ready-good")
        self.assertEqual(task["repo_identity"], "github.com/base/base")
        self.assertEqual(task["git_root"], "/tmp/base")
        self.assertEqual(task["commit_sha"], FULL_SHA)
        self.assertEqual(task["evidence_paths"], ["reports/source.json"])

    def test_packet_boundaries_make_no_exploit_or_submission_claim(self) -> None:
        report = MOD.build_scan_tasks(
            repo_root=ROOT,
            next_jobs_path=ROOT / "reports/commit_mining_next_jobs_2026-05-05.json",
            verify_path=ROOT / "reports/source_mirror_verify_2026-05-05.json",
        )

        self.assertGreaterEqual(report["summary"]["emitted_task_count"], 1)
        for task in report["tasks"]:
            self.assertTrue(task["advisory_only"])
            self.assertFalse(task["submit_ready"])
            self.assertFalse(task["exploit_proof"])
            self.assertEqual(task["severity_claim"], "")
            self.assertEqual(task["exploitability_claim"], "")
            self.assertEqual(task["impact_claim"], "")
            self.assertIn("source-review scan tasks, not exploit proof", task["proof_boundary"])
            self.assertIn("severity", task["disallowed_claims"])

    def test_ref_false_in_verify_report_blocks_even_when_job_embeds_verified(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            next_jobs_path = self._write_json(
                root,
                "reports/commit_mining_next_jobs_2026-05-05.json",
                {
                    "jobs": [
                        {
                            "job_id": "ready-but-stale",
                            "job_class": "ready_jobs",
                            "lane": "mirror_verified_scan_task_candidate",
                            "row_ids": ["ROW-STALE"],
                            "ref": FULL_SHA,
                            "source_mirror_verify": {
                                "status": "verified",
                                "ref_verified": True,
                            },
                        }
                    ]
                },
            )
            verify_path = self._write_json(
                root,
                "reports/source_mirror_verify_2026-05-05.json",
                {
                    "results": [
                        {
                            "id": "ROW-STALE",
                            "status": "verified",
                            "blockers": [],
                            "checks": {
                                "git_root": "/tmp/base",
                                "matched_repo_identity": "github.com/base/base",
                                "ref_verified": False,
                                "refs": [FULL_SHA],
                                "resolved_ref": None,
                            },
                        }
                    ]
                },
            )

            report = MOD.build_scan_tasks(
                repo_root=root,
                next_jobs_path=next_jobs_path,
                verify_path=verify_path,
            )

        self.assertEqual(report["summary"]["emitted_task_count"], 0)
        self.assertEqual(report["skipped_jobs"][0]["reason"], "source_mirror_verify_ref_not_verified")

    def test_job_ref_must_match_verify_resolved_ref(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            next_jobs_path = self._write_json(
                root,
                "reports/commit_mining_next_jobs_2026-05-05.json",
                {
                    "jobs": [
                        {
                            "job_id": "ready-stale-ref",
                            "job_class": "ready_jobs",
                            "lane": "mirror_verified_scan_task_candidate",
                            "row_ids": ["ROW-DRIFT"],
                            "repo": "https://github.com/base/base",
                            "ref": OTHER_SHA,
                            "source_mirror_verify": {
                                "status": "verified",
                                "ref_verified": True,
                            },
                        }
                    ]
                },
            )
            verify_path = self._write_json(
                root,
                "reports/source_mirror_verify_2026-05-05.json",
                {
                    "results": [
                        {
                            "id": "ROW-DRIFT",
                            "status": "verified",
                            "blockers": [],
                            "checks": {
                                "git_root": "/tmp/base",
                                "matched_repo_identity": "github.com/base/base",
                                "ref_verified": True,
                                "refs": [FULL_SHA],
                                "resolved_ref": FULL_SHA,
                            },
                        }
                    ]
                },
            )

            report = MOD.build_scan_tasks(
                repo_root=root,
                next_jobs_path=next_jobs_path,
                verify_path=verify_path,
            )

        self.assertEqual(report["summary"]["emitted_task_count"], 0)
        self.assertEqual(
            report["skipped_jobs"][0]["reason"],
            "job_ref_mismatches_source_mirror_resolved_ref",
        )

    def test_original_verified_ref_emits_locked_resolved_ref(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            next_jobs_path = self._write_json(
                root,
                "reports/commit_mining_next_jobs_2026-05-05.json",
                {
                    "jobs": [
                        {
                            "job_id": "ready-short-ref",
                            "job_class": "ready_jobs",
                            "lane": "mirror_verified_scan_task_candidate",
                            "row_ids": ["ROW-SHORT"],
                            "repo": "https://github.com/base/base",
                            "ref": "release-local",
                            "source_mirror_verify": {
                                "status": "verified",
                                "ref_verified": True,
                            },
                        }
                    ]
                },
            )
            verify_path = self._write_json(
                root,
                "reports/source_mirror_verify_2026-05-05.json",
                {
                    "results": [
                        {
                            "id": "ROW-SHORT",
                            "status": "verified",
                            "blockers": [],
                            "checks": {
                                "git_root": "/tmp/base",
                                "matched_repo_identity": "github.com/base/base",
                                "ref_verified": True,
                                "refs": ["release-local"],
                                "resolved_ref": FULL_SHA,
                            },
                        }
                    ]
                },
            )

            report = MOD.build_scan_tasks(
                repo_root=root,
                next_jobs_path=next_jobs_path,
                verify_path=verify_path,
            )

        self.assertEqual(report["summary"]["emitted_task_count"], 1)
        task = report["tasks"][0]
        self.assertEqual(task["commit_sha"], FULL_SHA)
        self.assertEqual(task["source_mirror_verify"]["refs"], ["release-local"])
        self.assertEqual(task["source_mirror_verify"]["resolved_ref"], FULL_SHA)

    def test_resolved_ref_is_required_for_actionable_task(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            next_jobs_path = self._write_json(
                root,
                "reports/commit_mining_next_jobs_2026-05-05.json",
                {
                    "jobs": [
                        {
                            "job_id": "ready-unlocked-ref",
                            "job_class": "ready_jobs",
                            "lane": "mirror_verified_scan_task_candidate",
                            "row_ids": ["ROW-UNLOCKED"],
                            "repo": "https://github.com/base/base",
                            "ref": FULL_SHA,
                            "source_mirror_verify": {
                                "status": "verified",
                                "ref_verified": True,
                            },
                        }
                    ]
                },
            )
            verify_path = self._write_json(
                root,
                "reports/source_mirror_verify_2026-05-05.json",
                {
                    "results": [
                        {
                            "id": "ROW-UNLOCKED",
                            "status": "verified",
                            "blockers": [],
                            "checks": {
                                "git_root": "/tmp/base",
                                "matched_repo_identity": "github.com/base/base",
                                "ref_verified": True,
                                "refs": [FULL_SHA],
                            },
                        }
                    ]
                },
            )

            report = MOD.build_scan_tasks(
                repo_root=root,
                next_jobs_path=next_jobs_path,
                verify_path=verify_path,
            )

        self.assertEqual(report["summary"]["emitted_task_count"], 0)
        self.assertEqual(
            report["skipped_jobs"][0]["reason"],
            "source_mirror_verify_missing_resolved_ref",
        )

    def test_markdown_renders_counts_and_tasks(self) -> None:
        report = {
            "date": "2026-05-05",
            "proof_boundary": "Source-review only.",
            "summary": {
                "input_job_count": 2,
                "source_mirror_verify_result_count": 1,
                "emitted_task_count": 1,
                "skipped_job_count": 1,
            },
            "input_reports": {"commit_mining_next_jobs": "reports/jobs.json"},
            "tasks": [
                {
                    "task_id": "scan-task-ROW",
                    "repo_identity": "github.com/base/base",
                    "commit_sha": FULL_SHA,
                    "source_row_id": "ROW",
                    "git_root": "/tmp/base",
                }
            ],
        }

        rendered = MOD.render_markdown(report)

        self.assertIn("# Commit Mining Scan Tasks", rendered)
        self.assertIn("- Emitted scan tasks: 1", rendered)
        self.assertIn("scan-task-ROW", rendered)
        self.assertIn("advisory source-review task", rendered)


if __name__ == "__main__":
    unittest.main()
