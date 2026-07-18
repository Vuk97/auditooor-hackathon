#!/usr/bin/env python3
from __future__ import annotations

import importlib.util
import json
import tempfile
import types
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
TOOL = ROOT / "tools" / "source-mirror-queue.py"
FULL_SHA = "a" * 40


def _load_module() -> types.ModuleType:
    spec = importlib.util.spec_from_file_location("source_mirror_queue", TOOL)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


MOD = _load_module()


class SourceMirrorQueueTest(unittest.TestCase):
    def _write_json(self, root: Path, relpath: str, payload: object) -> None:
        path = root / relpath
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(payload, indent=2), encoding="utf-8")

    def test_missing_reports_are_tolerated(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            report = MOD.build_queue(Path(tmp))

        self.assertEqual(report["summary"]["row_count"], 0)
        self.assertEqual(len(report["reports_missing"]), len(MOD.DEFAULT_REPORTS))
        self.assertEqual(report["queue_rows"], [])

    def test_full_sha_rows_are_queued_but_short_and_named_refs_are_blocked(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self._write_json(
                root,
                "reports/source_ref_replay_manifest_plan_2026-05-05.json",
                {
                    "remaining_limits": [
                        {
                            "limit": "no_network_resolver",
                            "detail": "branch, tag, and short-SHA resolution must remain local-only",
                        }
                    ]
                },
            )
            self._write_json(
                root,
                "reports/local_corpus_commit_mining_inventory_2026-05-05.json",
                {
                    "corpus_reference_counts": [
                        {
                            "corpus": "reference/corpus_txt/hexens",
                            "strict_github_commit_urls": 2,
                        }
                    ]
                },
            )
            self._write_json(
                root,
                "reports/commit_lifecycle_ledger_2026-05-05.json",
                {
                    "rows": [
                        {
                            "row_id": "READY-1",
                            "repo": "acme/vault",
                            "ref": FULL_SHA,
                            "commit": FULL_SHA,
                            "ref_type": "commit",
                            "lifecycle_state": "ready_full_sha_needs_mirror",
                            "target": "Acme",
                            "evidence_paths": ["reports/base.json"],
                        },
                        {
                            "row_id": "BLOCK-SHORT",
                            "repo": "acme/vault",
                            "ref": "abc1234",
                            "commit": None,
                            "ref_type": "short_sha",
                            "lifecycle_state": "blocked_short_or_named_ref",
                            "target": "Acme",
                        },
                        {
                            "row_id": "BLOCK-NAMED",
                            "repo": "acme/vault",
                            "ref": "release/v1",
                            "commit": None,
                            "ref_type": "named_ref",
                            "lifecycle_state": "blocked_short_or_named_ref",
                            "target": "Acme",
                        },
                        {
                            "row_id": "BLOCK-MISSING-REPO",
                            "repo": None,
                            "ref": "deadbee",
                            "commit": None,
                            "ref_type": "short_sha",
                            "lifecycle_state": "blocked_short_or_named_ref",
                            "target": "Unknown",
                        },
                    ]
                },
            )

            report = MOD.build_queue(root)

        rows = {row["source_row_id"]: row for row in report["queue_rows"]}
        self.assertEqual(rows["READY-1"]["mirror_status"], MOD.QUEUE_READY)
        self.assertEqual(rows["READY-1"]["required_resolution"], "local_mirror_verification")
        self.assertIn(FULL_SHA, rows["READY-1"]["safe_local_command_template"])
        self.assertEqual(rows["READY-1"]["priority"], "high")

        self.assertEqual(rows["BLOCK-SHORT"]["mirror_status"], MOD.QUEUE_BLOCKED)
        self.assertEqual(rows["BLOCK-SHORT"]["required_resolution"], "expand_to_full_sha_lockfile")
        self.assertIn("40-character commit", rows["BLOCK-SHORT"]["blocker"])

        self.assertEqual(rows["BLOCK-NAMED"]["mirror_status"], MOD.QUEUE_BLOCKED)
        self.assertEqual(
            rows["BLOCK-NAMED"]["required_resolution"],
            "pin_named_ref_to_full_sha_lockfile",
        )
        self.assertIn("mutable", rows["BLOCK-NAMED"]["blocker"])

        self.assertEqual(rows["BLOCK-MISSING-REPO"]["mirror_status"], MOD.QUEUE_BLOCKED_MISSING_REPO)
        self.assertEqual(
            rows["BLOCK-MISSING-REPO"]["required_resolution"],
            "attach_repo_identity_and_expand_to_full_sha",
        )
        self.assertEqual(report["summary"]["ready_for_local_mirror_verification"], 1)
        self.assertEqual(report["summary"]["blocked_rows"], 3)

    def test_blob_and_tree_urls_are_normalized(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self._write_json(
                root,
                "reports/commit_lifecycle_ledger_2026-05-05.json",
                {
                    "rows": [
                        {
                            "row_id": "BLOB-1",
                            "repo": "base/base",
                            "ref": f"https://github.com/base/base/blob/{FULL_SHA}/src/lib.rs",
                            "commit": None,
                            "ref_type": "url",
                            "lifecycle_state": "context_only_scope_anchor",
                            "target": "Base",
                        },
                        {
                            "row_id": "TREE-1",
                            "repo": "base/base",
                            "ref": "https://github.com/base/base/tree/v0.8.0-rc.28",
                            "commit": None,
                            "ref_type": "url",
                            "lifecycle_state": "context_only_scope_anchor",
                            "target": "Base",
                        },
                    ]
                },
            )

            report = MOD.build_queue(root)

        rows = {row["source_row_id"]: row for row in report["queue_rows"]}
        self.assertEqual(rows["BLOB-1"]["ref"], FULL_SHA)
        self.assertEqual(rows["BLOB-1"]["ref_kind"], "full_sha")
        self.assertEqual(rows["BLOB-1"]["mirror_status"], MOD.QUEUE_READY)
        self.assertEqual(rows["TREE-1"]["ref"], "v0.8.0-rc.28")
        self.assertEqual(rows["TREE-1"]["ref_kind"], "named_ref")
        self.assertEqual(rows["TREE-1"]["mirror_status"], MOD.QUEUE_BLOCKED)

    def test_markdown_renders_queue_table(self) -> None:
        report = {
            "schema": MOD.SCHEMA,
            "repo_root": "/tmp/repo",
            "branch": "continuation-plan",
            "network_used": False,
            "proof_boundary": MOD.PROOF_BOUNDARY,
            "reports_found": ["commit_lifecycle"],
            "reports_missing": ["local_corpus", "source_ref_plan"],
            "summary": {
                "row_count": 1,
                "ready_for_local_mirror_verification": 1,
                "blocked_rows": 0,
                "mirror_status_counts": [{"name": MOD.QUEUE_READY, "count": 1}],
                "ref_kind_counts": [{"name": "full_sha", "count": 1}],
            },
            "queue_rows": [
                {
                    "source_row_id": "ROW-1",
                    "repo_url": "https://github.com/acme/vault",
                    "ref": FULL_SHA,
                    "ref_kind": "full_sha",
                    "required_resolution": "local_mirror_verification",
                    "mirror_status": MOD.QUEUE_READY,
                    "safe_local_command_template": "git -C {mirror_root}/acme/vault rev-parse --verify ref^{commit}",
                    "blocker": None,
                    "priority": "high",
                }
            ],
        }

        markdown = MOD.render_markdown(report)

        self.assertIn("# Source Mirror Queue - 2026-05-05", markdown)
        self.assertIn("https://github.com/acme/vault", markdown)
        self.assertIn("local_mirror_verification", markdown)


if __name__ == "__main__":
    unittest.main()
