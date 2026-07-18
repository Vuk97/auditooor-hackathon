#!/usr/bin/env python3
from __future__ import annotations

import importlib.util
import json
import tempfile
import types
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
TOOL = ROOT / "tools" / "commit-lifecycle-ledger.py"


def _load_module() -> types.ModuleType:
    spec = importlib.util.spec_from_file_location("commit_lifecycle_ledger", TOOL)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


MOD = _load_module()
FULL_SHA = "a" * 40


class CommitLifecycleLedgerTest(unittest.TestCase):
    def _write_json(self, root: Path, relpath: str, payload: object) -> None:
        path = root / relpath
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(payload, indent=2), encoding="utf-8")

    def test_missing_reports_are_tolerated(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ledger = MOD.build_ledger(Path(tmp))

        self.assertEqual(ledger["summary"]["row_count"], 0)
        self.assertEqual(len(ledger["reports_missing"]), len(MOD.DEFAULT_REPORTS))
        self.assertEqual(ledger["concrete_queue"], [])
        self.assertIn("No contest_fix_mines/**/review_packets.json", ledger["coverage_limits"][-1])

    def test_expands_claimed_fix_refs_and_keeps_terminal_rows_closed(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self._write_json(
                root,
                "reports/local_corpus_commit_mining_inventory_2026-05-05.json",
                {
                    "date": "2026-05-05",
                    "project_context": {
                        "operator_snapshot": {
                            "base": "done except self-learning loop",
                        },
                        "continuation_plan_posture": {
                            "centrifuge": "unknown-reason terminal rejection memory",
                            "morpho": "unknown-reason terminal rejection memory",
                        },
                    },
                    "recommended_next_packet": [
                        "materialize rows",
                        "resolve high signal rows",
                        "fold base rows",
                        "convert ready rows into scan tasks",
                    ],
                    "returned_inventory_capability": {
                        "still_missing": [
                            "No emitted one-row-per-reference corpus artifact exists yet."
                        ]
                    },
                },
            )
            self._write_json(
                root,
                "reports/github_commit_mining_exploit_plan_2026-05-05.json",
                {
                    "date": "2026-05-05",
                    "branch": "continuation-plan",
                    "commit_lifecycle_ledger_upgrade": {
                        "proof_boundary": "Rows are routing memory only.",
                        "roadmap_integration": ["Refresh roadmap from counts."],
                    },
                },
            )
            self._write_json(
                root,
                "reports/base_audit_patch_commit_inventory_2026-05-05.json",
                {
                    "evidence_rows": [
                        {
                            "row_id": "BA-CLAIM-01",
                            "kind": "historical_claimed_fix_unresolved",
                            "target": "Base Azul historical prior-audit corpus",
                            "status": "blocked_short_sha_or_pr_only",
                            "inventory_action": "Normalize into repo/full-SHA rows before any replay or contest-fix use.",
                            "examples": [
                                {
                                    "path": "/tmp/base-claims.txt",
                                    "refs": ["abc1234", "def5678"],
                                }
                            ],
                        }
                    ]
                },
            )
            self._write_json(
                root,
                "reports/prior_commit_mining_artifacts_2026-05-05.json",
                {
                    "named_target_refs": [
                        {
                            "target": "Morpho",
                            "local_ref": "e52ab6b",
                            "classification": "legacy_fixdiff_pattern_ref",
                            "inventory_action": "Pattern already exists.",
                            "evidence_paths": ["reference/patterns.dsl/morpho.yaml"],
                        },
                        {
                            "target": "Centrifuge",
                            "local_ref": "ed0cae6e",
                            "classification": "legacy_mined_report_fixed_commit_token",
                            "inventory_action": "Needs exact repo/source replay.",
                            "evidence_paths": ["reference/patterns.dsl/centrifuge.yaml"],
                        },
                    ],
                    "local_corpus_inventory_recommendations": [
                        {
                            "lane": "contest_fix_mining.v0",
                            "required_unblockers": ["scan_tasks.json", "review_packets.json"],
                        }
                    ],
                    "stale_or_unknown": ["Contest pins are still placeholders."],
                },
            )
            self._write_json(
                root,
                "reports/source_ref_replay_manifest_plan_2026-05-05.json",
                {
                    "next_steps": [
                        {
                            "detail": "persist extracted source-ref facts before any checkout or detector replay path"
                        }
                    ]
                },
            )

            ledger = MOD.build_ledger(root)

        rows = {row["row_id"]: row for row in ledger["rows"]}
        self.assertIn("BA-CLAIM-01-01-01", rows)
        self.assertIn("BA-CLAIM-01-01-02", rows)
        self.assertEqual(rows["BA-CLAIM-01-01-01"]["ref"], "abc1234")
        self.assertEqual(rows["BA-CLAIM-01-01-01"]["lifecycle_state"], "blocked_short_or_named_ref")
        self.assertTrue(rows["BA-CLAIM-01-01-01"]["operator_reopen_required"])
        self.assertEqual(rows["e52ab6b"]["lifecycle_state"], "detectorized_or_covered")
        self.assertEqual(rows["ed0cae6e"]["downstream_lane"], "self_learning_or_no_action")
        self.assertTrue(rows["ed0cae6e"]["operator_reopen_required"])
        self.assertGreaterEqual(ledger["summary"]["queue_count"], 4)

    def test_review_packet_can_promote_to_harnessable(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self._write_json(
                root,
                "reports/base_audit_patch_commit_inventory_2026-05-05.json",
                {
                    "evidence_rows": [
                        {
                            "row_id": "ROW-1",
                            "kind": "base_owned_patch_commit",
                            "target": "Acme",
                            "repo_owner": "acme",
                            "repo_name": "vault",
                            "sha": FULL_SHA,
                            "status": "ready_full_sha_with_repo",
                            "inventory_action": "Ready for review lane.",
                        }
                    ]
                },
            )
            self._write_json(
                root,
                "contest_fix_mines/acme/review_packets.json",
                {
                    "rows": [
                        {
                            "repo": "acme/vault",
                            "commit": FULL_SHA,
                            "bucket": "high_signal_exploit_seed",
                            "proof_followon_slots": ["forge-poc"],
                            "poc_investment_allowed": False,
                        }
                    ]
                },
            )

            ledger = MOD.build_ledger(root)

        row = ledger["rows"][0]
        self.assertEqual(row["row_id"], "ROW-1")
        self.assertEqual(row["lifecycle_state"], "harnessable")
        self.assertEqual(row["downstream_lane"], "harness_or_invariant_proof")
        self.assertIn("separate local reproduction", row["next_action"])

    def test_markdown_renders_queue_and_rows(self) -> None:
        ledger = {
            "date": "2026-05-05",
            "schema": MOD.SCHEMA,
            "network_used": False,
            "summary": {
                "row_count": 1,
                "queue_count": 1,
                "state_counts": [{"name": "self_learning_only", "count": 1}],
            },
            "concrete_queue": [
                {
                    "item_id": "Q1",
                    "priority": "medium",
                    "lane": "self_learning_or_no_action",
                    "title": "Keep closed",
                    "detail": "Stay advisory only.",
                    "depends_on": [],
                    "row_ids": ["ROW-1"],
                }
            ],
            "rows": [
                {
                    "row_id": "ROW-1",
                    "lifecycle_state": "self_learning_only",
                    "repo": "acme/vault",
                    "ref": FULL_SHA,
                    "downstream_lane": "self_learning_or_no_action",
                    "operator_reopen_required": True,
                    "next_action": "Keep closed.",
                }
            ],
            "coverage_limits": ["missing corpus rows"],
            "proof_boundary": "Patch commits remain review leads only.",
        }

        rendered = MOD.render_markdown(ledger)

        self.assertIn("# Commit Lifecycle Ledger", rendered)
        self.assertIn("## Concrete Queue", rendered)
        self.assertIn("`ROW-1`", rendered)
        self.assertIn("missing corpus rows", rendered)


if __name__ == "__main__":
    unittest.main()
