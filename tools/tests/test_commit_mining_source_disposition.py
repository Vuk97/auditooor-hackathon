#!/usr/bin/env python3
from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
import tempfile
import types
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
TOOL = ROOT / "tools" / "commit-mining-source-disposition.py"


def _load_module() -> types.ModuleType:
    spec = importlib.util.spec_from_file_location("commit_mining_source_disposition", TOOL)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


MOD = _load_module()


def packet(
    task_id: str,
    *,
    subject: str,
    changed_files: int,
    focus: list[str],
    flags: list[str],
    files: list[str],
    directories: list[str],
    status: str = "source_review_packet_emitted",
) -> dict:
    return {
        "task_id": task_id,
        "source_row_id": task_id.replace("scan-task-", ""),
        "target": "Base Azul",
        "repo_identity": "github.com/base/base",
        "commit_sha": "a" * 40,
        "status": status,
        "blockers": [] if status == "source_review_packet_emitted" else [{"code": "source_mirror_not_verified"}],
        "commit_metadata": {"subject": subject},
        "diff_stats": {"changed_file_count": changed_files},
        "source_review_packet": {
            "summary": "advisory source-review packet",
            "review_focus": focus,
            "scope_flags": flags,
            "primary_files": files,
            "primary_directories": directories,
        },
    }


def next_step_packet(
    *,
    source_row_id: str,
    task_id: str,
    disposition_id: str,
    commit_sha: str,
    action_type: str,
) -> dict:
    return {
        "schema": "auditooor.commit_mining_next_step_packet.v1",
        "generated_at_utc": "2026-05-06T00:00:00+00:00",
        "advisory_only": True,
        "source_review_only": True,
        "network_used": False,
        "selected_row": {
            "source_row_id": source_row_id,
            "task_id": task_id,
            "disposition_id": disposition_id,
            "commit_sha": commit_sha,
            "action_type": action_type,
        },
    }


def _git(repo: Path, *args: str) -> str:
    result = subprocess.run(
        ["git", "-C", str(repo), *args],
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode != 0:
        raise AssertionError(result.stderr or result.stdout)
    return result.stdout.strip()


def _commit(repo: Path, message: str) -> str:
    _git(repo, "add", ".")
    _git(
        repo,
        "-c",
        "user.name=Codex Test",
        "-c",
        "user.email=codex@example.invalid",
        "commit",
        "-m",
        message,
    )
    return _git(repo, "rev-parse", "HEAD")


class CommitMiningSourceDispositionTest(unittest.TestCase):
    def test_build_report_classifies_requested_review_actions(self) -> None:
        payload = {
            "schema": "auditooor.commit_mining_source_review.v1",
            "generated_at_utc": "2026-05-05T18:36:58+00:00",
            "source_review_packets": [
                packet(
                    "scan-task-BA-HIST-01",
                    subject="backport: remove server-side zk prover service code",
                    changed_files=1772,
                    focus=["consensus_or_fork_logic", "proof_or_hashing"],
                    flags=["root_or_grafted_snapshot", "broad_multi_module_change"],
                    files=[
                        "crates/client/flashblocks-node/benches/fixtures/base_mainnet_blocks.json",
                        "Cargo.lock",
                        "crates/common/chains/res/genesis/zeronet_base.json",
                        "crates/execution/trie/src/db/store.rs",
                        "crates/proof/tee/registrar/src/driver.rs",
                        "crates/consensus/protocol/src/batch/span.rs",
                    ],
                    directories=["crates/consensus", "crates/proof", "crates/execution", "crates/common"],
                ),
                packet(
                    "scan-task-BA-PATCH-01",
                    subject="fix(consensus): iterate all transactions in is_deposits_only",
                    changed_files=1,
                    focus=["consensus_or_fork_logic", "state_transition"],
                    flags=["single_file_patch"],
                    files=["crates/consensus/protocol/src/attributes.rs"],
                    directories=["crates/consensus"],
                ),
                packet(
                    "scan-task-BA-PIN-01",
                    subject="[backport] feat(zk): import prover service",
                    changed_files=67,
                    focus=["proof_or_hashing", "tests_or_fixtures"],
                    flags=["contains_binary_artifacts"],
                    files=[
                        "crates/proof/zk/db/tests/postgres_integration.rs",
                        "crates/proof/zk/service/src/backends/op_succinct/backend.rs",
                    ],
                    directories=["crates/proof", "bin/prover"],
                ),
            ],
        }

        report = MOD.build_report(payload, ROOT, input_path=ROOT / "reports" / "commit_mining_source_review_2026-05-05.json")

        self.assertTrue(report["advisory_only"])
        self.assertFalse(report["network_used"])
        self.assertEqual(report["generated_at_utc"], "2026-05-05T18:36:58+00:00")
        self.assertEqual(report["summary"]["action_counts"]["broad_import_triage"], 1)
        self.assertEqual(report["summary"]["action_counts"]["narrow_consensus_patch_review"], 1)
        self.assertEqual(report["summary"]["action_counts"]["prover_service_review"], 1)
        self.assertEqual(report["summary"]["blocked_no_op_count"], 0)
        actions = {item["task_id"]: item["action_type"] for item in report["disposition_queue"]}
        self.assertEqual(actions["scan-task-BA-HIST-01"], "broad_import_triage")
        self.assertEqual(actions["scan-task-BA-PATCH-01"], "narrow_consensus_patch_review")
        self.assertEqual(actions["scan-task-BA-PIN-01"], "prover_service_review")
        broad = [item for item in report["disposition_queue"] if item["action_type"] == "broad_import_triage"][0]
        self.assertEqual(len(broad["bounded_review"]["selected_files"]), MOD.MAX_FILES_PER_ITEM)
        self.assertEqual(len(broad["bounded_review"]["selected_directories"]), MOD.MAX_DIRECTORIES_PER_ITEM)

    def test_completed_next_step_evidence_marks_rows_done_and_keeps_queued_first(self) -> None:
        commit = "b" * 40
        payload = {
            "schema": "auditooor.commit_mining_source_review.v1",
            "generated_at_utc": "2026-05-05T18:36:58+00:00",
            "source_review_packets": [
                packet(
                    "scan-task-BA-HIST-01",
                    subject="backport: remove server-side zk prover service code",
                    changed_files=1772,
                    focus=["consensus_or_fork_logic", "proof_or_hashing"],
                    flags=["root_or_grafted_snapshot", "broad_multi_module_change"],
                    files=["crates/consensus/protocol/src/attributes.rs"],
                    directories=["crates/consensus"],
                ),
                packet(
                    "scan-task-BA-PATCH-02",
                    subject="fix(consensus): validate system config fork gates",
                    changed_files=1,
                    focus=["consensus_or_fork_logic"],
                    flags=["narrow_patch"],
                    files=["crates/consensus/protocol/src/attributes.rs"],
                    directories=["crates/consensus"],
                ),
            ],
        }
        payload["source_review_packets"][0]["commit_sha"] = commit
        evidence = [
            next_step_packet(
                source_row_id="BA-HIST-01",
                task_id="scan-task-BA-HIST-01",
                disposition_id="source-disposition-scan-task-BA-HIST-01",
                commit_sha=commit,
                action_type="broad_import_triage",
            )
        ]
        next_step_evidence = [
            MOD._next_step_evidence_from_payload(item, "reports/commit_mining_next_step_packet_2026-05-05.json")
            for item in evidence
        ]

        report = MOD.build_report(
            payload,
            ROOT,
            input_path=ROOT / "reports" / "commit_mining_source_review_2026-05-05.json",
            next_step_evidence=[item for item in next_step_evidence if item is not None],
        )

        self.assertEqual(report["summary"]["queued_actionable_count"], 1)
        self.assertEqual(report["summary"]["completed_next_step_count"], 1)
        rows = report["disposition_queue"]
        self.assertEqual(rows[0]["source_row_id"], "BA-PATCH-02")
        self.assertEqual(rows[0]["status"], "queued")
        self.assertEqual(rows[1]["source_row_id"], "BA-HIST-01")
        self.assertEqual(rows[1]["status"], "completed_next_step_emitted")
        self.assertEqual(rows[1]["priority"], "low")
        self.assertIn("completed_next_step_evidence", rows[1])

    def test_discovers_overwritten_next_step_packets_from_git_history(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            _git(root, "init")
            report_path = root / "reports" / "commit_mining_next_step_packet_2026-05-05.json"
            report_path.parent.mkdir(parents=True)
            report_path.write_text(
                json.dumps(
                    next_step_packet(
                        source_row_id="BA-PATCH-02",
                        task_id="scan-task-BA-PATCH-02",
                        disposition_id="source-disposition-scan-task-BA-PATCH-02",
                        commit_sha="c" * 40,
                        action_type="narrow_consensus_patch_review",
                    )
                ),
                encoding="utf-8",
            )
            first_commit = _commit(root, "emit BA-PATCH-02 next-step packet")
            report_path.write_text(
                json.dumps(
                    next_step_packet(
                        source_row_id="BA-PIN-01",
                        task_id="scan-task-BA-PIN-01",
                        disposition_id="source-disposition-scan-task-BA-PIN-01",
                        commit_sha="d" * 40,
                        action_type="prover_service_review",
                    )
                ),
                encoding="utf-8",
            )
            second_commit = _commit(root, "emit BA-PIN-01 next-step packet")

            evidence = MOD.discover_next_step_history(root)

        rows = {(item["source_row_id"], item["source_ref"]) for item in evidence}
        self.assertIn(
            ("BA-PATCH-02", f"{first_commit}:reports/commit_mining_next_step_packet_2026-05-05.json"),
            rows,
        )
        self.assertIn(
            ("BA-PIN-01", f"{second_commit}:reports/commit_mining_next_step_packet_2026-05-05.json"),
            rows,
        )

    def test_absent_source_review_emits_blocked_no_op(self) -> None:
        report = MOD.build_report(
            {"schema": "auditooor.commit_mining_source_review.v1"},
            ROOT,
            input_path=ROOT / "missing.json",
        )

        self.assertEqual(report["summary"]["source_packets_seen"], 0)
        self.assertEqual(report["summary"]["queue_items_emitted"], 1)
        self.assertEqual(report["summary"]["blocked_no_op_count"], 1)
        item = report["disposition_queue"][0]
        self.assertEqual(item["action_type"], "blocked_no_op")
        self.assertEqual(item["packet_status"], "absent")
        self.assertEqual(item["bounded_review"]["selected_files"], [])

    def test_blocked_packet_remains_no_op(self) -> None:
        payload = {
            "schema": "auditooor.commit_mining_source_review.v1",
            "source_review_packets": [
                packet(
                    "scan-task-BLOCKED",
                    subject="blocked",
                    changed_files=0,
                    focus=[],
                    flags=[],
                    files=[],
                    directories=[],
                    status="blocked",
                )
            ],
        }

        report = MOD.build_report(payload, ROOT)

        item = report["disposition_queue"][0]
        self.assertEqual(item["action_type"], "blocked_no_op")
        self.assertIn("source_mirror_not_verified", item["rationale"])

    def test_report_omits_claim_posture_fields(self) -> None:
        report = MOD.build_report(
            {
                "schema": "auditooor.commit_mining_source_review.v1",
                "source_review_packets": [
                    packet(
                        "scan-task-BA-PATCH-01",
                        subject="fix(consensus): iterate all transactions",
                        changed_files=1,
                        focus=["consensus_or_fork_logic"],
                        flags=["single_file_patch"],
                        files=["crates/consensus/protocol/src/attributes.rs"],
                        directories=["crates/consensus"],
                    )
                ],
            },
            ROOT,
        )

        encoded = json.dumps(report, sort_keys=True)
        for field in ("severity_claim", "impact_claim", "exploitability_claim", "submission_posture", "submit_ready"):
            self.assertNotIn(field, encoded)

    def test_cli_writes_json_and_markdown(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            input_report = root / "source_review.json"
            output_report = root / "source_disposition.json"
            markdown = root / "source_disposition.md"
            input_report.write_text(
                json.dumps(
                    {
                        "schema": "auditooor.commit_mining_source_review.v1",
                        "source_review_packets": [
                            packet(
                                "scan-task-BA-PATCH-01",
                                subject="fix(consensus): iterate all transactions",
                                changed_files=1,
                                focus=["consensus_or_fork_logic"],
                                flags=["single_file_patch"],
                                files=["crates/consensus/protocol/src/attributes.rs"],
                                directories=["crates/consensus"],
                            )
                        ],
                    }
                ),
                encoding="utf-8",
            )

            proc = subprocess.run(
                [
                    sys.executable,
                    str(TOOL),
                    "--repo",
                    str(root),
                    "--input",
                    str(input_report),
                    "--out",
                    str(output_report),
                    "--markdown-out",
                    str(markdown),
                ],
                capture_output=True,
                text=True,
                timeout=30,
            )

            self.assertEqual(proc.returncode, 0, proc.stderr)
            report = json.loads(output_report.read_text(encoding="utf-8"))
            self.assertEqual(report["summary"]["action_counts"]["narrow_consensus_patch_review"], 1)
            rendered = markdown.read_text(encoding="utf-8")
            self.assertIn("Commit Mining Source Disposition", rendered)
            self.assertIn("narrow_consensus_patch_review", rendered)


if __name__ == "__main__":
    unittest.main()
