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
TOOL = ROOT / "tools" / "commit-mining-next-step-runner.py"


def _load_module() -> types.ModuleType:
    spec = importlib.util.spec_from_file_location("commit_mining_next_step_runner", TOOL)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


MOD = _load_module()


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


def _make_repo(root: Path) -> tuple[Path, str, str]:
    repo = root / "mirror" / "base"
    repo.mkdir(parents=True)
    _git(repo, "init")
    target = repo / "crates" / "consensus" / "protocol" / "src" / "attributes.rs"
    target.parent.mkdir(parents=True)
    target.write_text("pub const BEFORE: u64 = 1;\n", encoding="utf-8")
    parent = _commit(repo, "initial")
    target.write_text(
        "pub const BEFORE: u64 = 1;\npub const AFTER: u64 = 2;\n",
        encoding="utf-8",
    )
    commit = _commit(repo, "consensus attributes patch")
    return repo, parent, commit


def _disposition_payload(commit: str) -> dict[str, object]:
    return {
        "schema": "auditooor.commit_mining_source_disposition.v1",
        "advisory_only": True,
        "disallowed_claims": [
            "exploitability finding",
            "severity finding",
            "impact finding",
            "detector promotion finding",
            "submission readiness finding",
        ],
        "disposition_queue": [
            {
                "action_type": "broad_import_triage",
                "bounded_review": {
                    "max_directories": 3,
                    "max_files": 5,
                    "review_focus": [
                        "consensus_or_fork_logic",
                        "state_transition",
                        "proof_or_hashing",
                    ],
                    "selected_directories": ["crates/consensus"],
                    "selected_files": [
                        "crates/consensus/protocol/src/attributes.rs",
                    ],
                },
                "commit_sha": commit,
                "commit_short": commit[:12],
                "disposition_id": "source-disposition-scan-task-BA-HIST-01",
                "lane": "source_review_broad_import",
                "next_action": "Triage only the bounded directories and hotspot files.",
                "priority": "medium",
                "queue_index": 1,
                "rationale": "Source review spans a root or grafted snapshot.",
                "repo_identity": "github.com/base/base",
                "source_review_summary": "Broad advisory packet.",
                "source_row_id": "BA-HIST-01",
                "status": "queued",
                "target": "Base Azul",
                "task_id": "scan-task-BA-HIST-01",
            },
            {
                "action_type": "narrow_consensus_patch_review",
                "bounded_review": {
                    "max_directories": 3,
                    "max_files": 5,
                    "review_focus": ["consensus_or_fork_logic", "state_transition"],
                    "selected_directories": ["crates/consensus"],
                    "selected_files": [
                        "crates/consensus/protocol/src/attributes.rs",
                    ],
                },
                "commit_sha": commit,
                "commit_short": commit[:12],
                "disposition_id": "source-disposition-scan-task-BA-PATCH-01",
                "lane": "source_review_consensus_patch",
                "next_action": "Review the bounded consensus patch files.",
                "priority": "medium",
                "queue_index": 2,
                "rationale": "Source review is a narrow consensus-facing patch.",
                "repo_identity": "github.com/base/base",
                "source_review_summary": "Single-file advisory patch.",
                "source_row_id": "BA-PATCH-01",
                "status": "queued",
                "target": "Base Azul",
                "task_id": "scan-task-BA-PATCH-01",
            },
        ],
    }


def _write_disposition(path: Path, commit: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(_disposition_payload(commit)), encoding="utf-8")


class BuildPacketTests(unittest.TestCase):
    def test_builds_bounded_source_review_packet_for_first_narrow_row(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            repo, parent, commit = _make_repo(root)
            disposition = root / "reports" / "commit_mining_source_disposition_2026-05-05.json"
            _write_disposition(disposition, commit)

            packet = MOD.build_packet(input_path=disposition, git_root=repo)

        self.assertEqual(packet["schema"], "auditooor.commit_mining_next_step_packet.v1")
        self.assertFalse(packet["network_used"])
        self.assertTrue(packet["advisory_only"])
        self.assertTrue(packet["source_review_only"])
        self.assertEqual(packet["selected_row"]["source_row_id"], "BA-PATCH-01")
        self.assertEqual(packet["refs_to_inspect"]["commit"], commit)
        self.assertEqual(packet["refs_to_inspect"]["first_parent"], parent)
        self.assertEqual(
            packet["summary"],
            {
                "changed_selected_file_count": 1,
                "diff_ref": f"{parent}..{commit}",
                "existing_selected_file_count": 1,
                "review_focus": ["consensus_or_fork_logic", "state_transition"],
                "selected_action_type": "narrow_consensus_patch_review",
                "selected_file_count": 1,
                "selected_queue_index": 2,
                "selected_source_row_id": "BA-PATCH-01",
            },
        )
        self.assertEqual(
            packet["files_to_inspect"],
            [
                {
                    "path": "crates/consensus/protocol/src/attributes.rs",
                    "exists_at_commit": True,
                    "changed_in_selected_diff": True,
                    "changed_in_first_parent_diff": True,
                }
            ],
        )
        self.assertIn("exploitability finding", packet["disallowed_claims"])
        self.assertIn("allowed_source_review_claims", packet)
        self.assertNotIn("allowed_non_exploit_claims", packet)
        self.assertTrue(
            any("separate proof packet" in claim for claim in packet["allowed_source_review_claims"])
        )

    def test_specific_source_row_selector_fails_closed_when_missing(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            repo, _, commit = _make_repo(root)
            disposition = root / "reports" / "commit_mining_source_disposition_2026-05-05.json"
            _write_disposition(disposition, commit)

            with self.assertRaises(MOD.PacketError):
                MOD.build_packet(
                    input_path=disposition,
                    git_root=repo,
                    source_row_id="BA-PATCH-DOES-NOT-EXIST",
                )

    def test_specific_source_row_selector_accepts_broad_import_row(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            repo, parent, _commit = _make_repo(root)
            disposition = root / "reports" / "commit_mining_source_disposition_2026-05-05.json"
            _write_disposition(disposition, parent)

            packet = MOD.build_packet(
                input_path=disposition,
                git_root=repo,
                source_row_id="BA-HIST-01",
            )

        self.assertEqual(packet["selected_row"]["source_row_id"], "BA-HIST-01")
        self.assertEqual(packet["selected_row"]["action_type"], "broad_import_triage")
        self.assertEqual(packet["refs_to_inspect"]["commit"], parent)
        self.assertIsNone(packet["refs_to_inspect"]["first_parent"])
        self.assertEqual(packet["summary"]["changed_selected_file_count"], 1)
        self.assertEqual(packet["summary"]["diff_ref"], parent)
        self.assertEqual(packet["local_mirror"]["diff_kind"], "root_or_grafted_snapshot")
        self.assertTrue(packet["files_to_inspect"][0]["changed_in_selected_diff"])
        self.assertFalse(packet["files_to_inspect"][0]["changed_in_first_parent_diff"])
        self.assertTrue(
            any("root or grafted snapshot" in claim for claim in packet["allowed_source_review_claims"])
        )
        self.assertTrue(
            any(
                "show --format= --name-status --no-renames" in command
                for command in packet["commands_run_or_replayable"]
            )
        )

    def test_rejects_reports_without_advisory_boundary(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            repo, _, commit = _make_repo(root)
            disposition = root / "reports" / "commit_mining_source_disposition_2026-05-05.json"
            payload = _disposition_payload(commit)
            payload["advisory_only"] = False
            disposition.parent.mkdir(parents=True, exist_ok=True)
            disposition.write_text(json.dumps(payload), encoding="utf-8")

            with self.assertRaises(MOD.PacketError):
                MOD.build_packet(input_path=disposition, git_root=repo)

    def test_rejects_rows_that_exceed_bounded_file_limit(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            repo, _, commit = _make_repo(root)
            disposition = root / "reports" / "commit_mining_source_disposition_2026-05-05.json"
            payload = _disposition_payload(commit)
            row = payload["disposition_queue"][1]  # type: ignore[index]
            review = row["bounded_review"]  # type: ignore[index]
            review["max_files"] = 1  # type: ignore[index]
            review["selected_files"] = ["a.rs", "b.rs"]  # type: ignore[index]
            disposition.parent.mkdir(parents=True, exist_ok=True)
            disposition.write_text(json.dumps(payload), encoding="utf-8")

            with self.assertRaises(MOD.PacketError):
                MOD.build_packet(input_path=disposition, git_root=repo)


class CliTests(unittest.TestCase):
    def test_cli_writes_json_and_markdown(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            repo, _, commit = _make_repo(root)
            disposition = root / "reports" / "commit_mining_source_disposition_2026-05-05.json"
            out = root / "reports" / "packet.json"
            doc = root / "docs" / "packet.md"
            _write_disposition(disposition, commit)

            result = subprocess.run(
                [
                    sys.executable,
                    str(TOOL),
                    "--input",
                    str(disposition),
                    "--git-root",
                    str(repo),
                    "--out",
                    str(out),
                    "--doc",
                    str(doc),
                    "--json",
                ],
                capture_output=True,
                text=True,
                check=False,
            )

            self.assertEqual(result.returncode, 0, msg=result.stderr)
            payload = json.loads(result.stdout)
            self.assertEqual(payload["selected_row"]["source_row_id"], "BA-PATCH-01")
            self.assertTrue(out.is_file())
            self.assertTrue(doc.is_file())
            rendered = doc.read_text(encoding="utf-8")
            self.assertIn("Operational Summary", rendered)
            self.assertIn("- Changed in selected diff: `1`", rendered)
            self.assertIn("Allowed Source-Review Claims", rendered)

    def test_cli_returns_two_for_missing_input(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            repo, _, _ = _make_repo(root)
            result = subprocess.run(
                [
                    sys.executable,
                    str(TOOL),
                    "--input",
                    str(root / "missing.json"),
                    "--git-root",
                    str(repo),
                ],
                capture_output=True,
                text=True,
                check=False,
            )

            self.assertEqual(result.returncode, 2)
            self.assertIn("input report not found", result.stderr)


if __name__ == "__main__":
    unittest.main()
