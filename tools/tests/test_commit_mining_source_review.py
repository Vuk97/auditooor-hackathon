#!/usr/bin/env python3
from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
TOOL = ROOT / "tools" / "commit-mining-source-review.py"


def load_tool():
    spec = importlib.util.spec_from_file_location("commit_mining_source_review", TOOL)
    mod = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    sys.modules[spec.name] = mod
    spec.loader.exec_module(mod)
    return mod


def write(path: Path, text: str) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    return path


def git(cwd: Path, *args: str) -> str:
    proc = subprocess.run(
        ["git", "-C", str(cwd), *args],
        capture_output=True,
        text=True,
        check=True,
    )
    return proc.stdout.strip()


def make_git_repo(root: Path) -> tuple[Path, str]:
    source = root / "source"
    source.mkdir()
    git(source, "init", "-q")
    git(source, "config", "user.email", "auditooor@example.test")
    git(source, "config", "user.name", "Auditooor Test")
    git(source, "remote", "add", "origin", "https://github.com/base/base.git")
    write(source / "consensus" / "withdrawals.go", "package consensus\n\nfunc Root() string { return \"old\" }\n")
    git(source, "add", ".")
    git(source, "commit", "-q", "-m", "consensus withdrawal root seed")
    commit = git(source, "rev-parse", "HEAD")
    return source, commit


def scan_task(source: Path, commit: str, *, verified: bool = True) -> dict:
    return {
        "schema": "auditooor.commit_mining_scan_task.v1",
        "task_id": "scan-task-BA-HIST-01",
        "source_row_id": "BA-HIST-01",
        "target": "Base Azul",
        "repo_identity": "github.com/base/base",
        "commit_sha": commit,
        "git_root": str(source),
        "review_objective": "Inspect this verified local source ref for reusable source-review leads.",
        "terminal_state_options": ["source_review_lead_recorded", "needs_separate_impact_proof"],
        "source_mirror_verify": {
            "status": "verified" if verified else "missing",
            "ref_verified": verified,
            "git_root": str(source),
            "matched_repo_identity": "github.com/base/base",
        },
    }


class CommitMiningSourceReviewTest(unittest.TestCase):
    def test_build_report_emits_source_review_packet_from_local_git_stats(self) -> None:
        mod = load_tool()
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            source, commit = make_git_repo(root)
            payload = {
                "schema": "auditooor.commit_mining_scan_tasks.v1",
                "generated_at_utc": "2026-05-05T18:36:58+00:00",
                "tasks": [scan_task(source, commit)],
            }

            report = mod.build_report(payload, root, input_path=root / "reports" / "commit_mining_scan_tasks_2026-05-05.json")

            self.assertFalse(report["network_used"])
            self.assertFalse(report["exploit_proof"])
            self.assertEqual(report["generated_at_utc"], "2026-05-05T18:36:58+00:00")
            self.assertEqual(report["submission_posture"], "NOT_SUBMIT_READY")
            self.assertEqual(report["summary"]["input_task_count"], 1)
            self.assertEqual(report["summary"]["packets_emitted"], 1)
            self.assertEqual(report["summary"]["advisory_packets_emitted"], 1)
            self.assertEqual(report["summary"]["blocked_task_count"], 0)
            packet = report["source_review_packets"][0]
            self.assertEqual(packet["status"], "source_review_packet_emitted")
            self.assertEqual(packet["severity_claim"], "")
            self.assertEqual(packet["exploitability_claim"], "")
            self.assertEqual(packet["impact_claim"], "")
            self.assertEqual(packet["submission_posture"], "NOT_SUBMIT_READY")
            self.assertEqual(packet["commit_metadata"]["subject"], "consensus withdrawal root seed")
            self.assertEqual(packet["diff_stats"]["changed_file_count"], 1)
            self.assertEqual(packet["diff_stats"]["extension_counts"][".go"], 1)
            self.assertNotIn("head", packet["local_git"])
            self.assertNotIn("remote_lines", packet["local_git"])
            self.assertIn("single_file_patch", packet["source_review_packet"]["scope_flags"])
            self.assertIn("consensus_or_fork_logic", packet["source_review_packet"]["review_focus"])
            self.assertIn("consensus/withdrawals.go", packet["source_review_packet"]["primary_files"])

    def test_missing_local_commit_is_blocked_not_packetized(self) -> None:
        mod = load_tool()
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            source, _commit = make_git_repo(root)
            missing = "f" * 40
            payload = {"schema": "auditooor.commit_mining_scan_tasks.v1", "tasks": [scan_task(source, missing)]}

            report = mod.build_report(payload, root)

            self.assertEqual(report["summary"]["packets_emitted"], 0)
            self.assertEqual(report["summary"]["blocked_task_count"], 1)
            self.assertEqual(report["summary"]["blocker_counts"]["commit_not_available_locally"], 1)
            self.assertEqual(report["source_review_packets"][0]["status"], "blocked")
            self.assertEqual(report["source_review_packets"][0]["submission_posture"], "NOT_SUBMIT_READY")

    def test_unverified_task_is_blocked_before_git_review(self) -> None:
        mod = load_tool()
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            source, commit = make_git_repo(root)
            payload = {"schema": "auditooor.commit_mining_scan_tasks.v1", "tasks": [scan_task(source, commit, verified=False)]}

            report = mod.build_report(payload, root)

            self.assertEqual(report["summary"]["packets_emitted"], 0)
            self.assertEqual(report["summary"]["blocker_counts"]["source_mirror_not_verified"], 1)

    def test_build_report_is_deterministic_and_sorts_tasks(self) -> None:
        mod = load_tool()
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            source, commit = make_git_repo(root)
            a_task = dict(scan_task(source, commit))
            z_task = dict(scan_task(source, commit))
            a_task["task_id"] = "scan-task-A"
            z_task["task_id"] = "scan-task-Z"
            payload = {
                "schema": "auditooor.commit_mining_scan_tasks.v1",
                "date": "2026-05-05",
                "tasks": [z_task, a_task],
            }

            first = mod.build_report(payload, root, input_path=root / "reports" / "commit_mining_scan_tasks_2026-05-05.json")
            second = mod.build_report(payload, root, input_path=root / "reports" / "commit_mining_scan_tasks_2026-05-05.json")

            self.assertEqual(first, second)
            self.assertEqual(first["generated_at_utc"], "2026-05-05T00:00:00+00:00")
            self.assertEqual([packet["task_id"] for packet in first["source_review_packets"]], ["scan-task-A", "scan-task-Z"])

    def test_run_git_rejects_nonlocal_subcommands(self) -> None:
        mod = load_tool()
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            source, _commit = make_git_repo(root)
            with self.assertRaises(ValueError):
                mod._run_git(source, ["fetch", "--all"])

    def test_cli_writes_json_and_markdown_outputs(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            source, commit = make_git_repo(root)
            input_report = root / "scan_tasks.json"
            output_report = root / "source_review.json"
            markdown = root / "source_review.md"
            input_report.write_text(
                json.dumps({"schema": "auditooor.commit_mining_scan_tasks.v1", "tasks": [scan_task(source, commit)]}),
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
            self.assertEqual(report["summary"]["packets_emitted"], 1)
            self.assertEqual(report["generated_at_utc"], "1970-01-01T00:00:00+00:00")
            self.assertEqual(report["submission_posture"], "NOT_SUBMIT_READY")
            self.assertIn("Commit Mining Source Review", markdown.read_text(encoding="utf-8"))
            self.assertIn("Advisory Packet Details", markdown.read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main()
