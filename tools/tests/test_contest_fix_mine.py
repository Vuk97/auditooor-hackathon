from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
TOOL = ROOT / "tools" / "contest-fix-mine.py"


def _import():
    spec = importlib.util.spec_from_file_location("contest_fix_mine_test", str(TOOL))
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    sys.modules.setdefault(spec.name, mod)
    spec.loader.exec_module(mod)
    return mod


def _git(*args: str, cwd: Path) -> None:
    proc = subprocess.run(["git", *args], cwd=str(cwd), capture_output=True, text=True, check=False)
    if proc.returncode != 0:
        raise RuntimeError(proc.stderr)


def _write_registry(path: Path, row: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(row) + "\n", encoding="utf-8")


class ContestFixMineTests(unittest.TestCase):
    def test_builds_advisory_scan_tasks_from_keyword_fix_commit(self) -> None:
        mod = _import()
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            registry = root / "reference" / "contest_registry.jsonl"
            fetch_root = root / "contest_targets"
            repo = root / "src-repo"
            repo.mkdir()
            _git("init", cwd=repo)
            _git("config", "user.email", "test@example.com", cwd=repo)
            _git("config", "user.name", "Test User", cwd=repo)
            src = repo / "src"
            src.mkdir()
            vuln = src / "Vault.sol"
            vuln.write_text(
                "contract Vault {\n"
                "  address public owner;\n"
                "  function sweep(address to) external { }\n"
                "}\n",
                encoding="utf-8",
            )
            _git("add", ".", cwd=repo)
            _git("commit", "-m", "initial", cwd=repo)
            pre_sha = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=str(repo), text=True).strip()
            vuln.write_text(
                "contract Vault {\n"
                "  address public owner;\n"
                "  modifier onlyOwner(){require(msg.sender==owner);_;}\n"
                "  function sweep(address to) external onlyOwner { }\n"
                "}\n",
                encoding="utf-8",
            )
            _git("add", ".", cwd=repo)
            _git("commit", "-m", "security fix: restrict sweep access control", cwd=repo)
            head_sha = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=str(repo), text=True).strip()
            token = src / "Token.sol"
            token.write_text(
                "contract Token { function mint(address to, uint256 amount) external { } }\n",
                encoding="utf-8",
            )
            _git("add", ".", cwd=repo)
            _git("commit", "-m", "refactor token helper", cwd=repo)

            contest_id = "cantina-fixture-2025q1"
            row = {
                "schema": "auditooor.contest_registry.v1",
                "contest_id": contest_id,
                "platform": "cantina",
                "protocol": "Fixture",
                "target_repos": [
                    {"url": "https://github.com/example/vault-fixture", "commit_pin": pre_sha, "notes": "fixture"}
                ],
                "audit_window": {"start": "2025-01-01", "end": "2025-01-10"},
                "report_published": None,
                "report_url": None,
                "status": "completed",
                "fix_mine_status": "pending",
                "fix_mine_last_run": None,
                "findings_disclosed_count": 1,
                "fix_commits_mined": 0,
                "detectors_promoted": 0,
            }
            _write_registry(registry, row)

            fetched = fetch_root / contest_id / "vault-fixture"
            (fetched / "pre_audit").mkdir(parents=True)
            (fetched / "post_audit").mkdir(parents=True)
            _git("clone", str(repo), str(fetched / "post_audit"), cwd=root)
            _git("checkout", head_sha, cwd=fetched / "post_audit")
            _git("clone", str(repo), str(fetched / "pre_audit"), cwd=root)
            _git("checkout", pre_sha, cwd=fetched / "pre_audit")

            payload, out_root = mod.build_payload(
                contest_id=contest_id,
                registry_path=registry,
                fetch_root=fetch_root,
                output_dir=root / "out",
            )
            json_path, md_path = mod.write_outputs(payload, out_root)
            review_payload = mod.build_review_payload(payload)
            review_json_path, review_md_path = mod.write_review_outputs(review_payload, out_root)

            self.assertEqual(payload["task_count"], 1)
            task = payload["tasks"][0]
            self.assertEqual(task["commit_sha"], head_sha)
            self.assertEqual(task["evidence_class"], "advisory_fix_commit_diff")
            self.assertFalse(task["submit_ready"])
            self.assertEqual(task["severity_claim"], "")
            self.assertEqual(task["exploitability_claim"], "")
            self.assertEqual([row["path"] for row in task["changed_files"]], ["src/Vault.sol"])
            self.assertIn("access-control", task["bug_class_hints"])
            self.assertTrue(json_path.is_file())
            self.assertTrue(md_path.is_file())
            self.assertTrue(review_json_path.is_file())
            self.assertTrue(review_md_path.is_file())
            self.assertEqual(review_payload["ranked_packet_count"], 1)
            self.assertEqual(review_payload["blocked_packet_count"], 0)
            self.assertEqual(review_payload["proof_followon_count"], 1)
            packet = review_payload["review_packets"][0]
            self.assertEqual(packet["schema"], "auditooor.contest_fix_exploit_review_packet.v1")
            self.assertEqual(packet["review_verdict"], "high_signal_exploit_seed")
            self.assertEqual(packet["evidence_class"], "advisory_fix_commit_diff")
            self.assertFalse(packet["submit_ready"])
            self.assertEqual(packet["severity_claim"], "")
            self.assertIn("dedupe_key", packet["dedupe"])
            self.assertTrue(packet["dedupe"]["patch_id"])
            self.assertFalse(packet["dedupe"]["duplicate_in_run"])
            self.assertIn("required_before_poc", packet["originality_gate"])
            self.assertFalse(packet["originality_gate"]["poc_investment_allowed"])
            self.assertEqual(packet["blockers"], [])

    def test_fails_closed_on_todo_commit_pin(self) -> None:
        mod = _import()
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            registry = root / "reference" / "contest_registry.jsonl"
            _write_registry(
                registry,
                {
                    "schema": "auditooor.contest_registry.v1",
                    "contest_id": "cantina-todo",
                    "platform": "cantina",
                    "protocol": "Fixture",
                    "target_repos": [
                        {"url": "https://github.com/example/repo", "commit_pin": "<TODO_OPERATOR>", "notes": ""}
                    ],
                    "audit_window": {"start": "2025-01-01", "end": "2025-01-10"},
                    "report_published": None,
                    "report_url": None,
                    "status": "completed",
                    "fix_mine_status": "pending",
                    "fix_mine_last_run": None,
                    "findings_disclosed_count": 1,
                    "fix_commits_mined": 0,
                    "detectors_promoted": 0,
                },
            )
            with self.assertRaisesRegex(mod.ContestFixMineError, "TODO commit_pin"):
                mod.build_payload(
                    contest_id="cantina-todo",
                    registry_path=registry,
                    fetch_root=root / "contest_targets",
                    output_dir=root / "out",
                )

    def test_fails_closed_on_missing_fetched_inputs(self) -> None:
        mod = _import()
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            registry = root / "reference" / "contest_registry.jsonl"
            _write_registry(
                registry,
                {
                    "schema": "auditooor.contest_registry.v1",
                    "contest_id": "cantina-missing",
                    "platform": "cantina",
                    "protocol": "Fixture",
                    "target_repos": [
                        {"url": "https://github.com/example/repo", "commit_pin": "abc123", "notes": ""}
                    ],
                    "audit_window": {"start": "2025-01-01", "end": "2025-01-10"},
                    "report_published": None,
                    "report_url": None,
                    "status": "completed",
                    "fix_mine_status": "pending",
                    "fix_mine_last_run": None,
                    "findings_disclosed_count": 1,
                    "fix_commits_mined": 0,
                    "detectors_promoted": 0,
                },
            )
            with self.assertRaisesRegex(mod.ContestFixMineError, "missing fetched repo dir"):
                mod.build_payload(
                    contest_id="cantina-missing",
                    registry_path=registry,
                    fetch_root=root / "contest_targets",
                    output_dir=root / "out",
                )

    def test_review_payload_blocks_duplicate_patch_ids(self) -> None:
        mod = _import()
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            registry = root / "reference" / "contest_registry.jsonl"
            fetch_root = root / "contest_targets"
            repo = root / "src-repo"
            repo.mkdir()
            _git("init", cwd=repo)
            _git("config", "user.email", "test@example.com", cwd=repo)
            _git("config", "user.name", "Test User", cwd=repo)
            src = repo / "src"
            src.mkdir()
            vault = src / "Vault.sol"
            unguarded = "contract Vault {\n  function sweep(address to) external { }\n}\n"
            guarded = (
                "contract Vault {\n"
                "  modifier onlyOwner(){require(msg.sender == address(1));_;}\n"
                "  function sweep(address to) external onlyOwner { }\n"
                "}\n"
            )
            vault.write_text(unguarded, encoding="utf-8")
            _git("add", ".", cwd=repo)
            _git("commit", "-m", "initial", cwd=repo)
            pre_sha = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=str(repo), text=True).strip()
            vault.write_text(guarded, encoding="utf-8")
            _git("add", ".", cwd=repo)
            _git("commit", "-m", "security fix: restrict sweep access control", cwd=repo)
            vault.write_text(unguarded, encoding="utf-8")
            _git("add", ".", cwd=repo)
            _git("commit", "-m", "refactor sweep path", cwd=repo)
            vault.write_text(guarded, encoding="utf-8")
            _git("add", ".", cwd=repo)
            _git("commit", "-m", "security fix: restrict sweep access control again", cwd=repo)

            contest_id = "cantina-duplicate-2025q1"
            _write_registry(
                registry,
                {
                    "schema": "auditooor.contest_registry.v1",
                    "contest_id": contest_id,
                    "platform": "cantina",
                    "protocol": "Fixture",
                    "target_repos": [
                        {"url": "https://github.com/example/dupe-fixture", "commit_pin": pre_sha, "notes": ""}
                    ],
                    "audit_window": {"start": "2025-01-01", "end": "2025-01-10"},
                    "report_published": None,
                    "report_url": None,
                    "status": "completed",
                    "fix_mine_status": "pending",
                    "fix_mine_last_run": None,
                    "findings_disclosed_count": 1,
                    "fix_commits_mined": 0,
                    "detectors_promoted": 0,
                },
            )
            fetched = fetch_root / contest_id / "dupe-fixture"
            (fetched / "pre_audit").mkdir(parents=True)
            (fetched / "post_audit").mkdir(parents=True)
            _git("clone", str(repo), str(fetched / "post_audit"), cwd=root)
            _git("clone", str(repo), str(fetched / "pre_audit"), cwd=root)
            _git("checkout", pre_sha, cwd=fetched / "pre_audit")

            payload, _ = mod.build_payload(
                contest_id=contest_id,
                registry_path=registry,
                fetch_root=fetch_root,
                output_dir=root / "out",
            )
            review_payload = mod.build_review_payload(payload)

            self.assertEqual(payload["task_count"], 2)
            self.assertEqual(review_payload["ranked_packet_count"], 1)
            self.assertEqual(review_payload["blocked_packet_count"], 1)
            blocked = review_payload["blocked_packets"][0]
            self.assertIn("duplicate_patch_in_run", blocked["blockers"])
            self.assertTrue(blocked["dedupe"]["duplicate_in_run"])
            self.assertTrue(blocked["dedupe"]["duplicate_of"])

    def test_review_payload_emits_fail_closed_blocker_for_untrusted_scan_task(self) -> None:
        mod = _import()
        scan_payload = {
            "schema": "auditooor.contest_fix_mine.v1",
            "contest_id": "cantina-blocked",
            "platform": "cantina",
            "protocol": "Fixture",
            "tasks": [
                {
                    "contest_id": "cantina-blocked",
                    "repo_basename": "missing",
                    "audit_window_end_commit": "<TODO_OPERATOR>",
                    "commit_sha": "abc123",
                    "commit_subject": "security fix: add onlyOwner",
                    "changed_files": [{"path": "src/Vault.sol", "additions": 2, "deletions": 0}],
                    "bug_class_hints": ["access-control"],
                    "source_ref": str(Path("/tmp/does-not-exist/post_audit")),
                }
            ],
        }
        review_payload = mod.build_review_payload(scan_payload)

        self.assertEqual(review_payload["ranked_packet_count"], 0)
        self.assertEqual(review_payload["blocked_packet_count"], 1)
        packet = review_payload["blocked_packets"][0]
        self.assertEqual(packet["review_verdict"], "blocked_missing_local_context")
        self.assertFalse(packet["submit_ready"])
        self.assertIn("unresolved_commit_pin", packet["blockers"])
        self.assertIn("missing_pre_audit", packet["blockers"])
        self.assertIn("missing_post_audit", packet["blockers"])
        self.assertIn("dedupe_key", packet["dedupe"])
        self.assertIn("required_before_poc", packet["originality_gate"])
        self.assertFalse(packet["originality_gate"]["poc_investment_allowed"])

    def test_missing_scan_tasks_path_returns_blocker_payload(self) -> None:
        mod = _import()
        with tempfile.TemporaryDirectory() as td:
            payload = mod.load_scan_tasks(Path(td) / "missing" / "scan_tasks.json")

        self.assertEqual(payload["schema"], "auditooor.contest_fix_exploit_review.v1")
        self.assertEqual(payload["ranked_packet_count"], 0)
        self.assertEqual(payload["blocked_packet_count"], 1)
        self.assertIn("missing_scan_tasks_json", payload["blocked_packets"][0]["blockers"])


if __name__ == "__main__":
    unittest.main()
