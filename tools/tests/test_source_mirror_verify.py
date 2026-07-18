from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


REPO = Path(__file__).resolve().parents[2]
TOOL = REPO / "tools" / "source-mirror-verify.py"


def _load_tool():
    spec = importlib.util.spec_from_file_location("source_mirror_verify", TOOL)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


verify = _load_tool()


def _git(repo: Path, *args: str) -> None:
    proc = subprocess.run(
        ["git", "-C", str(repo), *args],
        capture_output=True,
        text=True,
        timeout=10,
    )
    if proc.returncode != 0:
        raise AssertionError(proc.stdout + proc.stderr)


def _make_repo(root: Path, name: str, remote: str) -> Path:
    repo = root / name
    repo.mkdir()
    _git(repo, "init")
    _git(repo, "remote", "add", "origin", remote)
    return repo


class SourceMirrorVerifyTest(unittest.TestCase):
    def test_cli_verifies_ready_rows_and_preserves_missing_identity_blocker(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            queue = tmp_path / "reports" / "source_mirror_queue_2026-05-05.json"
            out = tmp_path / "reports" / "source_mirror_verify_2026-05-05.json"
            alpha = _make_repo(tmp_path, "alpha", "git@github.com:acme/alpha.git")
            beta = _make_repo(tmp_path, "beta", "https://github.com/acme/beta.git")
            queue.parent.mkdir()
            queue.write_text(
                json.dumps(
                    {
                        "rows": [
                            {
                                "id": "alpha",
                                "status": "ready",
                                "repo_path": str(alpha),
                                "repo_url": "https://github.com/acme/alpha",
                            },
                            {
                                "id": "beta",
                                "queue_status": "ready",
                                "local_repo_path": str(beta),
                            },
                            {
                                "id": "missing-identity",
                                "status": "ready",
                                "blockers": ["operator_needs_repo_identity"],
                            },
                            {
                                "id": "missing-checkout",
                                "ready": True,
                                "repo_url": "github.com/acme/missing",
                                "repo_path": str(tmp_path / "missing"),
                            },
                            {
                                "id": "not-ready",
                                "status": "blocked",
                                "repo_url": "github.com/acme/ignored",
                            },
                        ]
                    },
                    indent=2,
                )
            )

            proc = subprocess.run(
                [sys.executable, str(TOOL), "--queue", str(queue), "--out", str(out)],
                cwd=REPO,
                capture_output=True,
                text=True,
                timeout=20,
            )

            self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
            self.assertIn("network", out.read_text())
            report = json.loads(out.read_text())
            self.assertEqual(report["network"], "not_used")
            self.assertEqual(
                report["counts"],
                {
                    "ready": 4,
                    "verified": 2,
                    "blocked": 2,
                    "resolved_blockers": 0,
                    "preserved_blockers": 0,
                },
            )
            statuses = {row["id"]: row for row in report["results"]}
            self.assertEqual(statuses["alpha"]["status"], "verified")
            self.assertEqual(statuses["beta"]["checks"]["repo_identity_source"], "local_git_remote")
            self.assertEqual(statuses["missing-identity"]["status"], "blocked")
            self.assertIn("operator_needs_repo_identity", statuses["missing-identity"]["blockers"])
            self.assertTrue(
                any("missing_repo_identity" in blocker for blocker in statuses["missing-identity"]["blockers"])
            )
            self.assertTrue(
                any("local_repo_unavailable" in blocker for blocker in statuses["missing-checkout"]["blockers"])
            )

    def test_remote_mismatch_blocks_without_network(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            repo = _make_repo(tmp_path, "gamma", "https://github.com/acme/gamma.git")
            row = {
                "id": "gamma",
                "status": "ready",
                "repo_path": str(repo),
                "repo_url": "https://github.com/other/gamma",
            }

            result = verify.verify_row(row, 0, tmp_path)

            self.assertEqual(result["status"], "blocked")
            self.assertTrue(any("remote_mismatch" in blocker for blocker in result["blockers"]))
            self.assertIn("github.com/acme/gamma", result["checks"]["actual_repo_identities"])

    def test_ready_rows_key_treats_all_rows_as_ready(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            repo = _make_repo(tmp_path, "delta", "https://github.com/acme/delta.git")
            rows = [{"id": "delta", "repo_path": str(repo), "repo_url": "acme/delta"}]

            report = verify.build_report(tmp_path / "queue.json", rows, "ready_rows", tmp_path)

            self.assertEqual(
                report["counts"],
                {
                    "ready": 1,
                    "verified": 1,
                    "blocked": 0,
                    "resolved_blockers": 0,
                    "preserved_blockers": 0,
                },
            )

    def test_actual_queue_rows_status_and_mirror_root_mapping(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            mirror_root = tmp_path / "mirrors"
            repo = mirror_root / "base" / "base"
            repo.mkdir(parents=True)
            _git(repo, "init")
            _git(repo, "remote", "add", "origin", "https://github.com/base/base.git")
            _git(repo, "config", "user.email", "test@example.com")
            _git(repo, "config", "user.name", "Test User")
            (repo / "README.md").write_text("test\n")
            _git(repo, "add", "README.md")
            _git(repo, "commit", "-m", "initial")
            proc = subprocess.run(
                ["git", "-C", str(repo), "rev-parse", "HEAD"],
                capture_output=True,
                text=True,
                timeout=10,
            )
            self.assertEqual(proc.returncode, 0, proc.stderr)
            head = proc.stdout.strip()
            rows = [
                {
                    "source_row_id": "BA-PATCH-01",
                    "repo_url": "https://github.com/base/base",
                    "ref": head,
                    "mirror_status": "queued_for_local_mirror_verification",
                }
            ]

            report = verify.build_report(tmp_path / "queue.json", rows, "queue_rows", tmp_path, mirror_root)

            self.assertEqual(
                report["counts"],
                {
                    "ready": 1,
                    "verified": 1,
                    "blocked": 0,
                    "resolved_blockers": 0,
                    "preserved_blockers": 0,
                },
            )
            result = report["results"][0]
            self.assertEqual(result["id"], "BA-PATCH-01")
            self.assertTrue(result["checks"]["ref_verified"])
            self.assertEqual(result["checks"]["matched_repo_identity"], "github.com/base/base")
            self.assertEqual(result["checks"]["resolved_ref"], head)

    def test_blocked_pending_resolution_rows_can_be_resolved_locally(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            repo = _make_repo(tmp_path, "epsilon", "https://github.com/acme/epsilon.git")
            _git(repo, "config", "user.email", "test@example.com")
            _git(repo, "config", "user.name", "Test User")
            (repo / "README.md").write_text("test\n")
            _git(repo, "add", "README.md")
            _git(repo, "commit", "-m", "initial")
            proc = subprocess.run(
                ["git", "-C", str(repo), "rev-parse", "HEAD"],
                capture_output=True,
                text=True,
                timeout=10,
            )
            self.assertEqual(proc.returncode, 0, proc.stderr)
            head = proc.stdout.strip()
            _git(repo, "tag", "release-local", head)
            rows = [
                {
                    "source_row_id": "short-ref",
                    "repo_url": "https://github.com/acme/epsilon",
                    "ref": head[:12],
                    "ref_kind": "short_sha",
                    "mirror_status": "blocked_pending_resolution",
                    "blocker": "short SHA is mutable until resolved",
                },
                {
                    "source_row_id": "tag-ref",
                    "repo_url": "https://github.com/acme/epsilon",
                    "ref": "release-local",
                    "ref_kind": "named_ref",
                    "mirror_status": "blocked_pending_resolution",
                    "blocker": "named ref is mutable until pinned",
                },
            ]

            report = verify.build_report(
                tmp_path / "queue.json",
                rows,
                "queue_rows",
                tmp_path,
                repo_map={"github.com/acme/epsilon": repo},
            )

        self.assertEqual(report["counts"]["ready"], 0)
        self.assertEqual(report["counts"]["resolved_blockers"], 2)
        self.assertEqual(report["counts"]["preserved_blockers"], 0)
        resolved = {row["id"]: row for row in report["resolved_blockers"]}
        self.assertEqual(resolved["short-ref"]["checks"]["resolved_ref"], head)
        self.assertEqual(resolved["tag-ref"]["checks"]["resolved_ref"], head)
        self.assertEqual(resolved["short-ref"]["original_blockers"], ["short SHA is mutable until resolved"])

    def test_non_ready_missing_identity_blockers_are_preserved(self) -> None:
        rows = [
            {
                "source_row_id": "blocked-short",
                "mirror_status": "blocked_missing_repo_identity",
                "blocker": "repo identity missing; cannot verify or lock the source ref locally",
                "ref": "abc1234",
                "ref_kind": "short_sha",
                "target": "Example",
                "evidence_paths": ["reference/example.md"],
            }
        ]

        report = verify.build_report(Path("queue.json"), rows, "queue_rows", Path.cwd())

        self.assertEqual(report["counts"]["ready"], 0)
        self.assertEqual(report["counts"]["resolved_blockers"], 0)
        self.assertEqual(report["counts"]["preserved_blockers"], 1)
        self.assertEqual(report["preserved_blockers"][0]["id"], "blocked-short")
        self.assertIn("repo identity missing", report["preserved_blockers"][0]["blocker"])
        hint = report["preserved_blockers"][0]["identity_resolution_hint"]
        self.assertEqual(hint["code"], "missing_repo_identity_resolution_hint")
        self.assertTrue(hint["no_source_claim"])
        self.assertEqual(hint["candidate_evidence_paths"], ["reference/example.md"])
        self.assertIn("github\\.com/", hint["safe_local_commands"][0])
        self.assertIn("abc1234", hint["safe_local_commands"][1])
        self.assertEqual(len(report["identity_resolution_classes"]), 1)
        self.assertEqual(report["identity_resolution_classes"][0]["row_ids"], ["blocked-short"])

    def test_ready_row_string_blocker_is_not_split_into_characters(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            row = {
                "id": "missing-identity",
                "status": "ready",
                "blocker": "operator_needs_repo_identity",
            }

            result = verify.verify_row(row, 0, tmp_path)

        self.assertEqual(result["status"], "blocked")
        self.assertIn("operator_needs_repo_identity", result["blockers"])
        self.assertNotIn("o", result["blockers"])

    def test_ref_not_found_emits_terminal_next_command_without_source_claim(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            repo = _make_repo(tmp_path, "zeta", "https://github.com/acme/zeta.git")
            missing_ref = "6a1333dd3f75430a4c2b378510d9aade1b507e37"
            row = {
                "id": "missing-ref",
                "status": "ready",
                "repo_path": str(repo),
                "repo_url": "https://github.com/acme/zeta",
                "ref": missing_ref,
            }

            result = verify.verify_row(row, 0, tmp_path)

        self.assertEqual(result["status"], "blocked")
        self.assertFalse(result["checks"]["ref_verified"])
        self.assertIsNone(result["checks"]["resolved_ref"])
        self.assertTrue(any("ref_not_found_locally" in blocker for blocker in result["blockers"]))
        terminal = result["terminal_blocker"]
        self.assertEqual(terminal["code"], "terminal_ref_not_found_locally")
        self.assertTrue(terminal["terminal"])
        self.assertTrue(terminal["no_source_claim"])
        self.assertIn("git -C", terminal["next_command"])
        self.assertIn("fetch --tags origin", terminal["next_command"])
        self.assertIn(f"rev-parse --verify '{missing_ref}^{{commit}}'", terminal["next_command"])

    def test_missing_identity_classes_group_by_target_and_evidence(self) -> None:
        rows = [
            {
                "source_row_id": "row-a",
                "mirror_status": "blocked_missing_repo_identity",
                "blocker": "repo identity missing",
                "target": "Grouped",
                "ref": "abc1234",
                "ref_kind": "short_sha",
                "evidence_paths": ["reference/grouped.md"],
            },
            {
                "source_row_id": "row-b",
                "mirror_status": "blocked_missing_repo_identity",
                "blocker": "repo identity missing",
                "target": "Grouped",
                "ref": "def5678",
                "ref_kind": "short_sha",
                "evidence_paths": ["reference/grouped.md"],
            },
            {
                "source_row_id": "row-c",
                "mirror_status": "blocked_missing_repo_identity",
                "blocker": "repo identity missing",
                "target": "Other",
                "ref": "v1",
                "ref_kind": "named_ref",
                "evidence_paths": ["reference/other.md"],
            },
        ]

        report = verify.build_report(Path("queue.json"), rows, "queue_rows", Path.cwd())

        classes = {item["target"]: item for item in report["identity_resolution_classes"]}
        self.assertEqual(len(classes), 2)
        self.assertEqual(classes["Grouped"]["row_count"], 2)
        self.assertEqual(classes["Grouped"]["row_ids"], ["row-a", "row-b"])
        self.assertEqual(classes["Grouped"]["refs"], ["abc1234", "def5678"])
        self.assertTrue(classes["Grouped"]["no_source_claim"])
        self.assertIn("reference/grouped.md", classes["Grouped"]["safe_local_commands"][0])
        self.assertIn("abc1234", classes["Grouped"]["safe_local_commands"][1])
        self.assertIn("def5678", classes["Grouped"]["safe_local_commands"][1])

    def test_missing_identity_hint_extracts_local_candidate_repo_identity(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            evidence = tmp_path / "evidence.md"
            evidence.write_text("Scope: https://github.com/ExampleOrg/ExampleRepo/tree/v1\n")
            rows = [
                {
                    "source_row_id": "row-a",
                    "mirror_status": "blocked_missing_repo_identity",
                    "blocker": "repo identity missing",
                    "target": "Example",
                    "ref": "v1",
                    "ref_kind": "named_ref",
                    "evidence_paths": ["evidence.md"],
                }
            ]

            report = verify.build_report(tmp_path / "queue.json", rows, "queue_rows", tmp_path)

        hint = report["preserved_blockers"][0]["identity_resolution_hint"]
        self.assertEqual(hint["candidate_repo_identities"], ["github.com/exampleorg/examplerepo"])
        self.assertEqual(
            hint["candidate_repo_identity_evidence"],
            [
                {
                    "repo_identity": "github.com/exampleorg/examplerepo",
                    "evidence_path": "evidence.md",
                    "line": 1,
                }
            ],
        )
        self.assertEqual(
            report["identity_resolution_classes"][0]["candidate_repo_identities"],
            ["github.com/exampleorg/examplerepo"],
        )


if __name__ == "__main__":
    unittest.main()
