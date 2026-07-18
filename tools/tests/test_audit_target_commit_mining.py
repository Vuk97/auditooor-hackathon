from __future__ import annotations

import importlib.util
import io
import json
import pathlib
import subprocess
import sys
import tempfile
import unittest
from contextlib import redirect_stderr


REPO = pathlib.Path(__file__).resolve().parents[2]
TOOL = REPO / "tools" / "audit-target-commit-mining.py"


def _load_tool():
    spec = importlib.util.spec_from_file_location("audit_target_commit_mining", TOOL)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"unable to load tool: {TOOL}")
    module = importlib.util.module_from_spec(spec)
    sys.modules["audit_target_commit_mining"] = module
    spec.loader.exec_module(module)
    return module


TOOL_MOD = _load_tool()


def _git(repo: pathlib.Path, args: list[str]) -> None:
    subprocess.run(
        ["git", "-C", str(repo), *args],
        text=True,
        capture_output=True,
        check=True,
    )


def _init_git_repo_with_commits(repo: pathlib.Path, count: int) -> None:
    repo.mkdir(parents=True)
    _git(repo, ["init"])
    (repo / "Cargo.toml").write_text("[package]\nname='snapshot'\n", encoding="utf-8")
    for idx in range(count):
        (repo / "history.txt").write_text(f"commit {idx}\n", encoding="utf-8")
        _git(repo, ["add", "."])
        _git(
            repo,
            [
                "-c",
                "user.name=Auditooor Test",
                "-c",
                "user.email=audit@example.invalid",
                "commit",
                "-m",
                f"commit {idx}",
            ],
        )


class AuditTargetCommitMiningTest(unittest.TestCase):
    def test_validate_history_blocks_missing_github_discussion_metadata(self):
        with tempfile.TemporaryDirectory() as td:
            ws = pathlib.Path(td)
            pin = "a" * 40
            (ws / "targets.tsv").write_text(
                f"https://github.com/example/protocol\t{pin}\tprotocol\n",
                encoding="utf-8",
            )
            out_dir = ws / "mining_rounds" / "round"
            out_dir.mkdir(parents=True)
            report = out_dir / "report.json"
            report.write_text(json.dumps({
                "discussion_metadata": {
                    "status": "not_applicable",
                    "reason": "github_issue_metadata_unavailable_in_local_git_only_mode",
                },
            }), encoding="utf-8")
            (out_dir / "commit_mining_manifest.json").write_text(json.dumps({
                "rows": [{
                    "owner_repo": "example/protocol",
                    "status": "skipped_existing",
                    "output_path": str(report),
                }],
            }), encoding="utf-8")
            rc, result = TOOL_MOD.validate_github_history(ws)
            self.assertEqual(rc, 1)
            self.assertEqual(result["verdict"], "fail-github-discussion-reconciliation")
            self.assertEqual(result["blocking"][0]["reason"], "github-issue-metadata-unavailable")

    def test_validate_history_accepts_explicit_empty_api_result(self):
        with tempfile.TemporaryDirectory() as td:
            ws = pathlib.Path(td)
            pin = "b" * 40
            (ws / "targets.tsv").write_text(
                f"https://github.com/example/protocol\t{pin}\tprotocol\n",
                encoding="utf-8",
            )
            out_dir = ws / "mining_rounds" / "round"
            out_dir.mkdir(parents=True)
            report = out_dir / "report.json"
            report.write_text(json.dumps({
                "discussion_metadata": {
                    "status": "available",
                    "reason": "github_api_available",
                    "evidence_record_count": 0,
                },
                "discussion_evidence": [],
            }), encoding="utf-8")
            (out_dir / "commit_mining_manifest.json").write_text(json.dumps({
                "rows": [{
                    "owner_repo": "example/protocol",
                    "status": "ok",
                    "output_path": str(report),
                }],
            }), encoding="utf-8")
            (ws / ".auditooor").mkdir()
            (ws / ".auditooor" / "github_history_analysis.json").write_text(json.dumps({
                "schema_version": "auditooor.github_history_analysis.v1",
                "targets": [{
                    "owner_repo": "example/protocol",
                    "status": "complete",
                    "issue_pr_comment_disposition": "none-found",
                    "commit_dispositions": [],
                }],
            }), encoding="utf-8")

            rc, result = TOOL_MOD.validate_github_history(ws)
            self.assertEqual(rc, 0)
            self.assertEqual(result["verdict"], "pass-github-discussion-reconciled")

    def test_load_targets_merges_scope_json_and_targets_tsv(self):
        with tempfile.TemporaryDirectory() as td:
            ws = pathlib.Path(td)
            (ws / "scope.json").write_text(
                json.dumps({
                    "target_repos": [
                        "https://github.com/polytope-labs/hyperbridge"
                    ],
                    "audit_pin_sha": "a" * 40,
                }),
                encoding="utf-8",
            )
            (ws / "targets.tsv").write_text(
                "# comment\n"
                f"https://github.com/polytope-labs/hyperbridge\t{'a' * 40}\thyperbridge\n"
                f"git@github.com:polytope-labs/solidity-merkle-trees.git\t{'b' * 40}\tsolidity-merkle-trees\n"
                f"polytope-labs/ismp@{'c' * 40}\n",
                encoding="utf-8",
            )

            targets = TOOL_MOD.load_targets(ws)
            self.assertEqual([t.owner_repo for t in targets], [
                "polytope-labs/hyperbridge",
                "polytope-labs/solidity-merkle-trees",
                "polytope-labs/ismp",
            ])

    def test_load_targets_normalizes_url_query_and_inline_ref(self):
        with tempfile.TemporaryDirectory() as td:
            ws = pathlib.Path(td)
            (ws / "scope.json").write_text(
                json.dumps({
                    "targets": [
                        {
                            "repo_url": "https://github.com/polytope-labs/hyperbridge?tab=readme",
                            "pin": "a" * 40,
                            "local_name": "hyperbridge",
                        },
                        {
                            "repo": "polytope-labs/ismp@main",
                            "pin": "b" * 40,
                        },
                    ]
                }),
                encoding="utf-8",
            )

            targets = TOOL_MOD.load_targets(ws)

            self.assertEqual([t.owner_repo for t in targets], [
                "polytope-labs/hyperbridge",
                "polytope-labs/ismp",
            ])
            self.assertEqual([t.pin for t in targets], ["a" * 40, "b" * 40])

    def test_infer_language_prefers_rust_then_solidity_then_go(self):
        with tempfile.TemporaryDirectory() as td:
            root = pathlib.Path(td)
            rust_repo = root / "rust"
            rust_repo.mkdir()
            (rust_repo / "Cargo.toml").write_text("[package]\nname='x'\n", encoding="utf-8")
            sol_repo = root / "sol"
            sol_repo.mkdir()
            (sol_repo / "foundry.toml").write_text("[profile.default]\n", encoding="utf-8")
            (sol_repo / "Contract.sol").write_text("contract C {}\n", encoding="utf-8")
            (sol_repo / "tests").mkdir()
            (sol_repo / "tests" / "differential.rs").write_text("fn helper() {}\n", encoding="utf-8")
            go_repo = root / "go"
            go_repo.mkdir()
            (go_repo / "go.mod").write_text("module example\n", encoding="utf-8")

            self.assertEqual(TOOL_MOD.infer_language(rust_repo), "rust")
            self.assertEqual(TOOL_MOD.infer_language(sol_repo), "solidity")
            self.assertEqual(TOOL_MOD.infer_language(go_repo), "go")

    def test_build_rows_emits_mixed_language_target_rows(self):
        with tempfile.TemporaryDirectory() as td:
            ws = pathlib.Path(td)
            repo = ws / "src" / "hyperbridge"
            (repo / "crates" / "x").mkdir(parents=True)
            (repo / "crates" / "x" / "lib.rs").write_text("pub fn x() {}\n", encoding="utf-8")
            (repo / "evm" / "src").mkdir(parents=True)
            (repo / "evm" / "src" / "Host.sol").write_text("contract Host {}\n", encoding="utf-8")
            targets = [
                TOOL_MOD.Target(
                    repo_url="https://github.com/polytope-labs/hyperbridge",
                    pin="a" * 40,
                    local_name="hyperbridge",
                )
            ]

            rows = TOOL_MOD.build_rows(ws, ws / "round", targets, window=90, force=False)

            self.assertEqual([row["language"] for row in rows], ["rust", "solidity"])
            self.assertTrue(rows[0]["output_path"].endswith("_rust_git_commits_mining.json"))
            self.assertTrue(rows[1]["output_path"].endswith("_solidity_git_commits_mining.json"))

    def test_build_rows_resolves_src_checkout_when_local_name_child_missing(self):
        with tempfile.TemporaryDirectory() as td:
            ws = pathlib.Path(td)
            repo = ws / "src"
            repo.mkdir(parents=True)
            _git(repo, ["init"])
            _git(repo, ["remote", "add", "origin", "https://github.com/morpho-org/midnight.git"])
            (repo / "src").mkdir()
            (repo / "src" / "Midnight.sol").write_text("contract Midnight {}\n", encoding="utf-8")
            target = TOOL_MOD.Target(
                repo_url="https://github.com/morpho-org/midnight.git",
                pin="a" * 40,
                local_name="midnight",
            )

            rows = TOOL_MOD.build_rows(ws, ws / "round", [target], window=90, force=False)

            self.assertEqual(len(rows), 1)
            self.assertEqual(rows[0]["language"], "solidity")
            self.assertEqual(rows[0]["repo_dir"], str(repo))

    def test_build_rows_keeps_legacy_local_name_child_precedence(self):
        with tempfile.TemporaryDirectory() as td:
            ws = pathlib.Path(td)
            repo = ws / "src" / "hyperbridge"
            repo.mkdir(parents=True)
            _git(repo, ["init"])
            _git(repo, ["remote", "add", "origin", "https://github.com/polytope-labs/hyperbridge.git"])
            (repo / "crates" / "x").mkdir(parents=True)
            (repo / "crates" / "x" / "lib.rs").write_text("pub fn x() {}\n", encoding="utf-8")
            target = TOOL_MOD.Target(
                repo_url="https://github.com/polytope-labs/hyperbridge",
                pin="a" * 40,
                local_name="hyperbridge",
            )

            rows = TOOL_MOD.build_rows(ws, ws / "round", [target], window=90, force=False)

            self.assertEqual(len(rows), 1)
            self.assertEqual(rows[0]["language"], "rust")
            self.assertEqual(rows[0]["repo_dir"], str(repo))

    def test_build_rows_ignores_legacy_local_name_file_for_src_checkout(self):
        with tempfile.TemporaryDirectory() as td:
            ws = pathlib.Path(td)
            repo = ws / "src"
            repo.mkdir(parents=True)
            _git(repo, ["init"])
            _git(repo, ["remote", "add", "origin", "https://github.com/morpho-org/midnight.git"])
            (repo / "midnight").write_text("not a directory\n", encoding="utf-8")
            (repo / "src").mkdir()
            (repo / "src" / "Midnight.sol").write_text("contract Midnight {}\n", encoding="utf-8")
            target = TOOL_MOD.Target(
                repo_url="https://github.com/morpho-org/midnight.git",
                pin="a" * 40,
                local_name="midnight",
            )

            rows = TOOL_MOD.build_rows(ws, ws / "round", [target], window=90, force=False)

            self.assertEqual(len(rows), 1)
            self.assertEqual(rows[0]["language"], "solidity")
            self.assertEqual(rows[0]["repo_dir"], str(repo))

    def test_dry_run_writes_manifest_without_running_miner(self):
        with tempfile.TemporaryDirectory() as td:
            ws = pathlib.Path(td)
            (ws / "src" / "hyperbridge").mkdir(parents=True)
            (ws / "src" / "hyperbridge" / "Cargo.toml").write_text(
                "[package]\nname='hyperbridge'\n",
                encoding="utf-8",
            )
            (ws / "targets.tsv").write_text(
                f"https://github.com/polytope-labs/hyperbridge\t{'a' * 40}\thyperbridge\n",
                encoding="utf-8",
            )
            out_dir = ws / "round"

            rc = TOOL_MOD.main([
                "--workspace",
                str(ws),
                "--out-dir",
                str(out_dir),
                "--dry-run",
                "--json",
            ])

            self.assertEqual(rc, 0)
            manifest = json.loads((out_dir / "commit_mining_manifest.json").read_text(encoding="utf-8"))
            self.assertEqual(manifest["schema"], "auditooor.audit_target_commit_mining_manifest.v1")
            self.assertEqual(manifest["rows"][0]["language"], "rust")
            self.assertEqual(manifest["rows"][0]["status"], "dry_run")
            self.assertTrue((out_dir / "commit_mining_manifest.md").exists())
            ledger = json.loads((ws / ".auditooor" / "commit_lifecycle_ledger.json").read_text(encoding="utf-8"))
            self.assertEqual(ledger["schema"], "auditooor.commit_lifecycle_ledger.v1")
            self.assertEqual(ledger["summary"]["targets_seen"], 1)
            self.assertEqual(ledger["summary"]["rows"], 1)

    def test_main_fails_loud_when_targets_tsv_missing(self):
        with tempfile.TemporaryDirectory() as td:
            ws = pathlib.Path(td)
            out_dir = ws / "round"
            err = io.StringIO()
            with redirect_stderr(err):
                rc = TOOL_MOD.main([
                    "--workspace",
                    str(ws),
                    "--out-dir",
                    str(out_dir),
                    "--dry-run",
                ])

            self.assertEqual(rc, 2)
            self.assertIn("targets.tsv missing", err.getvalue())
            self.assertFalse((out_dir / "commit_mining_manifest.json").exists())

    def test_main_fails_loud_when_targets_tsv_empty(self):
        with tempfile.TemporaryDirectory() as td:
            ws = pathlib.Path(td)
            (ws / "targets.tsv").write_text(
                "# REQUIRED: populate before running make audit\n\n",
                encoding="utf-8",
            )
            err = io.StringIO()
            with redirect_stderr(err):
                rc = TOOL_MOD.main([
                    "--workspace",
                    str(ws),
                    "--out-dir",
                    str(ws / "round"),
                    "--dry-run",
                ])

            self.assertEqual(rc, 2)
            self.assertIn("contains no mineable GitHub repo rows", err.getvalue())

    def test_stale_empty_manifest_reruns_when_targets_later_populated(self):
        with tempfile.TemporaryDirectory() as td:
            ws = pathlib.Path(td)
            repo = ws / "src" / "hyperbridge"
            repo.mkdir(parents=True)
            (repo / "Cargo.toml").write_text("[package]\nname='hyperbridge'\n")
            (ws / "targets.tsv").write_text(
                f"https://github.com/polytope-labs/hyperbridge\t{'a' * 40}\thyperbridge\n",
                encoding="utf-8",
            )
            out_dir = ws / "round"
            out_dir.mkdir()
            (out_dir / "commit_mining_manifest.json").write_text(
                json.dumps({
                    "schema": "auditooor.audit_target_commit_mining_manifest.v1",
                    "targets_seen": 0,
                    "rows": [],
                    "summary": {"ran": 0, "failed": 0},
                }),
                encoding="utf-8",
            )

            rc = TOOL_MOD.main([
                "--workspace",
                str(ws),
                "--out-dir",
                str(out_dir),
                "--dry-run",
                "--json",
            ])

            self.assertEqual(rc, 0)
            manifest = json.loads((out_dir / "commit_mining_manifest.json").read_text(encoding="utf-8"))
            self.assertTrue(manifest["stale_empty_manifest_rerun"])
            self.assertEqual(manifest["targets_seen"], 1)
            self.assertEqual(manifest["rows"][0]["status"], "dry_run")

    def test_flattened_snapshot_pivots_and_writes_strategy_and_prior_index(self):
        with tempfile.TemporaryDirectory() as td:
            ws = pathlib.Path(td)
            repo = ws / "src" / "superearn-core-public"
            _init_git_repo_with_commits(repo, 4)
            (ws / "targets.tsv").write_text(
                f"https://github.com/superearn-io/superearn-core-public\t{'a' * 40}\tsuperearn-core-public\n",
                encoding="utf-8",
            )
            prior = ws / "prior_audits"
            prior.mkdir()
            (prior / "certik-2026-04-07.txt").write_text(
                "SA2-77 was fixed in commit 44a64d7 by excluding outstandingDebt.\n"
                "The follow-up patch 859b2f11 resolved sibling accounting drift.\n"
                "Numeric audit id 20260527 should not be treated as a SHA.\n",
                encoding="utf-8",
            )

            rc = TOOL_MOD.main([
                "--workspace",
                str(ws),
                "--out-dir",
                str(ws / "round"),
                "--dry-run",
                "--json",
            ])

            self.assertEqual(rc, 0)
            manifest = json.loads((ws / "round" / "commit_mining_manifest.json").read_text(encoding="utf-8"))
            self.assertEqual(manifest["rows"][0]["status"], "flattened_snapshot_prior_audit_pivot")
            self.assertEqual(manifest["rows"][0]["strategy"], "flattened-snapshot-prior-audit-pivot")
            self.assertEqual(manifest["rows"][0]["commit_count"], 4)
            self.assertEqual(manifest["summary"]["flattened_snapshot_prior_audit_pivot"], 1)
            self.assertEqual(manifest["summary"]["prior_audit_fix_sha_references"], 2)

            strategy = json.loads((ws / ".auditooor" / "repo_strategy.json").read_text(encoding="utf-8"))
            self.assertEqual(strategy["strategy"], "flattened-snapshot-prior-audit-pivot")
            self.assertEqual(strategy["owner_repo"], "superearn-io/superearn-core-public")
            self.assertEqual(strategy["local_name"], "superearn-core-public")
            self.assertEqual(strategy["commit_count"], 4)
            self.assertIn("prior-audit SHA extraction", strategy["recommendation"])

            index = json.loads((ws / ".auditooor" / "prior_audit_fix_index.json").read_text(encoding="utf-8"))
            self.assertEqual(index["schema"], "auditooor.prior_audit_fix_index.v1")
            self.assertEqual(index["summary"]["sha_references"], 2)
            self.assertEqual([row["fix_sha"] for row in index["rows"]], ["44a64d7", "859b2f11"])
            self.assertIn("outstandingDebt", index["rows"][0]["context"])

    def test_commit_lifecycle_ledger_summarizes_existing_reports(self):
        with tempfile.TemporaryDirectory() as td:
            ws = pathlib.Path(td)
            repo = ws / "src" / "hyperbridge"
            repo.mkdir(parents=True)
            out_dir = ws / "round"
            out_dir.mkdir()
            report_path = out_dir / "polytope-labs_hyperbridge_rust_git_commits_mining.json"
            report_path.write_text(
                json.dumps(
                    {
                        "schema": "auditooor.git_commits_mining.v1",
                        "audit_pin_sha": "a" * 40,
                        "generated_at": "2026-05-21T00:00:00Z",
                        "commits_scanned": 9,
                        "security_fix_count": 2,
                        "shaped_commits_index": [
                            {"sha": "b" * 40, "subject": "fix proof-domain guard"}
                        ],
                    }
                ),
                encoding="utf-8",
            )
            manifest = {
                "schema": "auditooor.audit_target_commit_mining_manifest.v1",
                "generated_at_utc": "2026-05-21T00:00:00+00:00",
                "workspace": str(ws),
                "mode": "bidirectional",
                "window": 90,
                "targets_seen": 1,
                "rows": [
                    {
                        "owner_repo": "polytope-labs/hyperbridge",
                        "pin": "a" * 40,
                        "local_name": "hyperbridge",
                        "repo_dir": str(repo),
                        "language": "rust",
                        "output_path": str(report_path),
                        "status": "skipped_existing",
                    }
                ],
                "summary": {"failed": 0},
            }

            TOOL_MOD.write_commit_lifecycle_ledger(ws, manifest)

            ledger = json.loads((ws / ".auditooor" / "commit_lifecycle_ledger.json").read_text(encoding="utf-8"))
            self.assertEqual(ledger["audit_pin_sha"], "a" * 40)
            self.assertEqual(ledger["forward_window"]["count"], 9)
            self.assertEqual(ledger["backward_window"]["count"], 90)
            self.assertEqual(ledger["summary"]["security_fix_count"], 2)
            self.assertEqual(ledger["lanes_residual"][0]["sha"], "b" * 40)


if __name__ == "__main__":
    unittest.main()
