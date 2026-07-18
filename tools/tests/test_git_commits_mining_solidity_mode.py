from __future__ import annotations

import importlib.util
import json
import pathlib
import tempfile
import unittest
from unittest import mock


REPO = pathlib.Path(__file__).resolve().parents[2]
MINER = REPO / "tools" / "git-commits-mining.py"


def _load_miner_module():
    spec = importlib.util.spec_from_file_location("git_commits_mining_solidity_mode", MINER)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"unable to load miner module: {MINER}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class GitCommitsMiningSolidityModeTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.miner = _load_miner_module()

    def test_solidity_filter_requires_solidity_paths(self) -> None:
        commits = [
            {
                "sha": "a1",
                "date": "2026-05-01T00:00:00Z",
                "message": "fix: upgrade storage slot handling",
            },
            {
                "sha": "b2",
                "date": "2026-05-02T00:00:00Z",
                "message": "fix: upgrade storage slot handling",
            },
        ]
        details = {
            "a1": {
                "files": [
                    {
                        "filename": "contracts/Vault.sol",
                        "patch": "+ uint256[49] private __gap;",
                    }
                ]
            },
            "b2": {"files": [{"filename": "pkg/vault/keeper.go", "patch": "+ func fix() {}"}]},
        }

        shaped = self.miner.filter_security_shaped_for_language(
            commits,
            "solidity",
            repo="org/repo",
            detail_loader=lambda _repo, sha: details[sha],
        )

        self.assertEqual([commit["sha"] for commit in shaped], ["a1"])
        self.assertEqual(
            shaped[0]["_solidity_analysis"]["affected_solidity_paths"],
            ["contracts/Vault.sol"],
        )

    def test_solidity_filter_recognizes_keywords_in_commit_body(self) -> None:
        commits = [
            {
                "sha": "c3",
                "date": "2026-05-03T00:00:00Z",
                "message": "refactor: debt accounting\n\nliquidation ordering invariant fix",
            }
        ]
        details = {
            "c3": {
                "files": [
                    {
                        "filename": "src/TroveManager.sol",
                        "patch": "+ uint256 liquidationReserve;",
                    }
                ]
            }
        }

        shaped = self.miner.filter_security_shaped_for_language(
            commits,
            "solidity",
            repo="org/repo",
            detail_loader=lambda _repo, sha: details[sha],
        )

        self.assertEqual(len(shaped), 1)
        self.assertGreater(shaped[0]["_solidity_analysis"]["solidity_score"], 0)
        self.assertIn("liquidation", shaped[0]["_solidity_analysis"]["solidity_keywords_matched"])
        self.assertIn("ordering", shaped[0]["_solidity_analysis"]["solidity_keywords_matched"])
        self.assertIn("invariant", shaped[0]["_solidity_analysis"]["solidity_keywords_matched"])

    def test_analyze_solidity_commit_detects_storage_layout_changes(self) -> None:
        analysis = self.miner.analyze_solidity_commit(
            {"message": "fix: upgrade storage layout"},
            {
                "files": [
                    {
                        "filename": "contracts/ProxyAdmin.sol",
                        "patch": "+ uint256[49] private __gap;\n+ // storage gap for upgrade safety",
                    }
                ]
            },
        )

        self.assertTrue(analysis["proxy_storage_layout_changed"])
        self.assertEqual(analysis["affected_solidity_paths"], ["contracts/ProxyAdmin.sol"])

    def test_analyze_solidity_commit_detects_inheritance_changes(self) -> None:
        analysis = self.miner.analyze_solidity_commit(
            {"message": "fix: tighten access guard"},
            {
                "files": [
                    {
                        "filename": "contracts/Vault.sol",
                        "patch": "- contract Vault is Ownable {\n+ contract Vault is OwnableUpgradeable, PausableUpgradeable {",
                    }
                ]
            },
        )

        self.assertTrue(analysis["inheritance_changed"])
        self.assertFalse(analysis["oz_upgradeable_initialize_changed"])

    def test_analyze_solidity_commit_detects_oz_initializer_changes(self) -> None:
        analysis = self.miner.analyze_solidity_commit(
            {"message": "fix: initialize upgrade path"},
            {
                "files": [
                    {
                        "filename": "contracts/Vault.sol",
                        "patch": "+ function initialize() external initializer {}\n+ __Vault_init_unchained();",
                    }
                ]
            },
        )

        self.assertTrue(analysis["oz_upgradeable_initialize_changed"])
        self.assertGreaterEqual(analysis["solidity_score"], 5)

    def test_solidity_defaults_to_bidirectional_window_sixty(self) -> None:
        mode, window = self.miner.resolve_mode_and_window("solidity", None, None)

        self.assertEqual(mode, "bidirectional")
        self.assertEqual(window, 60)

    def test_collect_commits_can_bound_forward_side_by_window(self) -> None:
        with (
            mock.patch.object(self.miner, "gh_commits_since") as gh_since,
            mock.patch.object(
                self.miner,
                "gh_commits_window",
                side_effect=[
                    [{"sha": "head1", "date": "2026-05-12T00:00:00Z", "message": "fix: head"}],
                    [{"sha": "pin1", "date": "2026-05-01T00:00:00Z", "message": "fix: pin"}],
                ],
            ) as gh_window,
        ):
            commits = self.miner.collect_commits(
                "org/repo",
                "2026-05-01T00:00:00Z",
                "pinsha",
                "bidirectional",
                60,
                bounded_forward_window=True,
            )

        gh_since.assert_not_called()
        self.assertEqual([call.args for call in gh_window.call_args_list], [("org/repo", "HEAD", 60), ("org/repo", "pinsha", 60)])
        self.assertEqual([commit["sha"] for commit in commits], ["head1", "pin1"])

    def test_main_emits_solidity_schema_fields(self) -> None:
        commit = {
            "sha": "deadbeef",
            "date": "2026-05-04T00:00:00Z",
            "message": "fix: proxy storage upgrade initializer guard",
        }

        def fake_detail(_repo: str, sha: str):
            if sha == "pin123":
                return {"commit": {"author": {"date": "2026-05-01T12:00:00Z"}}}
            if sha == "deadbeef":
                return {
                    "files": [
                        {
                            "filename": "contracts/Vault.sol",
                            "patch": "+ uint256[49] private __gap;\n+ function initialize() external initializer {}",
                        }
                    ]
                }
            raise AssertionError(f"unexpected sha: {sha}")

        with tempfile.TemporaryDirectory() as tmpdir:
            out_path = pathlib.Path(tmpdir) / "solidity-report.json"
            argv = [
                "git-commits-mining.py",
                "--workspace",
                "demo",
                "--upstream",
                "org/repo",
                "--audit-pin",
                "pin123",
                "--lang",
                "sol",
                "--out",
                str(out_path),
            ]
            with (
                mock.patch.object(self.miner, "gh_auth_ok", return_value=True),
                mock.patch.object(self.miner, "gh_commits_since", return_value=[commit]),
                mock.patch.object(self.miner, "gh_commits_window", return_value=[]),
                mock.patch.object(self.miner, "gh_commit_detail", side_effect=fake_detail),
                mock.patch.object(self.miner, "_attach_pattern_preflights", return_value={"patterns_seen": 0}),
                mock.patch("sys.argv", argv),
            ):
                rc = self.miner.main()

            self.assertEqual(rc, 0)
            report = json.loads(out_path.read_text())
            self.assertEqual(report["schema"], "auditooor.git_commits_mining.v1.2-solidity")
            self.assertEqual(report["schema_version"], "1.2-solidity")
            self.assertEqual(report["mode"], "bidirectional")
            self.assertEqual(report["window"], 60)
            self.assertEqual(report["since_date"], "2026-05-01")
            shaped = report["shaped_commits_index"][0]
            self.assertEqual(shaped["affected_solidity_paths"], ["contracts/Vault.sol"])
            self.assertTrue(shaped["proxy_storage_layout_changed"])
            self.assertTrue(shaped["oz_upgradeable_initialize_changed"])
            self.assertIn("solidity_score", shaped)

    def test_non_solidity_mode_keeps_v1_schema_and_legacy_filter(self) -> None:
        commit = {
            "sha": "f00d",
            "date": "2026-05-05T00:00:00Z",
            "message": "fix: hardening race in coordinator",
        }

        with tempfile.TemporaryDirectory() as tmpdir:
            out_path = pathlib.Path(tmpdir) / "go-report.json"
            argv = [
                "git-commits-mining.py",
                "--workspace",
                "demo",
                "--upstream",
                "org/repo",
                "--since",
                "2026-05-01",
                "--out",
                str(out_path),
            ]
            with (
                mock.patch.object(self.miner, "gh_auth_ok", return_value=True),
                mock.patch.object(self.miner, "gh_commits_since", return_value=[commit]),
                mock.patch.object(self.miner, "_attach_pattern_preflights", return_value={"patterns_seen": 0}),
                mock.patch("sys.argv", argv),
            ):
                rc = self.miner.main()

            self.assertEqual(rc, 0)
            report = json.loads(out_path.read_text())
            self.assertEqual(report["schema"], "auditooor.git_commits_mining.v1")
            self.assertEqual(report["schema_version"], "1.1")
            self.assertEqual(report["filter_regex"], self.miner.SECURITY_FIX_REGEX.pattern)
            self.assertNotIn("mode", report)
            self.assertNotIn("window", report)
            shaped = report["shaped_commits_index"][0]
            self.assertEqual(set(shaped), {"sha", "date", "subject", "url"})


if __name__ == "__main__":
    unittest.main()
