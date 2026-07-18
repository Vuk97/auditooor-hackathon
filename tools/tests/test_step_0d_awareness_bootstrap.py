from __future__ import annotations

import importlib.util
import tempfile
import unittest
from pathlib import Path
from unittest import mock


TOOL = Path(__file__).resolve().parents[1] / "step-0d-awareness-bootstrap.py"
SPEC = importlib.util.spec_from_file_location("step_0d_awareness_bootstrap", TOOL)
BOOTSTRAP = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(BOOTSTRAP)


class Step0dAwarenessBootstrapTests(unittest.TestCase):
    def test_reads_each_github_target_once(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            targets = Path(directory) / "targets.tsv"
            targets.write_text(
                "# url\tpin\tname\nhttps://github.com/acme/vault.git\t" + "a" * 40 + "\tvault\n"
                "git@github.com:acme/vault.git\t" + "b" * 40 + "\tvault-duplicate\n",
                encoding="utf-8",
            )
            self.assertEqual(BOOTSTRAP.github_repositories(targets), ["acme/vault"])

    def test_non_github_target_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            targets = Path(directory) / "targets.tsv"
            targets.write_text("https://gitlab.example/acme/vault\t" + "a" * 40 + "\tvault\n", encoding="utf-8")
            with self.assertRaisesRegex(BOOTSTRAP.BootstrapError, "target_not_github"):
                BOOTSTRAP.github_repositories(targets)

    def test_run_produces_bidirectional_commit_history_before_discovery(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            workspace = Path(directory)
            workspace.joinpath("targets.tsv").write_text(
                "https://github.com/acme/vault.git\t" + "a" * 40 + "\tvault\n",
                encoding="utf-8",
            )
            commands: list[list[str]] = []
            with mock.patch.object(BOOTSTRAP, "_source_comment_scan"), mock.patch.object(
                BOOTSTRAP, "_run", side_effect=lambda command: commands.append(command)
            ):
                result = BOOTSTRAP.run(workspace, "a" * 40)

        miner = next(command for command in commands if command[1].endswith("git-commits-mining.py"))
        discovery = next(command for command in commands if command[1].endswith("awareness-source-discovery.py"))
        self.assertLess(commands.index(miner), commands.index(discovery))
        self.assertEqual(miner[miner.index("--workspace") + 1], workspace.name)
        self.assertEqual(miner[miner.index("--upstream") + 1], "acme/vault")
        self.assertEqual(miner[miner.index("--audit-pin") + 1], "a" * 40)
        self.assertEqual(miner[miner.index("--mode") + 1], "bidirectional")
        self.assertTrue(miner[miner.index("--out") + 1].endswith("git_commits_mining_acme_vault.json"))
        self.assertEqual(len(result["commit_reports"]), 1)


if __name__ == "__main__":
    unittest.main()
