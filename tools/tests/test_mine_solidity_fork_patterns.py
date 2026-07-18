from __future__ import annotations

import importlib.util
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
TOOL = ROOT / "tools" / "mine-solidity-fork-patterns.py"
FIXTURES = ROOT / "tools" / "tests" / "fixtures" / "mine_solidity_fork_patterns" / "reports"


def _load_tool():
    spec = importlib.util.spec_from_file_location("mine_solidity_fork_patterns_test", TOOL)
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    sys.modules.setdefault(spec.name, mod)
    spec.loader.exec_module(mod)
    return mod


class MineSolidityForkPatternsTests(unittest.TestCase):
    def test_default_target_inventory_matches_goldpath_plan(self) -> None:
        mod = _load_tool()
        targets = list(mod.DEFAULT_TARGETS)
        self.assertEqual(len(targets), 9)
        got = {(t.owner, t.repo, t.family) for t in targets}
        expected = {
            ("liquity", "dev", "liquity-fork"),
            ("liquity", "bold", "liquity-fork"),
            ("Threshold-Network", "tbtc-v2", "stability-pool"),
            ("MakerDAO", "dss", "cdp"),
            ("aave", "aave-v3-core", "aave-collateral"),
            ("curvefi", "curve-contract", "curve-stableswap"),
            ("balancer-labs", "balancer-v2-monorepo", "balancer-pool"),
            ("compound-finance", "compound-protocol", "compound-comptroller"),
            ("OpenZeppelin", "openzeppelin-contracts", "oz-upgrade"),
        }
        self.assertEqual(got, expected)

    def test_slug_stability(self) -> None:
        mod = _load_tool()
        slug1 = mod.stable_pattern_slug(
            family="liquity-fork",
            trigger_shape="Tail ordering signal used without fresh ICR guard.",
            fix_shape="Add fresh ICR guard prior to withdrawal.",
            detector_regex=r"tail.*icr.*guard",
            origin_commit_sha="abc123",
            source_report_reference="reports/git_commits_mining_liquity-dev_fixture.json",
        )
        slug2 = mod.stable_pattern_slug(
            family="liquity-fork",
            trigger_shape="Tail ordering signal used without   fresh ICR guard.",
            fix_shape="Add fresh ICR guard prior to withdrawal.",
            detector_regex=r"tail.*icr.*guard",
            origin_commit_sha="abc123",
            source_report_reference="reports/git_commits_mining_liquity-dev_fixture.json",
        )
        slug3 = mod.stable_pattern_slug(
            family="liquity-fork",
            trigger_shape="Different trigger shape",
            fix_shape="Add fresh ICR guard prior to withdrawal.",
            detector_regex=r"tail.*icr.*guard",
            origin_commit_sha="abc123",
            source_report_reference="reports/git_commits_mining_liquity-dev_fixture.json",
        )
        self.assertEqual(slug1, slug2)
        self.assertNotEqual(slug1, slug3)

    def test_no_network_replay_extracts_fixtures_and_generates_index(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            ws = Path(td)
            reports = ws / "reports"
            patterns = ws / "patterns"
            reports.mkdir(parents=True)
            for fixture in FIXTURES.glob("*.json"):
                shutil.copy2(fixture, reports / fixture.name)

            proc = subprocess.run(
                [
                    "python3",
                    str(TOOL),
                    "--workspace",
                    str(ws),
                    "--reports-dir",
                    str(reports),
                    "--patterns-dir",
                    str(patterns),
                    "--target",
                    "liquity/dev",
                    "--replay",
                    "--no-network",
                    "--json",
                ],
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(proc.returncode, 0, proc.stderr)
            payload = json.loads(proc.stdout)
            self.assertGreaterEqual(payload["pattern_count"], 3)

            family_dir = patterns / "liquity-fork"
            self.assertTrue(family_dir.is_dir())
            md_files = sorted(path for path in family_dir.glob("*.md") if path.name != "INDEX.md")
            self.assertGreaterEqual(len(md_files), 3)
            sample = md_files[0].read_text(encoding="utf-8")
            self.assertIn("trigger-shape:", sample)
            self.assertIn("fix-shape:", sample)
            self.assertIn("detector-regex:", sample)
            self.assertIn("applicability heuristic:", sample)
            self.assertIn("origin commit SHA:", sample)
            self.assertIn("source report reference:", sample)

            index_path = patterns / "INDEX.md"
            self.assertTrue(index_path.is_file())
            index = index_path.read_text(encoding="utf-8")
            self.assertIn("# Solidity Fork Pattern Index", index)
            self.assertIn("## liquity-fork", index)
            self.assertIn("(liquity-fork/", index)
            family_index_path = family_dir / "INDEX.md"
            self.assertTrue(family_index_path.is_file())
            family_index = family_index_path.read_text(encoding="utf-8")
            self.assertIn("# Solidity Fork Patterns: liquity-fork", family_index)
            self.assertIn("Total patterns:", family_index)

    def test_no_network_empty_workspace_surfaces_canonical_patterns(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            ws = Path(td)
            reports = ws / "reports"
            patterns = ws / "patterns"
            reports.mkdir(parents=True)
            proc = subprocess.run(
                [
                    "python3",
                    str(TOOL),
                    "--workspace",
                    str(ws),
                    "--reports-dir",
                    str(reports),
                    "--patterns-dir",
                    str(patterns),
                    "--replay",
                    "--no-network",
                    "--json",
                ],
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(proc.returncode, 0, proc.stderr)
            payload = json.loads(proc.stdout)
            self.assertGreaterEqual(payload["pattern_count"], 150)
            self.assertGreaterEqual(payload["canonical_pattern_count"], 150)
            self.assertTrue(all(row.get("source") == "canonical" for row in payload["patterns"]))
            self.assertGreaterEqual(len(payload["pattern_paths"]), 150)
            self.assertTrue(any(Path(path).is_file() for path in payload["pattern_paths"]))
            self.assertTrue((patterns / "INDEX.md").is_file())
            skipped = [a for a in payload["artifacts"] if a.get("status") == "skipped"]
            self.assertGreaterEqual(len(skipped), 3)
            self.assertTrue(any(a.get("reason") == "report_missing" for a in skipped))
            canonical = [a for a in payload["artifacts"] if a.get("tool") == "canonical_patterns"]
            self.assertEqual(canonical[0]["status"], "ok")

    def test_canonical_patterns_resolver_prefers_stable_env_repo(self) -> None:
        mod = _load_tool()
        with tempfile.TemporaryDirectory() as td:
            repo = Path(td) / "stable-repo"
            pattern = repo / "patterns" / "liquity-fork" / "sample.md"
            pattern.parent.mkdir(parents=True)
            pattern.write_text(
                "# sample\n\n"
                "- family: liquity-fork\n"
                "- target: stable\n"
                "- trigger-shape: stable branch corpus\n"
                "- fix-shape: apply stable corpus\n"
                "- detector-regex: `stable`\n"
                "- origin commit SHA: abc\n"
                "- source report reference: fixture\n",
                encoding="utf-8",
            )

            resolved = mod.resolve_canonical_patterns_dir(
                env={
                    "AUDITOOOR_REPO": str(repo),
                    "HOME": os.environ.get("HOME", ""),
                }
            )
            self.assertEqual(resolved, (repo / "patterns").resolve())

    def test_explicit_canonical_patterns_dir_overrides_auto_resolution(self) -> None:
        mod = _load_tool()
        with tempfile.TemporaryDirectory() as td:
            explicit = Path(td) / "explicit" / "patterns"
            explicit.mkdir(parents=True)
            resolved = mod.resolve_canonical_patterns_dir(
                explicit=explicit,
                env={"AUDITOOOR_REPO": "/does/not/matter"},
            )
            self.assertEqual(resolved, explicit.resolve())

    def test_missing_tool_is_structured_skip(self) -> None:
        mod = _load_tool()
        with tempfile.TemporaryDirectory() as td:
            ws = Path(td)
            reports = ws / "reports"
            patterns = ws / "patterns"
            payload = mod.seed_solidity_fork_patterns(
                workspace=ws,
                mirror_root=ws / "mirrors",
                reports_dir=reports,
                patterns_dir=patterns,
                targets=[mod.UpstreamTarget("liquity", "dev", "liquity-fork")],
                replay=False,
                no_network=False,
                tool_paths={
                    "reverted_guard_mine": ws / "tools" / "reverted-guard-mine.py",
                    "changelog_source_drift_miner": ws / "tools" / "changelog-source-drift-miner.py",
                    "git_commits_mining": ws / "tools" / "git-commits-mining.py",
                },
            )
            self.assertEqual(payload["pattern_count"], 0)
            statuses = [a for a in payload["artifacts"] if a.get("reason") == "tool_missing"]
            self.assertEqual(len(statuses), 3)


if __name__ == "__main__":
    unittest.main()
