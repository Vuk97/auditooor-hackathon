#!/usr/bin/env python3
"""Tests for deterministic fixture scoring in tools/poc-scaffold.py (P1-5)."""
from __future__ import annotations

import importlib.util
import json
import os
import tempfile
import time
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
TOOL = REPO_ROOT / "tools" / "poc-scaffold.py"


def load_tool():
    spec = importlib.util.spec_from_file_location("poc_scaffold_fixture", TOOL)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class FixtureScoringTest(unittest.TestCase):
    """Synthetic-workspace tests for the deterministic fixture scorer."""

    def _make_workspace(self, tmp: Path) -> Path:
        """Create three fixtures of varying relevance plus one decoy."""
        ws = tmp / "ws"
        # Highly relevant: same contract name in path + body, in test/ root.
        f_high = ws / "test" / "VaultExploit.t.sol"
        # Medium relevance: shares the function name only, in poc-tests/.
        f_med = ws / "poc-tests" / "GenericRedeem.t.sol"
        # Low relevance: unrelated contract under tests/ deep path.
        f_low = ws / "tests" / "unrelated" / "FooBar.t.sol"
        # Far off-path decoy under lib/.
        f_decoy = ws / "lib" / "third-party" / "test" / "ThirdParty.t.sol"
        for path in (f_high, f_med, f_low, f_decoy):
            path.parent.mkdir(parents=True, exist_ok=True)

        f_high.write_text(
            "// SPDX-License-Identifier: MIT\n"
            "pragma solidity ^0.8.0;\n"
            "import {Vault} from \"src/Vault.sol\";\n"
            "contract VaultExploitTest {\n"
            "    function test_redeem() public {}\n"
            "}\n",
            encoding="utf-8",
        )
        f_med.write_text(
            "// SPDX-License-Identifier: MIT\n"
            "contract GenericRedeem {\n"
            "    function test_redeem() public {}\n"
            "}\n",
            encoding="utf-8",
        )
        f_low.write_text(
            "contract FooBar { function test_nope() public {} }\n",
            encoding="utf-8",
        )
        f_decoy.write_text(
            "contract ThirdParty { function test_z() public {} }\n",
            encoding="utf-8",
        )

        # Make the high-relevance fixture also the most recent.
        now = time.time()
        os.utime(f_high, (now, now))
        os.utime(f_med, (now - 10 * 86400, now - 10 * 86400))
        os.utime(f_low, (now - 200 * 86400, now - 200 * 86400))
        os.utime(f_decoy, (now - 200 * 86400, now - 200 * 86400))
        return ws

    def test_picks_highest_score_fixture(self) -> None:
        tool = load_tool()
        with tempfile.TemporaryDirectory() as tmp:
            ws = self._make_workspace(Path(tmp))
            manifest = tool.select_best_fixture(
                ws, "Vault", ["redeem"], angle_id="A-RACE",
                min_score=10, write_manifest=False,
            )
        self.assertIsNotNone(manifest["selected"], manifest)
        self.assertEqual(manifest["selected"]["path"], "test/VaultExploit.t.sol")
        # Ranking has all four fixtures, sorted by descending score.
        paths = [r["path"] for r in manifest["ranking"]]
        self.assertEqual(paths[0], "test/VaultExploit.t.sol")
        scores = [r["score"] for r in manifest["ranking"]]
        self.assertEqual(scores, sorted(scores, reverse=True))
        self.assertGreater(scores[0], scores[1])

    def test_no_fixtures_emits_warning_with_searched_dirs(self) -> None:
        tool = load_tool()
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp) / "empty"
            ws.mkdir()
            manifest = tool.select_best_fixture(
                ws, "Vault", ["redeem"], angle_id="A-RACE",
                min_score=10, write_manifest=False,
            )
        self.assertIsNone(manifest["selected"])
        self.assertIn("no project test fixtures found", manifest["warning"])
        # Every default-search directory must appear in the warning.
        for sub in ("test", "poc-tests", "tests/integration", "tests"):
            self.assertIn(sub, manifest["warning"])
        # And the searched_directories list must enumerate them.
        for sub in ("test", "poc-tests", "tests/integration", "tests"):
            self.assertIn(sub, manifest["searched_directories"])

    def test_below_min_score_emits_warning(self) -> None:
        tool = load_tool()
        with tempfile.TemporaryDirectory() as tmp:
            ws = self._make_workspace(Path(tmp))
            manifest = tool.select_best_fixture(
                ws, "TotallyDifferentContract", [], angle_id="",
                min_score=10_000, write_manifest=False,
            )
        # Best fixture exists but it doesn't meet the absurdly high threshold.
        self.assertIsNone(manifest["selected"])
        self.assertIn("below threshold", manifest["warning"])
        self.assertEqual(manifest["reason"], "below minimum score")

    def test_require_fixture_raises_on_no_match(self) -> None:
        tool = load_tool()
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp) / "empty"
            ws.mkdir()
            with self.assertRaises(ValueError):
                tool.select_best_fixture(
                    ws, "Vault", ["redeem"], angle_id="A-RACE",
                    min_score=10, write_manifest=False, require_fixture=True,
                )

    def test_deterministic_scoring_regression(self) -> None:
        tool = load_tool()
        with tempfile.TemporaryDirectory() as tmp:
            ws = self._make_workspace(Path(tmp))
            # Pin "now" so recency is not flaky across runs.
            pinned = 1_700_000_000.0
            # Re-anchor mtimes to pinned for reproducibility.
            os.utime(ws / "test" / "VaultExploit.t.sol", (pinned - 5 * 86400, pinned - 5 * 86400))
            os.utime(ws / "poc-tests" / "GenericRedeem.t.sol", (pinned - 60 * 86400, pinned - 60 * 86400))
            os.utime(ws / "tests" / "unrelated" / "FooBar.t.sol", (pinned - 365 * 86400, pinned - 365 * 86400))
            os.utime(ws / "lib" / "third-party" / "test" / "ThirdParty.t.sol",
                     (pinned - 365 * 86400, pinned - 365 * 86400))
            kwargs = dict(
                contract="Vault", suggested_functions=["redeem"], angle_id="A-RACE",
                min_score=10, write_manifest=False, now=pinned,
            )
            m1 = tool.select_best_fixture(ws, **kwargs)
            m2 = tool.select_best_fixture(ws, **kwargs)
        # Same inputs => identical ranking + identical scores.
        self.assertEqual(m1["ranking"], m2["ranking"])
        self.assertEqual(m1["selected"], m2["selected"])

    def test_manifest_written_under_dot_auditooor(self) -> None:
        tool = load_tool()
        with tempfile.TemporaryDirectory() as tmp:
            ws = self._make_workspace(Path(tmp))
            manifest = tool.select_best_fixture(
                ws, "Vault", ["redeem"], angle_id="A-RACE",
                min_score=10, write_manifest=True,
            )
            mpath = manifest.get("manifest_path")
            self.assertIsNotNone(mpath)
            mpath_p = Path(mpath)
            self.assertTrue(mpath_p.exists())
            self.assertEqual(mpath_p.parent, ws / ".auditooor")
            payload = json.loads(mpath_p.read_text(encoding="utf-8"))
            self.assertEqual(payload["schema"], "poc_fixture_selection.v1")
            self.assertEqual(payload["selected"]["path"], "test/VaultExploit.t.sol")
            self.assertIn("ranking", payload)
            self.assertGreaterEqual(len(payload["ranking"]), 1)

    def test_proximity_score_ordering_is_documented(self) -> None:
        """Pure-function spot check on the proximity tier ladder."""
        tool = load_tool()
        self.assertGreater(tool._proximity_score("test/Foo.t.sol"),
                           tool._proximity_score("poc-tests/Foo.t.sol"))
        self.assertGreater(tool._proximity_score("poc-tests/Foo.t.sol"),
                           tool._proximity_score("tests/integration/Foo.t.sol"))
        self.assertGreater(tool._proximity_score("tests/integration/Foo.t.sol"),
                           tool._proximity_score("tests/Foo.t.sol"))
        self.assertGreater(tool._proximity_score("tests/Foo.t.sol"),
                           tool._proximity_score("lib/x/test/Foo.t.sol"))
        self.assertGreater(tool._proximity_score("lib/x/test/Foo.t.sol"),
                           tool._proximity_score("random/elsewhere/Foo.t.sol"))


if __name__ == "__main__":
    unittest.main()
