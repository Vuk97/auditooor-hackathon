#!/usr/bin/env python3
"""Tests for tools/changelog-source-drift-miner.py."""

from __future__ import annotations

import importlib.util
import json
import shutil
import subprocess
import sys
import tempfile
import textwrap
import unittest
from pathlib import Path
from types import ModuleType


ROOT = Path(__file__).resolve().parents[2]
TOOL = ROOT / "tools" / "changelog-source-drift-miner.py"
FIXTURES = ROOT / "tools" / "tests" / "fixtures" / "changelog_source_drift_miner"
MEZO_FIXTURE = FIXTURES / "mezo_stale_tail"


def _load_tool() -> ModuleType:
    spec = importlib.util.spec_from_file_location("changelog_source_drift_miner", TOOL)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def _write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(textwrap.dedent(text).strip() + "\n", encoding="utf-8")


def _run_cli(ws: Path, *args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(TOOL), str(ws), *args],
        capture_output=True,
        text=True,
        check=False,
    )


class ChangelogSourceDriftMinerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.tool = _load_tool()

    def test_discovers_required_changelog_shapes(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            ws = Path(td)
            for rel in (
                "CHANGELOG.md",
                "CHANGELOG-v2.md",
                "MIGRATION.md",
                "BREAKING.md",
                "RELEASES.md",
                "docs/changelog-protocol.md",
            ):
                _write(ws / rel, "- SortedTroves ordering changed.")
            _write(ws / "docs/not-a-changelog.md", "- SortedTroves ordering changed.")

            discovered = [p.relative_to(ws).as_posix() for p in self.tool.discover_changelog_files(ws)]
            self.assertEqual(
                discovered,
                [
                    "BREAKING.md",
                    "CHANGELOG-v2.md",
                    "CHANGELOG.md",
                    "docs/changelog-protocol.md",
                    "MIGRATION.md",
                    "RELEASES.md",
                ],
            )

    def test_discovers_nested_multi_package_changelogs_and_skips_dirs(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            ws = Path(td)
            for rel in (
                "src/pkg1/docs/CHANGELOG.md",
                "src/pkg2/docs/CHANGELOG.md",
                "docs/CHANGELOG.md",
                "src/pkg3/docs/migration.md",
                "src/pkg4/docs/Changelog-V2.MD",
            ):
                _write(ws / rel, "- SortedTroves ordering changed.")
            for dirname in self.tool.CHANGELOG_SKIP_DIRS:
                _write(ws / dirname / "nested" / "CHANGELOG.md", "- SortedTroves ordering changed.")

            discovered = [p.relative_to(ws).as_posix() for p in self.tool.discover_changelog_files(ws)]
            self.assertEqual(
                discovered,
                [
                    "docs/CHANGELOG.md",
                    "src/pkg1/docs/CHANGELOG.md",
                    "src/pkg2/docs/CHANGELOG.md",
                    "src/pkg3/docs/migration.md",
                    "src/pkg4/docs/Changelog-V2.MD",
                ],
            )

    def test_no_skip_dirs_cli_includes_changelogs_under_skipped_dirs(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            ws = Path(td)
            _write(ws / "node_modules" / "pkg" / "CHANGELOG.md", "- SortedTroves ordering changed.")
            _write(ws / "dist" / "BREAKING.md", "- SortedTroves ordering changed.")

            proc = _run_cli(ws, "--json", "--no-skip-dirs")
            self.assertEqual(proc.returncode, 0, proc.stderr)
            payload = json.loads(proc.stdout)
            self.assertEqual(
                payload["discovered_changelogs"],
                [
                    "dist/BREAKING.md",
                    "node_modules/pkg/CHANGELOG.md",
                ],
            )

    def test_claim_and_primitive_extraction(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            ws = Path(td)
            _write(
                ws / "CHANGELOG.md",
                """
                # Release
                - SortedTroves ordering changed; previously `getLast()` returned the worst ICR tail.
                - Boring documentation line.
                """,
            )
            claims = self.tool.extract_claims(ws, self.tool.discover_changelog_files(ws))
            self.assertEqual(len(claims), 1)
            self.assertIn("ordering", claims[0]["keywords"])
            self.assertIn("SortedTroves", claims[0]["primitives"])
            self.assertIn("getLast", claims[0]["primitives"])
            self.assertIn("ICR", claims[0]["primitives"])

    def test_mezo_style_stale_tail_is_exposed(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            ws = Path(td) / "ws"
            shutil.copytree(MEZO_FIXTURE, ws)

            out = self.tool.mine(ws)
            exposed = [
                site
                for site in out["ranked_exposed_call_sites"]
                if site["verdict"] == self.tool.VERDICT_EXPOSED
            ]
            self.assertTrue(exposed, out)
            self.assertEqual(exposed[0]["function"], "_requireNoUnderCollateralizedTroves")
            self.assertEqual(exposed[0]["verdict"], "consumer-NOT-updated-EXPOSED")
            self.assertEqual(out["verdicts"][0]["verdict"], "consumer-NOT-updated-EXPOSED")

    def test_safe_when_no_current_consumer_exists(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            ws = Path(td)
            _write(
                ws / "CHANGELOG.md",
                "- SortedTroves ordering changed; previously `getLast()` returned the worst ICR tail.",
            )
            _write(
                ws / "src/Other.sol",
                """
                pragma solidity ^0.8.20;
                contract Other {
                    function unrelated() external pure returns (uint256) {
                        return 1;
                    }
                }
                """,
            )
            out = self.tool.mine(ws)
            self.assertEqual(out["verdicts"][0]["verdict"], "safe")
            self.assertEqual(out["ranked_exposed_call_sites"], [])

    def test_updated_consumer_is_classified(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            ws = Path(td)
            _write(
                ws / "CHANGELOG.md",
                "- SortedTroves ordering changed; previously `getLast()` returned the worst ICR tail.",
            )
            _write(
                ws / "src/StabilityPool.sol",
                """
                pragma solidity ^0.8.20;
                interface ISortedTroves {
                    function getLast() external view returns (address);
                    function getPrev(address id) external view returns (address);
                }
                contract StabilityPool {
                    ISortedTroves public sortedTroves;
                    function _requireNoUnderCollateralizedTroves() internal view {
                        address cursor = sortedTroves.getLast();
                        while (cursor != address(0)) {
                            cursor = sortedTroves.getPrev(cursor);
                        }
                    }
                }
                """,
            )
            out = self.tool.mine(ws)
            self.assertEqual(out["verdicts"][0]["verdict"], "consumer-updated", out)
            self.assertEqual(out["ranked_exposed_call_sites"], [])
            self.assertEqual(out["ranked_call_sites"][0]["verdict"], "consumer-updated")

    def test_output_file_and_json_cli(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            ws = Path(td) / "ws"
            shutil.copytree(MEZO_FIXTURE, ws)
            output_path = Path(td) / "out" / "drift.json"

            proc = _run_cli(ws, "--json", "--output", str(output_path))
            self.assertEqual(proc.returncode, 0, proc.stderr)
            stdout_payload = json.loads(proc.stdout)
            file_payload = json.loads(output_path.read_text(encoding="utf-8"))
            self.assertEqual(stdout_payload["schema"], self.tool.SCHEMA)
            self.assertEqual(file_payload["schema"], self.tool.SCHEMA)
            self.assertEqual(
                stdout_payload["ranked_exposed_call_sites"][0]["function"],
                "_requireNoUnderCollateralizedTroves",
            )


if __name__ == "__main__":
    unittest.main()
