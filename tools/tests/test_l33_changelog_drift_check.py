#!/usr/bin/env python3
"""Regression coverage for L33 changelog drift coverage."""

from __future__ import annotations

import json
import shutil
import subprocess
import sys
import tempfile
import textwrap
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
TOOL = ROOT / "tools" / "l33-changelog-drift-check.py"
FIXTURES = ROOT / "tools" / "tests" / "fixtures" / "changelog_source_drift_miner"
MEZO_FIXTURE = FIXTURES / "mezo_stale_tail"


def _write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(textwrap.dedent(text).strip() + "\n", encoding="utf-8")


def _draft(ws: Path, body: str, *, lane: str = "paste_ready") -> Path:
    draft = ws / "submissions" / lane / "candidate.md"
    draft.parent.mkdir(parents=True, exist_ok=True)
    draft.write_text(textwrap.dedent(body).strip() + "\n", encoding="utf-8")
    return draft


def _run(draft: Path, *args: str, workspace: Path | None = None) -> subprocess.CompletedProcess[str]:
    argv = [sys.executable, str(TOOL), str(draft), "--json", *args]
    if workspace is not None:
        argv.extend(["--workspace", str(workspace)])
    return subprocess.run(argv, capture_output=True, text=True, check=False)


class L33ChangelogDriftCheckTests(unittest.TestCase):
    def test_passes_with_exposed_drift(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            ws = Path(td) / "ws"
            shutil.copytree(MEZO_FIXTURE, ws)
            draft = _draft(
                ws,
                """
                # StabilityPool stale ordering claim

                Severity: High
                The old ordering assumption is stale after CHANGELOG.md:2.
                `src/StabilityPool.sol` still relies on the outdated tail invariant.
                """,
            )

            proc = _run(draft, workspace=ws)
            self.assertEqual(proc.returncode, 0, proc.stderr)
            payload = json.loads(proc.stdout)
            self.assertEqual(payload["verdict"], "pass-exposed-drift")
            self.assertTrue(payload["triggered"])
            self.assertGreater(payload["miner"]["exposed_count"], 0)

    def test_fails_when_stale_claim_lacks_miner_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            ws = Path(td) / "ws"
            (ws / "submissions" / "paste_ready").mkdir(parents=True)
            _write(
                ws / "CHANGELOG.md",
                """
                - SortedTroves ordering changed; previously `getLast()` returned the worst ICR tail.
                """,
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
            draft = _draft(
                ws,
                """
                # Already migrated ordering claim

                Severity: High
                The stale invariant is no longer valid after CHANGELOG.md:1.
                `src/StabilityPool.sol` had an ordering changed migration.
                """,
            )

            proc = _run(draft, workspace=ws)
            self.assertEqual(proc.returncode, 1, proc.stdout)
            payload = json.loads(proc.stdout)
            self.assertEqual(payload["verdict"], "fail-no-exposed-drift")
            self.assertEqual(payload["miner"]["exposed_count"], 0)

    def test_rebuttal_allows_stale_claim_without_exposed_row(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            ws = Path(td) / "ws"
            (ws / "submissions" / "paste_ready").mkdir(parents=True)
            _write(
                ws / "CHANGELOG.md",
                """
                - SortedTroves ordering changed; previously `getLast()` returned the worst ICR tail.
                """,
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
            draft = _draft(
                ws,
                """
                # Rebutted ordering note

                Severity: High
                <!-- l33-rebuttal: changelog note quotes a migrated consumer and does not claim a live stale dependency -->
                This outdated ordering note cites CHANGELOG.md:1 for historical context only.
                Solidity path: `src/StabilityPool.sol`.
                """,
            )

            proc = _run(draft, workspace=ws)
            self.assertEqual(proc.returncode, 0, proc.stderr)
            payload = json.loads(proc.stdout)
            self.assertEqual(payload["verdict"], "ok-rebuttal")
            self.assertTrue(payload["rebuttal"]["accepted"])

    def test_non_solidity_non_stale_draft_is_out_of_scope(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            ws = Path(td) / "ws"
            draft = _draft(
                ws,
                """
                # Generic note

                Severity: Low
                This write-up discusses dashboard copy only.
                Release notes are attached separately.
                """,
            )

            proc = _run(draft, workspace=ws)
            self.assertEqual(proc.returncode, 0, proc.stderr)
            payload = json.loads(proc.stdout)
            self.assertEqual(payload["verdict"], "not-applicable")
            self.assertFalse(payload["triggered"])

    def test_hook_mode_writes_advisory_sidecar_when_workspace_missing(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            draft = root / "candidate.md"
            draft.write_text(
                textwrap.dedent(
                    """
                    # Solidity changelog note

                    CHANGELOG.md:7 says the tail ordering changed and is no longer valid.
                    `src/Vault.sol` still appears stale.
                    """
                ).strip()
                + "\n",
                encoding="utf-8",
            )

            proc = _run(draft, "--mode", "hook", "--write-sidecar")
            self.assertEqual(proc.returncode, 2, proc.stdout)
            payload = json.loads(proc.stdout)
            self.assertEqual(payload["verdict"], "advisory-workspace-unresolved")
            sidecar = Path(payload["sidecar_path"])
            self.assertTrue(sidecar.is_file(), sidecar)


if __name__ == "__main__":
    unittest.main(verbosity=2)
