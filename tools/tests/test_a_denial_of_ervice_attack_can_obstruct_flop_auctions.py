"""Smoke regression for a-denial-of-ervice-attack-can-obstruct-flop-auctions."""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


REPO = Path(__file__).resolve().parents[2]
DETECTOR = "a-denial-of-ervice-attack-can-obstruct-flop-auctions"
FIXTURE_STEM = "a_denial_of_ervice_attack_can_obstruct_flop_auctions"
FIXTURE_VULN = REPO / "detectors" / "test_fixtures" / f"{FIXTURE_STEM}_vulnerable.sol"
FIXTURE_CLEAN = REPO / "detectors" / "test_fixtures" / f"{FIXTURE_STEM}_clean.sol"
RUN_CUSTOM = REPO / "detectors" / "run_custom.py"


def _python_with_slither() -> str | None:
    candidates = [
        os.environ.get("SLITHER_PYTHON"),
        sys.executable,
        "/opt/homebrew/opt/python@3.13/bin/python3.13",
        "/opt/homebrew/bin/python3.13",
    ]
    seen: set[str] = set()
    for candidate in candidates:
        if not candidate or candidate in seen:
            continue
        seen.add(candidate)
        try:
            probe = subprocess.run(
                [
                    candidate,
                    "-c",
                    "import slither; import slither.detectors.abstract_detector",
                ],
                cwd=REPO,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=10,
            )
        except (OSError, subprocess.TimeoutExpired):
            continue
        if probe.returncode == 0:
            return candidate
    return None


class ADenialOfErviceAttackCanObstructFlopAuctionsSmokeTest(unittest.TestCase):
    def test_vuln_fixture_hits_and_clean_fixture_does_not(self) -> None:
        slither_python = _python_with_slither()
        if slither_python is None:
            self.skipTest(
                "slither-analyzer is not importable by the tested Python "
                "interpreters; install it or set SLITHER_PYTHON"
            )

        self.assertTrue(FIXTURE_VULN.is_file(), f"missing fixture: {FIXTURE_VULN}")
        self.assertTrue(FIXTURE_CLEAN.is_file(), f"missing fixture: {FIXTURE_CLEAN}")

        with tempfile.TemporaryDirectory(prefix="rank22_flop_auctions_") as tmp:
            scratch = Path(tmp)
            shutil.copy2(FIXTURE_VULN, scratch / FIXTURE_VULN.name)
            shutil.copy2(FIXTURE_CLEAN, scratch / FIXTURE_CLEAN.name)
            (scratch / "foundry.toml").write_text(
                '[profile.default]\nsrc = "."\nout = "out"\n',
                encoding="utf-8",
            )
            regression = scratch / "regression.tsv"
            regression.write_text(
                "\n".join(
                    [
                        f"vuln\t{DETECTOR}\t{FIXTURE_VULN.name}\t{DETECTOR}",
                        f"clean\t{DETECTOR}\t{FIXTURE_CLEAN.name}\t{DETECTOR} (clean)",
                        "",
                    ]
                ),
                encoding="utf-8",
            )

            env = os.environ.copy()
            env["AUDITOOOR_FIXTURE_SMOKE_MODE"] = "1"
            proc = subprocess.run(
                [
                    slither_python,
                    str(RUN_CUSTOM),
                    "--batch",
                    str(scratch),
                    str(regression),
                    "--tier=ALL",
                ],
                cwd=REPO,
                env=env,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                timeout=120,
            )

        self.assertEqual(proc.returncode, 0, proc.stdout)
        self.assertIn("Batch regression: 2/2 passed, 0 failed", proc.stdout)


if __name__ == "__main__":
    unittest.main()
