"""Smoke regression for a-flashloan-will-be-broken-if-the-usdt-fee-is-more-than-zero."""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


REPO = Path(__file__).resolve().parents[2]
DETECTOR = "a-flashloan-will-be-broken-if-the-usdt-fee-is-more-than-zero"
FIXTURE_DIR = REPO / "detectors" / "fixtures" / "a_flashloan_will_be_broken_if_the_usdt_fee_is_more_than_zero"
FIXTURE_POSITIVE = FIXTURE_DIR / "ssi-fix-011_positive.sol"
FIXTURE_CLEAN = FIXTURE_DIR / "ssi-fix-011_clean.sol"
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
                [candidate, "-c", "import slither; import slither.detectors.abstract_detector"],
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


class AFlashloanWillBeBrokenIfUsdtFeeMoreThanZeroSmokeTest(unittest.TestCase):
    def test_positive_fixture_hits_and_clean_fixture_does_not(self) -> None:
        slither_python = _python_with_slither()
        if slither_python is None:
            self.skipTest(
                "slither-analyzer is not importable by the tested Python interpreters; "
                "install it or set SLITHER_PYTHON"
            )

        self.assertTrue(FIXTURE_POSITIVE.is_file(), f"missing fixture: {FIXTURE_POSITIVE}")
        self.assertTrue(FIXTURE_CLEAN.is_file(), f"missing fixture: {FIXTURE_CLEAN}")

        with tempfile.TemporaryDirectory(prefix="flashloan_usdt_fee_") as tmp:
            scratch = Path(tmp)
            shutil.copy2(FIXTURE_POSITIVE, scratch / FIXTURE_POSITIVE.name)
            shutil.copy2(FIXTURE_CLEAN, scratch / FIXTURE_CLEAN.name)
            (scratch / "foundry.toml").write_text('[profile.default]\nsrc = "."\nout = "out"\n', encoding="utf-8")
            regression = scratch / "regression.tsv"
            regression.write_text(
                "\n".join(
                    [
                        f"vuln\t{DETECTOR}\t{FIXTURE_POSITIVE.name}\t{DETECTOR}",
                        f"clean\t{DETECTOR}\t{FIXTURE_CLEAN.name}\t{DETECTOR} (clean)",
                        "",
                    ]
                ),
                encoding="utf-8",
            )

            env = os.environ.copy()
            env["AUDITOOOR_FIXTURE_SMOKE_MODE"] = "1"
            env["AUDITOOOR_SLITHER_NOCACHE"] = "1"
            proc = subprocess.run(
                [slither_python, str(RUN_CUSTOM), "--batch", str(scratch), str(regression), "--tier=ALL"],
                cwd=REPO,
                env=env,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                timeout=120,
            )

        self.assertEqual(proc.returncode, 0, proc.stdout)
        self.assertIn("Batch regression: 2/2 passed, 0 failed", proc.stdout)

    def test_classic_runner_discriminates_fixture_pair_across_duplicate_argument(self) -> None:
        slither_python = _python_with_slither()
        if slither_python is None:
            self.skipTest(
                "slither-analyzer is not importable by the tested Python interpreters; "
                "install it or set SLITHER_PYTHON"
            )

        self.assertTrue(FIXTURE_POSITIVE.is_file(), f"missing fixture: {FIXTURE_POSITIVE}")
        self.assertTrue(FIXTURE_CLEAN.is_file(), f"missing fixture: {FIXTURE_CLEAN}")

        env = os.environ.copy()
        env["AUDITOOOR_FIXTURE_SMOKE_MODE"] = "1"
        env["AUDITOOOR_SLITHER_NOCACHE"] = "1"
        positive_proc = subprocess.run(
            [slither_python, str(RUN_CUSTOM), "--tier=ALL", str(FIXTURE_POSITIVE), DETECTOR],
            cwd=REPO,
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            timeout=120,
        )
        clean_proc = subprocess.run(
            [slither_python, str(RUN_CUSTOM), "--tier=ALL", str(FIXTURE_CLEAN), DETECTOR],
            cwd=REPO,
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            timeout=120,
        )

        self.assertEqual(positive_proc.returncode, 0, positive_proc.stdout)
        self.assertEqual(clean_proc.returncode, 0, clean_proc.stdout)
        self.assertRegex(positive_proc.stdout, r"\[done\] total hits: [1-9]\d*")
        self.assertIn("[done] total hits: 0", clean_proc.stdout)


if __name__ == "__main__":
    unittest.main()
