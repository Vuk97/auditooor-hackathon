"""Smoke regression for the Astaria Seaport collateral-listing detector."""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


REPO = Path(__file__).resolve().parents[2]
ARGUMENT = "a-borrower-can-list-their-collateral-on-seaport-and-receive-almo"
FIXTURE_DIR = REPO / "detectors" / "fixtures" / "a_borrower_can_list_their_collateral_on_seaport_and_receive_almo"
FIXTURE_VULN = FIXTURE_DIR / "ssi-fix-001_positive.sol"
FIXTURE_CLEAN = FIXTURE_DIR / "ssi-fix-001_clean.sol"
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


class ABorrowerCanListCollateralOnSeaportSmokeTest(unittest.TestCase):
    def test_fixture_pair_hits_vulnerable_and_suppresses_clean(self) -> None:
        slither_python = _python_with_slither()
        if slither_python is None:
            self.skipTest("slither-analyzer is not installed in this workspace")

        self.assertTrue(FIXTURE_VULN.is_file(), f"missing fixture: {FIXTURE_VULN}")
        self.assertTrue(FIXTURE_CLEAN.is_file(), f"missing fixture: {FIXTURE_CLEAN}")

        outputs: dict[str, str] = {}
        env = {
            **os.environ,
            "AUDITOOOR_FIXTURE_SMOKE_MODE": "1",
            "AUDITOOOR_SLITHER_NOCACHE": "1",
        }
        for label, fixture in (("vuln", FIXTURE_VULN), ("clean", FIXTURE_CLEAN)):
            with tempfile.TemporaryDirectory(prefix=f"seaport_listing_{label}_") as tmp:
                scratch = Path(tmp)
                isolated = scratch / fixture.name
                shutil.copy2(fixture, isolated)
                proc = subprocess.run(
                    [slither_python, str(RUN_CUSTOM), "--tier=ALL", str(isolated), ARGUMENT],
                    cwd=REPO,
                    env=env,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                    text=True,
                    timeout=120,
                )
                self.assertEqual(proc.returncode, 0, proc.stdout)
                outputs[label] = proc.stdout

        self.assertRegex(outputs["vuln"], r"total hits:\s*[1-9]")
        self.assertRegex(outputs["clean"], r"total hits:\s*0")


if __name__ == "__main__":
    unittest.main()
