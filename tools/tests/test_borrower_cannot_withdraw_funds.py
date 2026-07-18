from __future__ import annotations

import json
import os
import re
import subprocess
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
RUNNER = ROOT / "detectors" / "run_custom.py"
PATTERN = "borrower-cannot-withdraw-funds"
FIXTURE_DIR = ROOT / "detectors" / "fixtures" / "borrower_cannot_withdraw_funds"
POSITIVE = FIXTURE_DIR / "ssi-fix-051_positive.sol"
CLEAN = FIXTURE_DIR / "ssi-fix-051_clean.sol"
SMOKE = FIXTURE_DIR / "ssi-fix-051_smoke.json"
DSL = ROOT / "detectors" / "_specs" / "drafts_audit_text" / "borrower-cannot-withdraw-funds.yaml"
DETECTOR = ROOT / "detectors" / "wave14" / "borrower_cannot_withdraw_funds.py"


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
            proc = subprocess.run(
                [candidate, "-c", "import slither; import slither.detectors.abstract_detector"],
                cwd=ROOT,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=10,
            )
        except (OSError, subprocess.TimeoutExpired):
            continue
        if proc.returncode == 0:
            return candidate
    return None


class BorrowerCannotWithdrawFundsTest(unittest.TestCase):
    def _hits(self, fixture: Path) -> int:
        slither_python = _python_with_slither()
        if slither_python is None:
            self.skipTest("slither-analyzer is not importable by the tested Python interpreters")

        env = os.environ.copy()
        env["AUDITOOOR_FIXTURE_SMOKE_MODE"] = "1"
        env["AUDITOOOR_SLITHER_NOCACHE"] = "1"
        proc = subprocess.run(
            [slither_python, str(RUNNER), "--tier=ALL", str(fixture), PATTERN],
            cwd=ROOT,
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            timeout=120,
        )
        self.assertEqual(proc.returncode, 0, proc.stdout)
        match = re.search(r"total hits:\s*(\d+)", proc.stdout)
        self.assertIsNotNone(match, proc.stdout)
        return int(match.group(1))

    def test_row_artifacts_are_wired_to_owned_fixture_pair(self) -> None:
        self.assertTrue(DETECTOR.is_file())
        text = DSL.read_text(encoding="utf-8")
        self.assertIn('fn_name_regex: ".*(withdraw|onlyBorrower|loanState).*"', text)
        self.assertIn('guard_require_line: "require(amount <= balance, \\"insufficient balance\\");"', text)
        self.assertTrue(POSITIVE.is_file())
        self.assertTrue(CLEAN.is_file())

    def test_smoke_record_captures_positive_and_clean_counts(self) -> None:
        payload = json.loads(SMOKE.read_text(encoding="utf-8"))
        self.assertEqual(payload["status"], "smoke_pass")
        self.assertGreaterEqual(payload["vulnerable_hits"], 1)
        self.assertEqual(payload["clean_hits"], 0)

    def test_positive_fixture_fires_and_clean_fixture_stays_quiet(self) -> None:
        self.assertGreaterEqual(self._hits(POSITIVE), 1)
        self.assertEqual(self._hits(CLEAN), 0)


if __name__ == "__main__":
    unittest.main()
