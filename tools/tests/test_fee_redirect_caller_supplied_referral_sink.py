from __future__ import annotations

import os
import py_compile
import re
import subprocess
import sys
import unittest
from pathlib import Path

import yaml


ROOT = Path(__file__).resolve().parents[2]
RUNNER = ROOT / "detectors" / "run_custom.py"
PATTERN = "fee-redirect-caller-supplied-referral-sink"
DETECTOR = ROOT / "detectors" / "wave17" / "fee_redirect_caller_supplied_referral_sink.py"
REFERENCE = ROOT / "reference" / "patterns.dsl" / f"{PATTERN}.yaml"
FIXTURE_DIR = ROOT / "detectors" / "fixtures" / "fee_redirect_caller_supplied_referral_sink"
POSITIVE = FIXTURE_DIR / "positive.sol"
CLEAN = FIXTURE_DIR / "clean.sol"
EXISTING_DIRECT_SINK = "fee-redirect-user-controlled-sink"
EXISTING_COLLECTOR_SINK = "fee-redirect-user-controlled-collector-or-sink"


def _python_with_slither() -> str | None:
    candidates = [
        os.environ.get("SLITHER_PYTHON"),
        sys.executable,
        "/opt/homebrew/opt/python@3.13/bin/python3.13",
        "/opt/homebrew/bin/python3.13",
        "python3",
    ]
    seen: set[str] = set()
    for candidate in candidates:
        if not candidate or candidate in seen:
            continue
        seen.add(candidate)
        try:
            probe = subprocess.run(
                [candidate, "-c", "import slither; import slither.detectors.abstract_detector"],
                cwd=ROOT,
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


class FeeRedirectCallerSuppliedReferralSinkTest(unittest.TestCase):
    def _hits(self, fixture: Path, pattern: str = PATTERN) -> tuple[int, str]:
        slither_python = _python_with_slither()
        if slither_python is None:
            self.skipTest("slither-analyzer is not importable by the tested Python interpreters")

        env = os.environ.copy()
        env["AUDITOOOR_FIXTURE_SMOKE_MODE"] = "1"
        env["AUDITOOOR_SLITHER_NOCACHE"] = "1"
        proc = subprocess.run(
            [slither_python, str(RUNNER), "--tier=ALL", str(fixture), pattern],
            cwd=ROOT,
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            timeout=120,
        )
        self.assertEqual(proc.returncode, 0, proc.stdout)
        self.assertIn(pattern, proc.stdout)
        match = re.search(r"total hits:\s*(\d+)", proc.stdout)
        self.assertIsNotNone(match, proc.stdout)
        return int(match.group(1)), proc.stdout

    def test_detector_compiles_and_reference_is_fee_redirect(self) -> None:
        py_compile.compile(str(DETECTOR), doraise=True)
        spec = yaml.safe_load(REFERENCE.read_text(encoding="utf-8"))
        self.assertEqual(spec["pattern"], PATTERN)
        self.assertIn("fee-redirect", spec["tags"])
        self.assertEqual(
            spec["fixtures"]["vuln"],
            "detectors/fixtures/fee_redirect_caller_supplied_referral_sink/positive.sol",
        )
        self.assertEqual(
            spec["fixtures"]["clean"],
            "detectors/fixtures/fee_redirect_caller_supplied_referral_sink/clean.sol",
        )
        self.assertEqual(spec["submission_posture"], "NOT_SUBMIT_READY")

    def test_positive_fixture_fires_and_clean_fixture_is_silent(self) -> None:
        positive_hits, positive_stdout = self._hits(POSITIVE)
        clean_hits, clean_stdout = self._hits(CLEAN)
        self.assertEqual(positive_hits, 1, positive_stdout)
        self.assertEqual(clean_hits, 0, clean_stdout)

    def test_existing_fee_redirect_detectors_do_not_catch_referral_shape(self) -> None:
        direct_hits, direct_stdout = self._hits(POSITIVE, EXISTING_DIRECT_SINK)
        collector_hits, collector_stdout = self._hits(POSITIVE, EXISTING_COLLECTOR_SINK)
        self.assertEqual(direct_hits, 0, direct_stdout)
        self.assertEqual(collector_hits, 0, collector_stdout)

    def test_clean_fixture_has_bounded_configured_protocol_owned_fee_sink(self) -> None:
        positive = POSITIVE.read_text(encoding="utf-8")
        clean = CLEAN.read_text(encoding="utf-8")

        self.assertIn("function buyPass(uint256 amount, address referral) external", positive)
        self.assertIn("token.safeTransfer(referral, referralFee);", positive)
        self.assertNotIn("approvedReferral", positive)
        self.assertNotIn("MAX_REFERRAL_SHARE_BPS", positive)

        self.assertIn("MAX_REFERRAL_SHARE_BPS", clean)
        self.assertIn("approvedReferral[referral]", clean)
        self.assertIn("referralVault", clean)
        self.assertIn("token.safeTransfer(referralSink, referralFee);", clean)


if __name__ == "__main__":
    unittest.main()
