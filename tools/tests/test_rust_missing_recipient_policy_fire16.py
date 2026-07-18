from __future__ import annotations

import py_compile
import re
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


HERE = Path(__file__).resolve().parent
REPO_ROOT = HERE.parent.parent
RUST_DETECT = REPO_ROOT / "tools" / "rust-detect.py"
DETECTOR = (
    REPO_ROOT
    / "detectors"
    / "rust_wave1"
    / "missing_recipient_policy_fire16.py"
)
FIXTURES = REPO_ROOT / "detectors" / "rust_wave1" / "test_fixtures"
DETECTOR_ID = "missing_recipient_policy_fire16"
POSITIVE = FIXTURES / f"{DETECTOR_ID}_positive.rs"
NEGATIVE = FIXTURES / f"{DETECTOR_ID}_negative.rs"
ZERO_ADDRESS_MISS = FIXTURES / "missing_input_validation_zero_address_positive.rs"
BURN_SENDER_MISS = FIXTURES / "r94_loop_burn_notification_sender_unvalidated_positive.rs"
_HIT_RE = re.compile(rf"^=== {DETECTOR_ID}\s+\((\d+) hits\)", re.MULTILINE)


def _run_fixture(fixture: Path) -> tuple[int, str]:
    with tempfile.NamedTemporaryFile(prefix=".rust_fire16_missing_recipient_", suffix=".log") as tmp:
        proc = subprocess.run(
            [
                sys.executable,
                str(RUST_DETECT),
                str(FIXTURES),
                "--only",
                DETECTOR_ID,
                "--file",
                str(fixture),
                "--log",
                tmp.name,
            ],
            cwd=REPO_ROOT,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            timeout=120,
        )
        if proc.returncode != 0:
            raise AssertionError(proc.stdout)
        text = Path(tmp.name).read_text(encoding="utf-8", errors="ignore")
    match = _HIT_RE.search(text)
    return (int(match.group(1)) if match else 0, text)


class RustMissingRecipientPolicyFire16Test(unittest.TestCase):
    def test_detector_compiles(self) -> None:
        py_compile.compile(str(DETECTOR), doraise=True)

    def test_positive_fixture_fires_on_policy_shapes(self) -> None:
        hits, log_text = _run_fixture(POSITIVE)
        self.assertEqual(hits, 3, log_text)
        self.assertIn("treasury", log_text)
        self.assertIn("operator", log_text)
        self.assertIn("notification sender", log_text)
        self.assertIn("destination", log_text)

    def test_negative_fixture_is_silent(self) -> None:
        hits, log_text = _run_fixture(NEGATIVE)
        self.assertEqual(hits, 0, log_text)

    def test_confirmed_zero_address_miss_now_fires(self) -> None:
        hits, log_text = _run_fixture(ZERO_ADDRESS_MISS)
        self.assertEqual(hits, 2, log_text)

    def test_confirmed_burn_sender_miss_now_fires(self) -> None:
        hits, log_text = _run_fixture(BURN_SENDER_MISS)
        self.assertEqual(hits, 1, log_text)


if __name__ == "__main__":
    unittest.main()
