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
    / "missing_recipient_or_sender_validation_fire9.py"
)
FIXTURES = REPO_ROOT / "detectors" / "rust_wave1" / "test_fixtures"
DETECTOR_ID = "missing_recipient_or_sender_validation_fire9"
POSITIVE = FIXTURES / f"{DETECTOR_ID}_positive.rs"
NEGATIVE = FIXTURES / f"{DETECTOR_ID}_negative.rs"
POSITIVE_FIRE14 = FIXTURES / "missing_recipient_or_sender_validation_fire14_positive.rs"
NEGATIVE_FIRE14 = FIXTURES / "missing_recipient_or_sender_validation_fire14_negative.rs"
_HIT_RE = re.compile(rf"^=== {DETECTOR_ID}\s+\((\d+) hits\)", re.MULTILINE)


def _run_fixture(fixture: Path) -> tuple[int, str]:
    with tempfile.NamedTemporaryFile(prefix=".rust_fire9_missing_recipient_", suffix=".log") as tmp:
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


class RustMissingRecipientOrSenderValidationFire9Test(unittest.TestCase):
    def test_detector_compiles(self) -> None:
        py_compile.compile(str(DETECTOR), doraise=True)

    def test_positive_fixture_fires_on_confirmed_shapes(self) -> None:
        hits, log_text = _run_fixture(POSITIVE)
        self.assertEqual(hits, 3, log_text)
        self.assertIn("requested_recipient", log_text)
        self.assertIn("notification sender", log_text)
        self.assertIn("remaining_accounts", log_text)

    def test_negative_fixture_is_silent(self) -> None:
        hits, log_text = _run_fixture(NEGATIVE)
        self.assertEqual(hits, 0, log_text)

    def test_fire14_identity_accounting_fixture_fires(self) -> None:
        hits, log_text = _run_fixture(POSITIVE_FIRE14)
        self.assertEqual(hits, 2, log_text)
        self.assertIn("treasury", log_text)
        self.assertIn("operator", log_text)
        self.assertIn("destination", log_text)

    def test_fire14_identity_accounting_negative_is_silent(self) -> None:
        hits, log_text = _run_fixture(NEGATIVE_FIRE14)
        self.assertEqual(hits, 0, log_text)


if __name__ == "__main__":
    unittest.main()
