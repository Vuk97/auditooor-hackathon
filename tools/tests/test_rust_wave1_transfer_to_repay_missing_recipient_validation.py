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
    / "rust_transfer_to_repay_missing_recipient_validation.py"
)
FIXTURES = REPO_ROOT / "detectors" / "rust_wave1" / "test_fixtures"
DETECTOR_ID = "rust_transfer_to_repay_missing_recipient_validation"
POSITIVE = FIXTURES / f"{DETECTOR_ID}_positive.rs"
NEGATIVE = FIXTURES / f"{DETECTOR_ID}_negative.rs"
_HIT_RE = re.compile(rf"^=== {DETECTOR_ID}\s+\((\d+) hits\)", re.MULTILINE)


def _run_fixture(fixture: Path) -> int:
    with tempfile.NamedTemporaryFile(prefix=".rust_missing_recipient_", suffix=".log") as tmp:
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
    return int(match.group(1)) if match else 0


class RustTransferToRepayMissingRecipientValidationTest(unittest.TestCase):
    def test_detector_compiles(self) -> None:
        py_compile.compile(str(DETECTOR), doraise=True)

    def test_positive_fixture_fires(self) -> None:
        self.assertEqual(_run_fixture(POSITIVE), 1)

    def test_negative_fixture_is_silent(self) -> None:
        self.assertEqual(_run_fixture(NEGATIVE), 0)


if __name__ == "__main__":
    unittest.main()
