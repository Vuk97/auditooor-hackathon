from __future__ import annotations

import re
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


HERE = Path(__file__).resolve().parent
REPO_ROOT = HERE.parent.parent
RUST_DETECT = REPO_ROOT / "tools" / "rust-detect.py"
FIXTURES = REPO_ROOT / "detectors" / "rust_wave1" / "test_fixtures"
DETECTOR_ID = "reentrancy_external_call_before_accounting_fire16"
_HIT_RE = re.compile(rf"^=== {DETECTOR_ID}\s+\((\d+) hits\)", re.MULTILINE)


def _run_fixture(fixture_name: str) -> tuple[int, str]:
    with tempfile.NamedTemporaryFile(suffix=".log", delete=False) as tf:
        log_path = Path(tf.name)
    try:
        proc = subprocess.run(
            [
                sys.executable,
                str(RUST_DETECT),
                str(FIXTURES),
                "--only",
                DETECTOR_ID,
                "--file",
                str(FIXTURES / fixture_name),
                "--log",
                str(log_path),
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=False,
        )
        if proc.returncode != 0:
            raise AssertionError(proc.stderr or proc.stdout)
        text = log_path.read_text(encoding="utf-8", errors="ignore")
        match = _HIT_RE.search(text)
        return (int(match.group(1)) if match else 0, text)
    finally:
        log_path.unlink(missing_ok=True)


class RustReentrancyExternalCallBeforeAccountingFire16Tests(unittest.TestCase):
    def test_positive_fixture_fires_on_three_same_class_shapes(self) -> None:
        hits, log_text = _run_fixture(
            "reentrancy_external_call_before_accounting_fire16_positive.rs"
        )
        self.assertEqual(hits, 3, log_text)
        self.assertIn("before finalizing accounting state", log_text)
        self.assertIn("writes accounting state", log_text)
        self.assertIn("reads Curve virtual price", log_text)

    def test_negative_fixture_is_silent_when_guarded_or_probed(self) -> None:
        hits, log_text = _run_fixture(
            "reentrancy_external_call_before_accounting_fire16_negative.rs"
        )
        self.assertEqual(hits, 0, log_text)


if __name__ == "__main__":
    unittest.main()
