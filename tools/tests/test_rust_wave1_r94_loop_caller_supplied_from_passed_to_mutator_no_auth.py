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
DETECTOR_ID = "r94_loop_caller_supplied_from_passed_to_mutator_no_auth"
_HIT_RE = re.compile(rf"^=== {DETECTOR_ID}\s+\((\d+) hits\)", re.MULTILINE)


def _run_fixture(fixture: Path) -> int:
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
                str(fixture),
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
        return int(match.group(1)) if match else 0
    finally:
        log_path.unlink(missing_ok=True)


class RustWave1CallerSuppliedFromNoAuthTests(unittest.TestCase):
    def test_positive_fixture_fires(self) -> None:
        hits = _run_fixture(
            FIXTURES / "r94_loop_caller_supplied_from_passed_to_mutator_no_auth_positive.rs"
        )
        self.assertEqual(hits, 1)

    def test_negative_fixture_is_silent(self) -> None:
        hits = _run_fixture(
            FIXTURES / "r94_loop_caller_supplied_from_passed_to_mutator_no_auth_negative.rs"
        )
        self.assertEqual(hits, 0)


if __name__ == "__main__":
    unittest.main()
