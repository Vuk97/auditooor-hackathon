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
DETECTOR_ID = "state_change_between_check_and_use_after_callback"
_HIT_RE = re.compile(rf"^=== {DETECTOR_ID}\s+\((\d+) hits\)", re.MULTILINE)


def _run_fixture(fixture: Path) -> tuple[int, str]:
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
        return (int(match.group(1)) if match else 0, text)
    finally:
        log_path.unlink(missing_ok=True)


class RustWave1StateChangeBetweenCheckAndUseAfterCallbackTests(unittest.TestCase):
    def test_positive_fixture_fires_on_cached_state_reuse_after_callback(self) -> None:
        hits, log_text = _run_fixture(
            FIXTURES / f"{DETECTOR_ID}_positive.rs"
        )
        self.assertGreaterEqual(hits, 1, log_text)
        self.assertIn("cached state value `cached_remaining`", log_text)
        self.assertIn(f"=== {DETECTOR_ID}  (1 hits) ===", log_text)

    def test_clean_fixture_reloads_and_revalidates_after_callback(self) -> None:
        hits, log_text = _run_fixture(
            FIXTURES / f"{DETECTOR_ID}_clean.rs"
        )
        self.assertEqual(hits, 0, log_text)


if __name__ == "__main__":
    unittest.main()
