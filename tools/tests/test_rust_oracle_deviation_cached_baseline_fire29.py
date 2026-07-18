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
FIXTURES = REPO_ROOT / "detectors" / "rust_wave1" / "test_fixtures"
DETECTOR = (
    REPO_ROOT
    / "detectors"
    / "rust_wave1"
    / "rust_oracle_deviation_cached_baseline_fire29.py"
)
DETECTOR_ID = "rust_oracle_deviation_cached_baseline_fire29"
POSITIVE = FIXTURES / "rust_oracle_deviation_cached_baseline_fire29_positive.rs"
NEGATIVE = FIXTURES / "rust_oracle_deviation_cached_baseline_fire29_negative.rs"
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
            cwd=REPO_ROOT,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=False,
            timeout=30,
        )
        if proc.returncode != 0:
            raise AssertionError(proc.stderr or proc.stdout)
        text = log_path.read_text(encoding="utf-8", errors="ignore")
        match = _HIT_RE.search(text)
        return int(match.group(1)) if match else 0, text
    finally:
        log_path.unlink(missing_ok=True)


class RustOracleDeviationCachedBaselineFire29Tests(unittest.TestCase):
    def test_detector_and_test_compile(self) -> None:
        py_compile.compile(str(DETECTOR), doraise=True)
        py_compile.compile(__file__, doraise=True)

    def test_positive_fixture_fires_on_live_cache_update_before_final_guards(self) -> None:
        hits, log_text = _run_fixture(POSITIVE)
        self.assertGreaterEqual(hits, 2, log_text)
        self.assertIn("update_price_cached_baseline_before_freshness", log_text)
        self.assertIn("heartbeat_rolls_timestamp_cache_before_round_guard", log_text)
        self.assertIn("before all oracle guards finish", log_text)

    def test_negative_fixture_is_silent_on_validate_then_update_and_pending_stage(self) -> None:
        hits, log_text = _run_fixture(NEGATIVE)
        self.assertEqual(hits, 0, log_text)
        negative_text = NEGATIVE.read_text(encoding="utf-8")
        self.assertIn("update_price_after_all_guards", negative_text)
        self.assertIn("update_price_with_validate_before_cache", negative_text)
        self.assertIn("pending_cached_price", negative_text)

    def test_no_unicode_dashes_in_owned_sources(self) -> None:
        for path in (DETECTOR, POSITIVE, NEGATIVE, Path(__file__)):
            with self.subTest(path=path.name):
                text = path.read_text(encoding="utf-8")
                self.assertIsNone(re.search("[\u2013\u2014]", text))


if __name__ == "__main__":
    unittest.main()
