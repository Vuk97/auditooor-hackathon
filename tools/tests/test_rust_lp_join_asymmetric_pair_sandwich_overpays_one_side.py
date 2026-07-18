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
DETECTOR_ID = "lp_join_asymmetric_pair_sandwich_overpays_one_side"
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


class RustLpJoinAsymmetricPairSandwichTests(unittest.TestCase):
    def test_named_positive_fixture_flags_min_ratio_join(self) -> None:
        hits, log_text = _run_fixture(
            FIXTURES / "lp_join_asymmetric_pair_sandwich_overpays_one_side_positive.rs"
        )
        self.assertGreaterEqual(hits, 1, log_text)
        self.assertIn("without min-out or proportionality guards", log_text)

    def test_named_negative_fixture_is_silent_on_guards(self) -> None:
        hits, log_text = _run_fixture(
            FIXTURES / "lp_join_asymmetric_pair_sandwich_overpays_one_side_negative.rs"
        )
        self.assertEqual(hits, 0, log_text)

    def test_short_r94_positive_fixture_also_flags(self) -> None:
        hits, log_text = _run_fixture(
            FIXTURES / "r94_loop_lp_join_asymmetric_min_ratio_sandwich_overpay_positive.rs"
        )
        self.assertGreaterEqual(hits, 1, log_text)

    def test_short_r94_negative_fixture_is_silent_on_min_out(self) -> None:
        hits, log_text = _run_fixture(
            FIXTURES / "r94_loop_lp_join_asymmetric_min_ratio_sandwich_overpay_negative.rs"
        )
        self.assertEqual(hits, 0, log_text)


if __name__ == "__main__":
    unittest.main()
