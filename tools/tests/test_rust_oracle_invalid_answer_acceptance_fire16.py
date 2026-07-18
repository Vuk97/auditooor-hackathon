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
WAVE1_DIR = REPO_ROOT / "detectors" / "rust_wave1"
FIXTURES = WAVE1_DIR / "test_fixtures"
DETECTOR = "oracle_invalid_answer_acceptance_fire16"
DETECTOR_PATH = WAVE1_DIR / f"{DETECTOR}.py"
_HIT_RE = re.compile(rf"^=== {DETECTOR}\s+\((\d+) hits\)", re.MULTILINE)


def _run_fixture(fixture_name: str) -> tuple[int, str]:
    with tempfile.NamedTemporaryFile(prefix=".rust_oracle_fire16_", suffix=".log") as tmp:
        proc = subprocess.run(
            [
                sys.executable,
                str(RUST_DETECT),
                str(FIXTURES),
                "--only",
                DETECTOR,
                "--file",
                str(FIXTURES / fixture_name),
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
        log_text = Path(tmp.name).read_text(encoding="utf-8", errors="ignore")

    match = _HIT_RE.search(log_text)
    return (int(match.group(1)) if match else 0, log_text)


class RustOracleInvalidAnswerAcceptanceFire16Tests(unittest.TestCase):
    def test_detector_compiles(self) -> None:
        py_compile.compile(str(DETECTOR_PATH), doraise=True)

    def test_fire16_positive_fixture_fires_on_three_invalid_answer_shapes(self) -> None:
        hits, log_text = _run_fixture(
            "oracle_invalid_answer_acceptance_fire16_positive.rs"
        )
        self.assertEqual(hits, 3, log_text)
        self.assertIn("signed oracle answer cast", log_text)
        self.assertIn("signed confidence delta", log_text)
        self.assertIn("caller-supplied feed id", log_text)

    def test_fire16_negative_fixture_is_silent(self) -> None:
        hits, log_text = _run_fixture(
            "oracle_invalid_answer_acceptance_fire16_negative.rs"
        )
        self.assertEqual(hits, 0, log_text)

    def test_confirmed_chainlink_negative_price_miss_fires(self) -> None:
        hits, log_text = _run_fixture(
            "r94_loop_chainlink_negative_price_not_rejected_signed_cast_positive.rs"
        )
        self.assertGreaterEqual(hits, 1, log_text)
        self.assertIn("signed oracle answer cast", log_text)

    def test_confirmed_chainlink_negative_price_clean_is_silent(self) -> None:
        hits, log_text = _run_fixture(
            "r94_loop_chainlink_negative_price_not_rejected_signed_cast_negative.rs"
        )
        self.assertEqual(hits, 0, log_text)

    def test_confirmed_confidence_negative_accept_miss_fires(self) -> None:
        hits, log_text = _run_fixture(
            "r94_loop_oracle_confidence_negative_accept_positive.rs"
        )
        self.assertGreaterEqual(hits, 1, log_text)
        self.assertIn("signed confidence delta", log_text)

    def test_confirmed_confidence_negative_accept_clean_is_silent(self) -> None:
        hits, log_text = _run_fixture(
            "r94_loop_oracle_confidence_negative_accept_negative.rs"
        )
        self.assertEqual(hits, 0, log_text)

    def test_confirmed_feed_id_mismatch_miss_fires(self) -> None:
        hits, log_text = _run_fixture("r94_loop_oracle_feed_id_mismatch_positive.rs")
        self.assertGreaterEqual(hits, 1, log_text)
        self.assertIn("caller-supplied feed id", log_text)

    def test_confirmed_feed_id_mismatch_clean_is_silent(self) -> None:
        hits, log_text = _run_fixture("r94_loop_oracle_feed_id_mismatch_negative.rs")
        self.assertEqual(hits, 0, log_text)


if __name__ == "__main__":
    unittest.main()
