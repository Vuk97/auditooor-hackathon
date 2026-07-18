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

DETECTOR = "matching_engine_misprice_fire22"
DETECTOR_PATH = WAVE1_DIR / f"{DETECTOR}.py"
POSITIVE = FIXTURES / f"{DETECTOR}_positive.rs"
NEGATIVE = FIXTURES / f"{DETECTOR}_negative.rs"
_HIT_RE = re.compile(rf"^=== {re.escape(DETECTOR)}\s+\((\d+) hits\)", re.MULTILINE)


def _run_fixture(fixture: Path) -> tuple[int, str]:
    with tempfile.NamedTemporaryFile(prefix=".rust_matching_fire22_", suffix=".log") as tmp:
        proc = subprocess.run(
            [
                sys.executable,
                str(RUST_DETECT),
                str(FIXTURES),
                "--only",
                DETECTOR,
                "--file",
                str(fixture),
                "--log",
                tmp.name,
            ],
            cwd=REPO_ROOT,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            timeout=60,
        )
        if proc.returncode != 0:
            raise AssertionError(proc.stdout)
        log_text = Path(tmp.name).read_text(encoding="utf-8", errors="ignore")

    match = _HIT_RE.search(log_text)
    return int(match.group(1)) if match else 0, log_text


class RustMatchingEngineMispriceFire22Tests(unittest.TestCase):
    def test_detector_and_test_compile(self) -> None:
        py_compile.compile(str(DETECTOR_PATH), doraise=True)
        py_compile.compile(str(Path(__file__)), doraise=True)

    def test_positive_fixture_fires_on_three_confirmed_shapes(self) -> None:
        fixture_text = POSITIVE.read_text(encoding="utf-8")
        self.assertIn("self.book.last_px", fixture_text)
        self.assertIn("Side::Buy => self.book.best_bid()", fixture_text)
        self.assertIn("underlying_price: u128", fixture_text)

        hits, log_text = _run_fixture(POSITIVE)
        self.assertEqual(hits, 3, log_text)
        self.assertIn("stale orderbook last price", log_text)
        self.assertIn("wrong-side book price", log_text)
        self.assertIn("unbound underlying price", log_text)
        self.assertIn("matching-engine-misprice", log_text)

    def test_negative_fixture_uses_oracle_or_current_book_and_is_silent(self) -> None:
        fixture_text = NEGATIVE.read_text(encoding="utf-8")
        self.assertIn("checked_mark_price", fixture_text)
        self.assertIn("price_for_side", fixture_text)
        self.assertIn("Side::Buy => self.best_ask()", fixture_text)
        self.assertIn("Side::Sell => self.best_bid()", fixture_text)

        hits, log_text = _run_fixture(NEGATIVE)
        self.assertEqual(hits, 0, log_text)


if __name__ == "__main__":
    unittest.main()
