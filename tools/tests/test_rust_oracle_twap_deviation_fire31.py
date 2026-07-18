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
DETECTOR = "rust_oracle_twap_deviation_fire31"
DETECTOR_PATH = WAVE1_DIR / f"{DETECTOR}.py"
POSITIVE = FIXTURES / f"{DETECTOR}_positive.rs"
NEGATIVE = FIXTURES / f"{DETECTOR}_negative.rs"

_HIT_RE = re.compile(rf"^=== {DETECTOR}\s+\((\d+) hits\)", re.MULTILINE)


def _run_fixture(fixture: Path) -> tuple[int, str]:
    with tempfile.NamedTemporaryFile(prefix=".rust_oracle_fire31_", suffix=".log") as tmp:
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


class RustOracleTwapDeviationFire31Tests(unittest.TestCase):
    def test_detector_and_test_compile(self) -> None:
        py_compile.compile(str(DETECTOR_PATH), doraise=True)
        py_compile.compile(str(Path(__file__)), doraise=True)

    def test_positive_fixture_fires_on_spot_and_cached_acceptance(self) -> None:
        positive_text = POSITIVE.read_text(encoding="utf-8")
        self.assertIn("feed.latest_price", positive_text)
        self.assertIn("self.last_price_data.price", positive_text)
        self.assertIn("borrower.debt = borrower.debt.saturating_add", positive_text)

        hits, log_text = _run_fixture(POSITIVE)
        self.assertEqual(hits, 2, log_text)
        self.assertIn("borrow_against_spot_oracle_no_twap", log_text)
        self.assertIn("get_asset_prices_batch_accepts_cached_without_guard", log_text)
        self.assertIn("oracle-price-manipulation", log_text)

    def test_negative_fixture_is_silent_on_twap_heartbeat_and_shutdown(self) -> None:
        negative_text = NEGATIVE.read_text(encoding="utf-8")
        self.assertIn("return Err(OracleError::Shutdown)", negative_text)
        self.assertIn("self.ensure_fresh(round.updated_at, now)", negative_text)
        self.assertIn("self.ensure_deviation(round.price", negative_text)
        self.assertIn("self.safe_twap_price", negative_text)
        self.assertIn("cache_age > self.asset_config.max_age", negative_text)

        hits, log_text = _run_fixture(NEGATIVE)
        self.assertEqual(hits, 0, log_text)

    def test_no_unicode_dashes_in_owned_sources(self) -> None:
        for path in (DETECTOR_PATH, POSITIVE, NEGATIVE, Path(__file__)):
            with self.subTest(path=path.name):
                text = path.read_text(encoding="utf-8")
                self.assertIsNone(re.search("[\u2013\u2014]", text))


if __name__ == "__main__":
    unittest.main()
