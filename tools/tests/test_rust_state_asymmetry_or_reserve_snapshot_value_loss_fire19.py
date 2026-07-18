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
    / "state_asymmetry_or_reserve_snapshot_value_loss_fire19.py"
)
DETECTOR_ID = "state_asymmetry_or_reserve_snapshot_value_loss_fire19"
POSITIVE = FIXTURES / f"{DETECTOR_ID}_positive.rs"
NEGATIVE = FIXTURES / f"{DETECTOR_ID}_negative.rs"
_HIT_RE = re.compile(rf"^=== {DETECTOR_ID}\s+\((\d+) hits\)", re.MULTILINE)


def _run_fixture(fixture: Path) -> tuple[int, str]:
    with tempfile.NamedTemporaryFile(
        prefix=".rust_fire19_state_asymmetry_",
        suffix=".log",
    ) as tmp:
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
    return int(match.group(1)) if match else 0, text


class RustStateAsymmetryOrReserveSnapshotValueLossFire19Test(unittest.TestCase):
    def test_detector_compiles(self) -> None:
        py_compile.compile(str(DETECTOR), doraise=True)

    def test_positive_fixture_fires_on_all_class_shapes(self) -> None:
        hits, log_text = _run_fixture(POSITIVE)
        self.assertGreaterEqual(hits, 4, log_text)
        self.assertIn("moves value before", log_text)
        self.assertIn("freshness guard", log_text)
        self.assertIn("burns tick-range liquidity", log_text)
        self.assertIn("credits user-facing value", log_text)

    def test_negative_fixture_is_silent_with_refresh_and_symmetric_updates(self) -> None:
        hits, log_text = _run_fixture(NEGATIVE)
        self.assertEqual(hits, 0, log_text)

    def test_confirmed_fire18_misses_are_recalled(self) -> None:
        fixtures = [
            "fund_loss_state_asymmetry_fire13_positive.rs",
            "r94_loop_il_compensation_reserve_snapshot_positive.rs",
            "r94_loop_lp_shared_tick_range_accounting_theft_positive.rs",
        ]
        for fixture in fixtures:
            with self.subTest(fixture=fixture):
                hits, log_text = _run_fixture(FIXTURES / fixture)
                self.assertGreaterEqual(hits, 1, log_text)

    def test_confirmed_clean_controls_are_silent(self) -> None:
        fixtures = [
            "fund_loss_state_asymmetry_fire13_negative.rs",
            "r94_loop_il_compensation_reserve_snapshot_negative.rs",
            "r94_loop_lp_shared_tick_range_accounting_theft_negative.rs",
        ]
        for fixture in fixtures:
            with self.subTest(fixture=fixture):
                hits, log_text = _run_fixture(FIXTURES / fixture)
                self.assertEqual(hits, 0, log_text)

    def test_generic_arithmetic_without_value_context_is_silent(self) -> None:
        fixtures = [
            "division_before_multiplication_positive.rs",
            "integer_overflow_unchecked_block_positive.rs",
        ]
        for fixture in fixtures:
            with self.subTest(fixture=fixture):
                hits, log_text = _run_fixture(FIXTURES / fixture)
                self.assertEqual(hits, 0, log_text)


if __name__ == "__main__":
    unittest.main()
