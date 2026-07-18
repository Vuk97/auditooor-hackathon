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
DETECTOR = "fund_loss_state_asymmetry_fire13"
DETECTOR_PATH = REPO_ROOT / "detectors" / "rust_wave1" / f"{DETECTOR}.py"
POSITIVE = FIXTURES / f"{DETECTOR}_positive.rs"
NEGATIVE = FIXTURES / f"{DETECTOR}_negative.rs"
HELD_OUT = [
    FIXTURES / "paired_function_state_write_asymmetry_positive.rs",
    FIXTURES / "r94_loop_airdrop_double_claim_positive.rs",
    FIXTURES / "r94_loop_double_subtraction_accounting_positive.rs",
]
_HIT_RE = re.compile(rf"^=== {DETECTOR}\s+\((\d+) hits\)", re.MULTILINE)


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
                DETECTOR,
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


class RustFundLossStateAsymmetryFire13Tests(unittest.TestCase):
    def test_detector_compiles(self) -> None:
        py_compile.compile(str(DETECTOR_PATH), doraise=True)

    def test_positive_fires(self) -> None:
        text = POSITIVE.read_text(encoding="utf-8")
        self.assertIn("n.unwrap_or(0) + 1", text)
        self.assertLess(text.index("token::transfer"), text.index("set_claimed"))

        hits, log_text = _run_fixture(POSITIVE)
        self.assertGreaterEqual(hits, 1, log_text)
        self.assertIn("fund-loss-state-asymmetry-fire13", log_text)

    def test_negative_is_silent(self) -> None:
        text = NEGATIVE.read_text(encoding="utf-8")
        self.assertLess(text.index("set_claimed"), text.index("token::transfer"))

        hits, log_text = _run_fixture(NEGATIVE)
        self.assertEqual(hits, 0, log_text)

    def test_independent_held_out_recall(self) -> None:
        results = {}
        for fixture in HELD_OUT:
            hits, log_text = _run_fixture(fixture)
            results[fixture.name] = hits
            self.assertGreater(
                hits,
                0,
                f"{fixture.name} should be recalled by {DETECTOR}\n{log_text}",
            )
        self.assertEqual(
            set(results),
            {
                "paired_function_state_write_asymmetry_positive.rs",
                "r94_loop_airdrop_double_claim_positive.rs",
                "r94_loop_double_subtraction_accounting_positive.rs",
            },
        )


if __name__ == "__main__":
    unittest.main()
