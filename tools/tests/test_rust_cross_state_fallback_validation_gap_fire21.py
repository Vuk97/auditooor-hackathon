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
DETECTOR = "cross_state_fallback_validation_gap_fire21"
DETECTOR_PATH = REPO_ROOT / "detectors" / "rust_wave1" / f"{DETECTOR}.py"
TEST_FILE = HERE / "test_rust_cross_state_fallback_validation_gap_fire21.py"
POSITIVE = FIXTURES / f"{DETECTOR}_positive.rs"
NEGATIVE = FIXTURES / f"{DETECTOR}_negative.rs"

_HIT_RE = re.compile(rf"^=== {DETECTOR}\s+\((\d+) hits\)", re.MULTILINE)


def _run_fixture(fixture: Path) -> tuple[int, str]:
    with tempfile.NamedTemporaryFile(
        prefix=".rust_cross_state_fallback_fire21_",
        suffix=".log",
    ) as tmp:
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
            timeout=120,
        )
        if proc.returncode != 0:
            raise AssertionError(proc.stdout)
        log_text = Path(tmp.name).read_text(encoding="utf-8", errors="ignore")

    match = _HIT_RE.search(log_text)
    return int(match.group(1)) if match else 0, log_text


class RustCrossStateFallbackValidationGapFire21Test(unittest.TestCase):
    def test_detector_and_test_compile(self) -> None:
        py_compile.compile(str(DETECTOR_PATH), doraise=True)
        py_compile.compile(str(TEST_FILE), doraise=True)

    def test_positive_fixture_fires_on_trusted_and_non_finalized_fallbacks(self) -> None:
        text = POSITIVE.read_text(encoding="utf-8")
        self.assertIn(".or_else(|| pending_cache.cached_root(height))", text)
        self.assertIn(".or_else(|| finalized_state.finalized_root(height))", text)

        hits, log_text = _run_fixture(POSITIVE)
        self.assertEqual(hits, 2, log_text)
        self.assertIn("cross-state-fallback-validation-gap", log_text)
        self.assertIn("finality, height, chain context", log_text)

    def test_negative_fixture_keeps_fallback_but_revalidates_context(self) -> None:
        text = NEGATIVE.read_text(encoding="utf-8")
        self.assertIn(".or_else(|| pending_cache.cached_root(height))", text)
        self.assertIn("is_finalized(root.height)", text)
        self.assertIn("validate_chain_context", text)

        hits, log_text = _run_fixture(NEGATIVE)
        self.assertEqual(hits, 0, log_text)

    def test_confirmed_fire20_miss_is_recalled(self) -> None:
        hits, log_text = _run_fixture(
            FIXTURES / "zebra_finalized_nonfinalized_fallback_gap_positive.rs"
        )
        self.assertGreaterEqual(hits, 1, log_text)
        self.assertIn("cross-state-fallback-validation-gap", log_text)

    def test_confirmed_clean_control_is_silent(self) -> None:
        hits, log_text = _run_fixture(
            FIXTURES / "zebra_finalized_nonfinalized_fallback_gap_negative.rs"
        )
        self.assertEqual(hits, 0, log_text)


if __name__ == "__main__":
    unittest.main()
