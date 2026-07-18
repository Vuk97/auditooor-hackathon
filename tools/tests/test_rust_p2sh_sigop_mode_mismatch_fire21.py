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
DETECTOR = REPO_ROOT / "detectors" / "rust_wave1" / "p2sh_sigop_mode_mismatch_fire21.py"
TEST_FILE = HERE / "test_rust_p2sh_sigop_mode_mismatch_fire21.py"
DETECTOR_ID = "p2sh_sigop_mode_mismatch_fire21"
POSITIVE = FIXTURES / f"{DETECTOR_ID}_positive.rs"
NEGATIVE = FIXTURES / f"{DETECTOR_ID}_negative.rs"
_HIT_RE = re.compile(rf"^=== {DETECTOR_ID}\s+\((\d+) hits\)", re.MULTILINE)


def _run_fixture(fixture: Path) -> tuple[int, str]:
    with tempfile.NamedTemporaryFile(
        prefix=".rust_fire21_p2sh_sigop_",
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


class RustP2shSigopModeMismatchFire21Test(unittest.TestCase):
    def test_detector_and_test_compile(self) -> None:
        py_compile.compile(str(DETECTOR), doraise=True)
        py_compile.compile(str(TEST_FILE), doraise=True)

    def test_positive_fixture_fires_on_hardcoded_legacy_mode(self) -> None:
        hits, log_text = _run_fixture(POSITIVE)
        self.assertGreaterEqual(hits, 1, log_text)
        self.assertIn("hard-coded mode", log_text)
        self.assertIn("network-upgrade context", log_text)

    def test_negative_fixture_is_silent_when_mode_is_context_derived(self) -> None:
        hits, log_text = _run_fixture(NEGATIVE)
        self.assertEqual(hits, 0, log_text)

    def test_confirmed_fire20_zebra_miss_is_recalled(self) -> None:
        hits, log_text = _run_fixture(FIXTURES / "zebra_p2sh_sigop_legacy_mode_gap_positive.rs")
        self.assertGreaterEqual(hits, 1, log_text)

    def test_confirmed_zebra_clean_control_is_silent(self) -> None:
        hits, log_text = _run_fixture(FIXTURES / "zebra_p2sh_sigop_legacy_mode_gap_negative.rs")
        self.assertEqual(hits, 0, log_text)


if __name__ == "__main__":
    unittest.main()
