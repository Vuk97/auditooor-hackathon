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
    / "consensus_state_root_or_context_gap_fire20.py"
)
TEST_FILE = HERE / "test_rust_consensus_state_root_or_context_gap_fire20.py"
DETECTOR_ID = "consensus_state_root_or_context_gap_fire20"
POSITIVE = FIXTURES / f"{DETECTOR_ID}_positive.rs"
NEGATIVE = FIXTURES / f"{DETECTOR_ID}_negative.rs"
_HIT_RE = re.compile(rf"^=== {DETECTOR_ID}\s+\((\d+) hits\)", re.MULTILINE)


def _run_fixture(fixture: Path) -> tuple[int, str]:
    with tempfile.NamedTemporaryFile(
        prefix=".rust_fire20_consensus_context_",
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


class RustConsensusStateRootOrContextGapFire20Test(unittest.TestCase):
    def test_detector_and_test_compile(self) -> None:
        py_compile.compile(str(DETECTOR), doraise=True)
        py_compile.compile(str(TEST_FILE), doraise=True)

    def test_positive_fixture_fires_on_all_seed_shapes(self) -> None:
        hits, log_text = _run_fixture(POSITIVE)
        self.assertGreaterEqual(hits, 4, log_text)
        self.assertIn("locally computed root", log_text)
        self.assertIn("finalized state only", log_text)
        self.assertIn("tree root", log_text)
        self.assertIn("non-finalized spends", log_text)

    def test_negative_fixture_is_silent_when_context_is_bound(self) -> None:
        hits, log_text = _run_fixture(NEGATIVE)
        self.assertEqual(hits, 0, log_text)

    def test_confirmed_fire19_misses_are_recalled(self) -> None:
        fixtures = [
            "rust-consensus-state-root-commitment-divergence_positive.rs",
            "zebra_anchor_contextual_validation_gap_positive.rs",
            "zebra_finalized_nonfinalized_fallback_gap_positive.rs",
        ]
        for fixture in fixtures:
            with self.subTest(fixture=fixture):
                hits, log_text = _run_fixture(FIXTURES / fixture)
                self.assertGreaterEqual(hits, 1, log_text)

    def test_confirmed_clean_controls_are_silent(self) -> None:
        fixtures = [
            "rust-consensus-state-root-commitment-divergence_negative.rs",
            "zebra_anchor_contextual_validation_gap_negative.rs",
            "zebra_finalized_nonfinalized_fallback_gap_negative.rs",
        ]
        for fixture in fixtures:
            with self.subTest(fixture=fixture):
                hits, log_text = _run_fixture(FIXTURES / fixture)
                self.assertEqual(hits, 0, log_text)


if __name__ == "__main__":
    unittest.main()
