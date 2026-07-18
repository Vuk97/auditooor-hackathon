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

DETECTOR = "governance_timelock_or_duplicate_queue_fire20"
DETECTOR_PATH = WAVE1_DIR / f"{DETECTOR}.py"
POSITIVE = FIXTURES / f"{DETECTOR}_positive.rs"
NEGATIVE = FIXTURES / f"{DETECTOR}_negative.rs"
_HIT_RE = re.compile(rf"^=== {re.escape(DETECTOR)}\s+\((\d+) hits\)", re.MULTILINE)


def _run_fixture(fixture: Path) -> tuple[int, str]:
    with tempfile.NamedTemporaryFile(suffix=".log", delete=False) as tmp:
        log_path = Path(tmp.name)
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
            timeout=60,
        )
        if proc.returncode != 0:
            raise AssertionError(proc.stderr or proc.stdout)
        log_text = log_path.read_text(encoding="utf-8", errors="ignore")
        match = _HIT_RE.search(log_text)
        return (int(match.group(1)) if match else 0), log_text
    finally:
        log_path.unlink(missing_ok=True)


class RustGovernanceTimelockOrDuplicateQueueFire20Tests(unittest.TestCase):
    def test_detector_compiles(self) -> None:
        py_compile.compile(str(DETECTOR_PATH), doraise=True)

    def test_positive_fixture_fires_on_all_variants(self) -> None:
        hits, log_text = _run_fixture(POSITIVE)
        self.assertGreaterEqual(hits, 4, log_text)
        self.assertIn("execute-missing-timelock", log_text)
        self.assertIn("duplicate-action-queue-key", log_text)
        self.assertIn("timelock-delta-unenforced", log_text)

    def test_negative_fixture_is_silent(self) -> None:
        hits, log_text = _run_fixture(NEGATIVE)
        self.assertEqual(hits, 0, log_text)

    def test_confirmed_governance_execute_no_timelock_miss_fires(self) -> None:
        hits, log_text = _run_fixture(FIXTURES / "r94_governance_execute_no_timelock_positive.rs")
        self.assertGreaterEqual(hits, 1, log_text)
        self.assertIn("execute-missing-timelock", log_text)

    def test_confirmed_duplicate_action_queue_collision_miss_fires(self) -> None:
        hits, log_text = _run_fixture(
            FIXTURES / "r94_loop_governance_proposal_duplicate_action_queue_collision_positive.rs"
        )
        self.assertGreaterEqual(hits, 1, log_text)
        self.assertIn("duplicate-action-queue-key", log_text)

    def test_confirmed_htlc_timelock_delta_miss_fires(self) -> None:
        hits, log_text = _run_fixture(FIXTURES / "r94_loop_htlc_timelock_delta_unenforced_positive.rs")
        self.assertGreaterEqual(hits, 2, log_text)
        self.assertIn("timelock-delta-unenforced", log_text)

    def test_confirmed_duplicate_action_queue_negative_stays_silent(self) -> None:
        hits, log_text = _run_fixture(
            FIXTURES / "r94_loop_governance_proposal_duplicate_action_queue_collision_negative.rs"
        )
        self.assertEqual(hits, 0, log_text)


if __name__ == "__main__":
    unittest.main()
