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
DETECTOR_ID = "rust_bridge_withdrawals_root_parent_state_missing_silent_pass"
POSITIVE_FIXTURE = (
    FIXTURES / "rust_bridge_withdrawals_root_parent_state_missing_silent_pass_positive.rs"
)
NEGATIVE_FIXTURE = (
    FIXTURES / "rust_bridge_withdrawals_root_parent_state_missing_silent_pass_negative.rs"
)


def _run_detector(fixture: Path, detector_id: str = DETECTOR_ID) -> int:
    hit_re = re.compile(rf"^=== {re.escape(detector_id)}\s+\((\d+) hits\)", re.MULTILINE)
    with tempfile.NamedTemporaryFile(suffix=".log", delete=False) as tf:
        log_path = Path(tf.name)
    try:
        proc = subprocess.run(
            [
                sys.executable,
                str(RUST_DETECT),
                str(FIXTURES),
                "--only",
                detector_id,
                "--file",
                str(fixture),
                "--log",
                str(log_path),
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=False,
        )
        if proc.returncode != 0:
            raise AssertionError(proc.stderr or proc.stdout)
        text = log_path.read_text(encoding="utf-8", errors="ignore")
        match = hit_re.search(text)
        return int(match.group(1)) if match else 0
    finally:
        log_path.unlink(missing_ok=True)


def _run_all_detectors(fixture: Path) -> dict[str, int]:
    hit_re = re.compile(r"^=== (?P<detector>\S+)\s+\((?P<hits>\d+) hits\)", re.MULTILINE)
    with tempfile.NamedTemporaryFile(suffix=".log", delete=False) as tf:
        log_path = Path(tf.name)
    try:
        proc = subprocess.run(
            [
                sys.executable,
                str(RUST_DETECT),
                str(FIXTURES),
                "--file",
                str(fixture),
                "--log",
                str(log_path),
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=False,
        )
        if proc.returncode != 0:
            raise AssertionError(proc.stderr or proc.stdout)
        text = log_path.read_text(encoding="utf-8", errors="ignore")
        return {
            match.group("detector"): int(match.group("hits"))
            for match in hit_re.finditer(text)
        }
    finally:
        log_path.unlink(missing_ok=True)


class RustBridgeWithdrawalsRootParentStateMissingSilentPassTests(unittest.TestCase):
    def test_positive_fixture_fires(self) -> None:
        self.assertGreaterEqual(_run_detector(POSITIVE_FIXTURE), 1)

    def test_negative_fixture_is_silent(self) -> None:
        self.assertEqual(_run_detector(NEGATIVE_FIXTURE), 0)

    def test_existing_bridge_detectors_do_not_claim_positive_fixture(self) -> None:
        hits = _run_all_detectors(POSITIVE_FIXTURE)
        overlap = {
            detector: count
            for detector, count in hits.items()
            if detector != DETECTOR_ID and "bridge" in detector and count > 0
        }
        self.assertEqual(overlap, {})


if __name__ == "__main__":
    unittest.main()
