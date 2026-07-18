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
DETECTOR = REPO_ROOT / "detectors" / "rust_wave1" / "reentrancy_callback_midstate_fire37.py"
DETECTOR_ID = "reentrancy_callback_midstate_fire37"
POSITIVE = FIXTURES / f"{DETECTOR_ID}_positive.rs"
NEGATIVE = FIXTURES / f"{DETECTOR_ID}_negative.rs"
_HIT_RE = re.compile(rf"^=== {DETECTOR_ID}\s+\((\d+) hits\)", re.MULTILINE)


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
                DETECTOR_ID,
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
            timeout=90,
        )
        if proc.returncode != 0:
            raise AssertionError(proc.stderr or proc.stdout)
        text = log_path.read_text(encoding="utf-8", errors="ignore")
        match = _HIT_RE.search(text)
        return int(match.group(1)) if match else 0, text
    finally:
        log_path.unlink(missing_ok=True)


class RustReentrancyCallbackMidstateFire37Tests(unittest.TestCase):
    def test_detector_and_test_compile(self) -> None:
        py_compile.compile(str(DETECTOR), doraise=True)
        py_compile.compile(str(Path(__file__)), doraise=True)

    def test_detector_declares_source_refs_and_evidence_limits(self) -> None:
        detector_text = DETECTOR.read_text(encoding="utf-8")
        self.assertIn(
            "reports/detector_lift_fire36_20260605/post_priorities_rust.md",
            detector_text,
        )
        self.assertIn(
            "reference/patterns.dsl/reentrancy-cross-contract-stale-state-callback.yaml",
            detector_text,
        )
        self.assertIn("detectors/rust_wave1/reentrant_midstate_callback_fire34.py", detector_text)
        self.assertIn(
            "detectors/wave17/reentrancy_callback_balance_snapshot_fire36.py",
            detector_text,
        )
        self.assertIn("verification_tier: tier-3-synthetic-taxonomy-anchored", detector_text)
        self.assertIn("attack_class: reentrancy-cross-contract", detector_text)
        self.assertIn("NOT_SUBMIT_READY", detector_text)

    def test_positive_fixture_fires_on_callback_and_cpi_midstates(self) -> None:
        hits, log_text = _run_fixture(POSITIVE)
        self.assertEqual(hits, 2, log_text)
        self.assertIn("claim_with_receiver_callback", log_text)
        self.assertIn("open_packet_with_cpi", log_text)
        self.assertIn("snapshots state", log_text)
        self.assertIn("without a shared reentrancy guard or post-callback refresh", log_text)

    def test_negative_fixture_is_silent_on_guard_refresh_and_cei(self) -> None:
        hits, log_text = _run_fixture(NEGATIVE)
        self.assertEqual(hits, 0, log_text)

    def test_false_positive_boundaries_are_locked(self) -> None:
        positive = POSITIVE.read_text(encoding="utf-8")
        negative = NEGATIVE.read_text(encoding="utf-8")
        detector_text = DETECTOR.read_text(encoding="utf-8")

        self.assertIn("receiver.on_claim(user, amount)", positive)
        self.assertIn("receiver_program.invoke(packet_id)?", positive)
        self.assertIn("self.balances.insert(user, balance_before - amount)", positive)
        self.assertIn("self.packets.insert", positive)

        self.assertIn("self.reentrancy_lock = true", negative)
        self.assertIn("let balance_after = self.balances.get(&user)", negative)
        self.assertIn("receiver.on_claim(user, amount)", negative)
        self.assertIn("self.claims.insert(claim_id, ClaimStatus::Claimed);", negative)

        self.assertIn("post-callback refresh", detector_text)
        self.assertIn("per-account/per-packet lock", detector_text)

        for path in (DETECTOR, POSITIVE, NEGATIVE, Path(__file__)):
            text = path.read_text(encoding="utf-8")
            self.assertNotIn("\u2014", text)
            self.assertNotIn("\u2013", text)


if __name__ == "__main__":
    unittest.main()
