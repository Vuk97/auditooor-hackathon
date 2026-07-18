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
DETECTOR = REPO_ROOT / "detectors" / "rust_wave1" / "reentrancy_packet_open_midstate_fire38.py"
DETECTOR_ID = "reentrancy_packet_open_midstate_fire38"
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


class RustReentrancyPacketOpenMidstateFire38Tests(unittest.TestCase):
    def test_detector_and_test_compile(self) -> None:
        py_compile.compile(str(DETECTOR), doraise=True)
        py_compile.compile(str(Path(__file__)), doraise=True)

    def test_detector_declares_source_refs_and_evidence_limits(self) -> None:
        detector_text = DETECTOR.read_text(encoding="utf-8")
        self.assertIn(
            "reports/detector_lift_fire37_20260605/post_priorities_rust.md",
            detector_text,
        )
        self.assertIn(
            "detectors/rust_wave1/reentrancy_callback_midstate_fire37.py",
            detector_text,
        )
        self.assertIn(
            "detectors/rust_wave1/r94_loop_nft_packet_open_reentrancy_duplicate_card_mint.py",
            detector_text,
        )
        self.assertIn(
            "detectors/rust_wave1/r94_loop_post_exec_check_reentrancy_bypass.py",
            detector_text,
        )
        self.assertIn(
            "detectors/rust_wave1/r94_loop_rewards_update_after_external_transfer_reentrancy_steal.py",
            detector_text,
        )
        self.assertIn(
            "reference/patterns.dsl/reentrancy-cross-contract-stale-state-callback.yaml",
            detector_text,
        )
        self.assertIn("verification_tier: tier-3-synthetic-taxonomy-anchored", detector_text)
        self.assertIn("attack_class: reentrancy-cross-contract", detector_text)
        self.assertIn("NOT_SUBMIT_READY", detector_text)

    def test_positive_fixture_fires_on_packet_nft_and_reward_midstates(self) -> None:
        hits, log_text = _run_fixture(POSITIVE)
        self.assertEqual(hits, 3, log_text)
        self.assertIn("open_packet_mints_before_marking_open", log_text)
        self.assertIn("on_erc721_received_updates_collateral_after_hook", log_text)
        self.assertIn("withdraw_rewards_transfers_before_reward_update", log_text)
        self.assertIn("snapshots packet/card/reward/collateral state", log_text)
        self.assertIn("without a shared lock or post-callback reload", log_text)

    def test_negative_fixture_is_silent_on_lock_cei_and_reload(self) -> None:
        hits, log_text = _run_fixture(NEGATIVE)
        self.assertEqual(hits, 0, log_text)

    def test_false_positive_boundaries_are_locked(self) -> None:
        positive = POSITIVE.read_text(encoding="utf-8")
        negative = NEGATIVE.read_text(encoding="utf-8")
        detector_text = DETECTOR.read_text(encoding="utf-8")

        self.assertIn("receiver.safe_mint(user, card_snapshot)", positive)
        self.assertIn("hook.on_receive_nft(user, token_id)", positive)
        self.assertIn("receiver.on_reward(user, amount)", positive)
        self.assertIn("self.update_account_rewards(user, share_snapshot", positive)

        self.assertIn("self.packet_open_lock = true", negative)
        self.assertIn("receiver.safe_mint(user, card_snapshot)", negative)
        self.assertIn("let packet_after = self.packets.get(&packet_id)", negative)
        self.assertIn("let collateral_after = self.collateral.get(&user)", negative)
        self.assertIn("self.update_account_rewards(user, share_snapshot", negative)

        self.assertIn("post-callback reload", detector_text)
        self.assertIn("per-packet/per-account lock", detector_text)

        for path in (DETECTOR, POSITIVE, NEGATIVE, Path(__file__)):
            text = path.read_text(encoding="utf-8")
            self.assertNotIn("\u2014", text)
            self.assertNotIn("\u2013", text)


if __name__ == "__main__":
    unittest.main()
