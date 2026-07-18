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
DETECTOR = REPO_ROOT / "detectors" / "rust_wave1" / "reentrancy_royalty_receiver_callback_fire39.py"
DETECTOR_ID = "reentrancy_royalty_receiver_callback_fire39"
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


class RustReentrancyRoyaltyReceiverCallbackFire39Tests(unittest.TestCase):
    def test_detector_and_test_compile(self) -> None:
        py_compile.compile(str(DETECTOR), doraise=True)
        py_compile.compile(str(Path(__file__)), doraise=True)

    def test_detector_declares_provenance_and_evidence_limits(self) -> None:
        detector_text = DETECTOR.read_text(encoding="utf-8")
        self.assertIn("verification_tier: tier-3-synthetic-taxonomy-anchored", detector_text)
        self.assertIn("attack_class: reentrancy-cross-contract", detector_text)
        self.assertIn(
            "context_pack_id: auditooor.vault_context_pack.v1:resume:cbdd9eeb5255863c",
            detector_text,
        )
        self.assertIn(
            "context_pack_hash: cbdd9eeb5255863c4870d83e88642e9c4a3eef8e7cdfb8b5fb9a8ee7ac5a25d8",
            detector_text,
        )
        self.assertIn("MCP receipt: .auditooor/memory_context_receipt.json", detector_text)
        self.assertIn("NOT_SUBMIT_READY", detector_text)
        self.assertIn("R40/R76/R80 caveat", detector_text)

    def test_positive_fixture_fires_on_royalty_and_collateral_callback_semantics(self) -> None:
        hits, log_text = _run_fixture(POSITIVE)
        self.assertEqual(hits, 2, log_text)
        self.assertIn("buy_with_stale_royalty_callback", log_text)
        self.assertIn("on_erc721_received_reenters_before_share_commit", log_text)
        self.assertIn("derives royalty receiver state", log_text)
        self.assertIn("derives NFT receiver collateral/share state", log_text)
        self.assertIn("post-callback reload", log_text)

    def test_negative_fixture_is_silent_on_guard_binding_checkpoint_reload_and_packet_shape(self) -> None:
        hits, log_text = _run_fixture(NEGATIVE)
        self.assertEqual(hits, 0, log_text)

    def test_semantic_boundary_terms_are_present_in_fixtures_and_detector(self) -> None:
        positive = POSITIVE.read_text(encoding="utf-8")
        negative = NEGATIVE.read_text(encoding="utf-8")
        detector_text = DETECTOR.read_text(encoding="utf-8")

        self.assertIn("RoyaltyOracle::royalty_info(token_id, price)", positive)
        self.assertIn("callback.receive_royalty(royalty_amount)", positive)
        self.assertIn("self.balances.entry(royalty_receiver)", positive)
        self.assertIn("receiver.on_erc721_received(operator, from, token_id)", positive)
        self.assertIn("self.collateral_configs.insert(token_id, collateral_config)", positive)

        self.assertIn("non_reentrant()", negative)
        self.assertIn("verify_royalty_domain(token_id, royalty_receiver)", negative)
        self.assertIn("self.sale_status.insert(token_id, \"Settling\")", negative)
        self.assertIn("let collateral_after = self.collateral_configs.get(&token_id)", negative)
        self.assertIn("open_packet_mints_duplicate_card_shape_not_royalty_or_collateral", negative)

        self.assertIn("_PACKET_ONLY_CONTEXT_RE", detector_text)
        self.assertIn("_POST_RELOAD_RE", detector_text)
        self.assertIn("_PRECOMMIT_RE", detector_text)
        self.assertIn("_GUARD_OR_BIND_RE", detector_text)

        for path in (DETECTOR, POSITIVE, NEGATIVE, Path(__file__)):
            text = path.read_text(encoding="utf-8")
            self.assertNotIn("\u2014", text)
            self.assertNotIn("\u2013", text)


if __name__ == "__main__":
    unittest.main()
