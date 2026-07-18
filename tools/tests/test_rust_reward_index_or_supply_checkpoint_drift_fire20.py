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
DETECTOR = "reward_index_or_supply_checkpoint_drift_fire20"
DETECTOR_PATH = REPO_ROOT / "detectors" / "rust_wave1" / f"{DETECTOR}.py"
POSITIVE = FIXTURES / f"{DETECTOR}_positive.rs"
NEGATIVE = FIXTURES / f"{DETECTOR}_negative.rs"

SEED_POSITIVES = (
    "r94_loop_reward_cached_vs_current_index_drift_positive.rs",
    "r94_loop_reward_cliff_boundary_wrong_supply_positive.rs",
    "r94_loop_restaking_withdraw_dos_erc20_buffer_overflow_positive.rs",
)

SEED_NEGATIVES = (
    "r94_loop_reward_cached_vs_current_index_drift_negative.rs",
    "r94_loop_reward_cliff_boundary_wrong_supply_negative.rs",
    "r94_loop_restaking_withdraw_dos_erc20_buffer_overflow_negative.rs",
)

CLASS_MAP = REPO_ROOT / "reference" / "detector_class_map_complete.yaml"
LEGACY_MAP = REPO_ROOT / "reference" / "detector_to_attack_classes_map.yaml"

_HIT_RE = re.compile(rf"^=== {DETECTOR}\s+\((\d+) hits\)", re.MULTILINE)


def _run_fixture(fixture: Path) -> tuple[int, str]:
    with tempfile.NamedTemporaryFile(prefix=".rust_reward_fire20_", suffix=".log") as tmp:
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
            timeout=60,
        )
        if proc.returncode != 0:
            raise AssertionError(proc.stdout)
        log_text = Path(tmp.name).read_text(encoding="utf-8", errors="ignore")

    match = _HIT_RE.search(log_text)
    return int(match.group(1)) if match else 0, log_text


class RustRewardIndexOrSupplyCheckpointDriftFire20Tests(unittest.TestCase):
    def test_detector_and_test_compile(self) -> None:
        py_compile.compile(str(DETECTOR_PATH), doraise=True)
        py_compile.compile(str(Path(__file__)), doraise=True)

    def test_positive_fixture_covers_index_supply_withdraw_and_buffer_shapes(self) -> None:
        text = POSITIVE.read_text(encoding="utf-8")
        self.assertIn("reward_per_token_stored", text)
        self.assertIn("let cliff = total_supply()", text)
        self.assertIn("pool.total_shares -= shares", text)
        self.assertIn("buf.erc20_buffer = buf.erc20_buffer + amount", text)

        hits, log_text = _run_fixture(POSITIVE)
        self.assertEqual(hits, 4, log_text)
        self.assertIn("cached reward index", log_text)
        self.assertIn("pre-mutation supply checkpoint", log_text)
        self.assertIn("before settling user rewards", log_text)
        self.assertIn("cap-saturation fallthrough", log_text)
        self.assertIn("rewards-distribution-skew", log_text)

    def test_negative_fixture_checkpoints_before_mutating_denominators(self) -> None:
        text = NEGATIVE.read_text(encoding="utf-8")
        self.assertLess(text.index("update_reward"), text.index("reward_per_token_stored"))
        self.assertIn("let pre_mint_supply = total_supply()", text)
        self.assertLess(text.index("checkpoint_user_rewards"), text.index("pool.total_shares -= shares"))
        self.assertIn("let buffer_space", text)
        self.assertIn("transfer_leftover_to_user", text)

        hits, log_text = _run_fixture(NEGATIVE)
        self.assertEqual(hits, 0, log_text)

    def test_confirmed_seed_misses_now_fire(self) -> None:
        for fixture_name in SEED_POSITIVES:
            with self.subTest(fixture=fixture_name):
                hits, log_text = _run_fixture(FIXTURES / fixture_name)
                self.assertGreaterEqual(hits, 1, log_text)
                self.assertIn("rewards-distribution-skew", log_text)

    def test_confirmed_seed_clean_fixtures_stay_silent(self) -> None:
        for fixture_name in SEED_NEGATIVES:
            with self.subTest(fixture=fixture_name):
                hits, log_text = _run_fixture(FIXTURES / fixture_name)
                self.assertEqual(hits, 0, log_text)

    def test_class_maps_route_detector_to_rewards_distribution_skew(self) -> None:
        complete = CLASS_MAP.read_text(encoding="utf-8")
        legacy = LEGACY_MAP.read_text(encoding="utf-8")
        self.assertIn(f"rust_wave1.{DETECTOR}:", complete)
        self.assertIn(f"{DETECTOR}:", complete)
        self.assertIn("attack_class: rewards-distribution-skew", complete)
        self.assertIn(f"rust_wave1.{DETECTOR}:", legacy)
        self.assertIn(f"{DETECTOR}:", legacy)
        self.assertIn("- rewards-distribution-skew", legacy)


if __name__ == "__main__":
    unittest.main()
