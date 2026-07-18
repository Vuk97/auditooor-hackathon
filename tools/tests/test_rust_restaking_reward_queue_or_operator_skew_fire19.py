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
DETECTOR = "restaking_reward_queue_or_operator_skew_fire19"
DETECTOR_PATH = REPO_ROOT / "detectors" / "rust_wave1" / f"{DETECTOR}.py"
POSITIVE = FIXTURES / f"{DETECTOR}_positive.rs"
NEGATIVE = FIXTURES / f"{DETECTOR}_negative.rs"

SEED_POSITIVES = (
    "r94_loop_restaking_operator_heap_removed_id_stale_divzero_positive.rs",
    "r94_loop_restaking_operator_self_undelegate_lrt_rate_manipulation_positive.rs",
    "r94_loop_restaking_strategy_cap_zero_skips_shares_queue_sync_positive.rs",
)

SEED_NEGATIVES = (
    "r94_loop_restaking_operator_heap_removed_id_stale_divzero_negative.rs",
    "r94_loop_restaking_operator_self_undelegate_lrt_rate_manipulation_negative.rs",
    "r94_loop_restaking_strategy_cap_zero_skips_shares_queue_sync_negative.rs",
)

CLASS_MAP = REPO_ROOT / "reference" / "detector_class_map_complete.yaml"
LEGACY_MAP = REPO_ROOT / "reference" / "detector_to_attack_classes_map.yaml"

_HIT_RE = re.compile(rf"^=== {DETECTOR}\s+\((\d+) hits\)", re.MULTILINE)


def _run_fixture(fixture: Path) -> tuple[int, str]:
    with tempfile.NamedTemporaryFile(prefix=".rust_restaking_fire19_", suffix=".log") as tmp:
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


class RustRestakingRewardQueueOrOperatorSkewFire19Tests(unittest.TestCase):
    def test_detector_and_test_compile(self) -> None:
        py_compile.compile(str(DETECTOR_PATH), doraise=True)
        py_compile.compile(str(Path(__file__)), doraise=True)

    def test_positive_fixture_covers_three_restaking_reward_skew_shapes(self) -> None:
        text = POSITIVE.read_text(encoding="utf-8")
        self.assertIn("load_operator_heap", text)
        self.assertIn("remove_delegation(staker)", text)
        self.assertIn("strategy.cap = 0", text)

        hits, log_text = _run_fixture(POSITIVE)
        self.assertEqual(hits, 3, log_text)
        self.assertIn("operator heap", log_text)
        self.assertIn("before participant reward", log_text)
        self.assertIn("withdrawal queue membership", log_text)
        self.assertIn("rewards-distribution-skew", log_text)

    def test_negative_fixture_settles_or_syncs_before_mutating(self) -> None:
        text = NEGATIVE.read_text(encoding="utf-8")
        self.assertIn("entry.operator_id == 0", text)
        self.assertLess(text.index("settle_participant"), text.index("remove_delegation"))
        self.assertLess(text.index("sync_shares"), text.index("strategy.cap = 0"))
        self.assertLess(text.index("update_withdrawal_queue"), text.index("strategy.cap = 0"))

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
