from __future__ import annotations

import importlib.util
import sys
import unittest
from pathlib import Path


REPO = Path(__file__).resolve().parents[2]
DETECTOR_PATH = REPO / "detectors" / "move_wave2" / "inflation_attack_on_zero_total_stake_staking_v2.py"
FIXTURE_DIR = REPO / "detectors" / "move_wave2" / "test_fixtures"
FIXTURE_VULN = FIXTURE_DIR / "inflation_attack_on_zero_total_stake_staking_v2_vulnerable.move"
FIXTURE_CLEAN = FIXTURE_DIR / "inflation_attack_on_zero_total_stake_staking_v2_clean.move"


def _load_detector():
    spec = importlib.util.spec_from_file_location("inflation_attack_on_zero_total_stake_staking_v2", DETECTOR_PATH)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules["inflation_attack_on_zero_total_stake_staking_v2"] = module
    spec.loader.exec_module(module)
    return module


class InflationAttackOnZeroTotalStakeStakingV2Test(unittest.TestCase):
    def test_fixture_pair_hits_vulnerable_and_suppresses_clean(self) -> None:
        detector = _load_detector()
        self.assertTrue(FIXTURE_VULN.is_file(), f"missing fixture: {FIXTURE_VULN}")
        self.assertTrue(FIXTURE_CLEAN.is_file(), f"missing fixture: {FIXTURE_CLEAN}")

        vulnerable_hits = detector.scan_file(FIXTURE_VULN)
        clean_hits = detector.scan_file(FIXTURE_CLEAN)

        self.assertEqual(len(vulnerable_hits), 1)
        self.assertEqual(vulnerable_hits[0]["function"].lower(), "stake_thapt_v2")
        self.assertIn("zero-total-stake bootstrap guard", vulnerable_hits[0]["message"])
        self.assertEqual(clean_hits, [])

    def test_comment_only_guard_does_not_suppress_hit(self) -> None:
        detector = _load_detector()
        source = """
        module staking::thapt_pool {
            struct Pool has key { total_stake: u64, total_shares: u64 }
            public entry fun stake_thAPT_v2(pool: &mut Pool, amount: u64): u64 {
                // if (pool.total_stake == 0) { bootstrap }
                amount * pool.total_shares / pool.total_stake
            }
        }
        """

        self.assertEqual(len(detector.scan_text(source, "comment_guard.move")), 1)


if __name__ == "__main__":
    unittest.main()
