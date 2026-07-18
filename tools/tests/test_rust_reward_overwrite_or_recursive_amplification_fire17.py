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
DETECTOR = "reward_overwrite_or_recursive_amplification_fire17"
DETECTOR_PATH = REPO_ROOT / "detectors" / "rust_wave1" / f"{DETECTOR}.py"
POSITIVE = FIXTURES / f"{DETECTOR}_positive.rs"
NEGATIVE = FIXTURES / f"{DETECTOR}_negative.rs"

SEED_POSITIVES = (
    "r94_loop_htlc_reward_overwrite_positive.rs",
    "r94_loop_incentivized_erc20_recursive_liquidity_reward_amplification_positive.rs",
    "r94_loop_restaking_node_operator_withdraw_credentials_overwrite_positive.rs",
)
SEED_NEGATIVES = (
    "r94_loop_htlc_reward_overwrite_negative.rs",
    "r94_loop_incentivized_erc20_recursive_liquidity_reward_amplification_negative.rs",
    "r94_loop_restaking_node_operator_withdraw_credentials_overwrite_negative.rs",
)

_HIT_RE = re.compile(rf"^=== {DETECTOR}\s+\((\d+) hits\)", re.MULTILINE)


def _run_fixture(fixture: Path) -> tuple[int, str]:
    with tempfile.NamedTemporaryFile(prefix=".rust_rewards_fire17_", suffix=".log") as tmp:
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


class RustRewardOverwriteOrRecursiveAmplificationFire17Tests(unittest.TestCase):
    def test_detector_compiles(self) -> None:
        py_compile.compile(str(DETECTOR_PATH), doraise=True)

    def test_positive_fixture_covers_three_reward_skew_shapes(self) -> None:
        text = POSITIVE.read_text(encoding="utf-8")
        self.assertIn("lock.reward = amount", text)
        self.assertIn("bal * pool.acc_reward_per_share", text)
        self.assertIn("save_withdraw_credentials", text)

        hits, log_text = _run_fixture(POSITIVE)
        self.assertEqual(hits, 3, log_text)
        self.assertIn("overwrite-or-recursive", log_text)
        self.assertIn("source-principal", log_text)
        self.assertIn("caller-supplied withdrawal credentials", log_text)
        self.assertIn("rewards-distribution-skew", log_text)

    def test_negative_fixture_preserves_and_authorizes_reward_flow(self) -> None:
        text = NEGATIVE.read_text(encoding="utf-8")
        self.assertIn("lock.reward == 0", text)
        self.assertIn("is_pool_or_vault", text)
        self.assertIn("require_auth(&admin)", text)
        self.assertIn("current_creds == [0u8; 20]", text)

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


if __name__ == "__main__":
    unittest.main()
