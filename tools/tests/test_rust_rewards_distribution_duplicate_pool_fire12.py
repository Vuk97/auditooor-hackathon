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
DETECTOR = "rewards_distribution_duplicate_pool_fire12"
DETECTOR_PATH = REPO_ROOT / "detectors" / "rust_wave1" / f"{DETECTOR}.py"
POSITIVE = FIXTURES / f"{DETECTOR}_positive.rs"
NEGATIVE = FIXTURES / f"{DETECTOR}_negative.rs"
_HIT_RE = re.compile(rf"^=== {DETECTOR}\s+\((\d+) hits\)", re.MULTILINE)


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
            timeout=30,
        )
        if proc.returncode != 0:
            raise AssertionError(proc.stderr or proc.stdout)
        text = log_path.read_text(encoding="utf-8", errors="ignore")
        match = _HIT_RE.search(text)
        return int(match.group(1)) if match else 0, text
    finally:
        log_path.unlink(missing_ok=True)


class RustRewardsDistributionDuplicatePoolFire12Tests(unittest.TestCase):
    def test_detector_compiles(self) -> None:
        py_compile.compile(str(DETECTOR_PATH), doraise=True)

    def test_positive_flags_pair_keyed_rewards_for_full_pool_key(self) -> None:
        text = POSITIVE.read_text(encoding="utf-8")
        self.assertIn("pair_rewards: HashMap<([u8; 32], [u8; 32]), u128>", text)
        self.assertIn("fee: 500", text)
        self.assertIn("claim_rewards_for_pool(&duplicate_pool)", text)

        hits, log_text = _run_fixture(POSITIVE)
        self.assertEqual(hits, 1, log_text)
        self.assertIn("rewards-distribution-duplicate-pool-fire12", log_text)
        self.assertIn("rewards-distribution-skew", log_text)

    def test_negative_is_silent_when_canonical_pool_checked(self) -> None:
        text = NEGATIVE.read_text(encoding="utf-8")
        self.assertIn("canonical_pools.contains_key(&pair)", text)
        self.assertIn("if &supplied != canonical", text)

        hits, log_text = _run_fixture(NEGATIVE)
        self.assertEqual(hits, 0, log_text)


if __name__ == "__main__":
    unittest.main()
