from __future__ import annotations

import importlib.util
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
DETECTOR_ID = "rewards_orphan_checkpoint_fire38"
DETECTOR = REPO_ROOT / "detectors" / "rust_wave1" / f"{DETECTOR_ID}.py"
POSITIVE = FIXTURES / f"{DETECTOR_ID}_positive.rs"
NEGATIVE = FIXTURES / f"{DETECTOR_ID}_negative.rs"

_HIT_RE = re.compile(rf"^=== {DETECTOR_ID}\s+\((\d+) hits\)", re.MULTILINE)


def _load_detector():
    spec = importlib.util.spec_from_file_location(DETECTOR_ID, DETECTOR)
    if spec is None or spec.loader is None:
        raise AssertionError(f"cannot load {DETECTOR}")
    module = importlib.util.module_from_spec(spec)
    sys.path.insert(0, str(DETECTOR.parent))
    try:
        spec.loader.exec_module(module)
    finally:
        try:
            sys.path.remove(str(DETECTOR.parent))
        except ValueError:
            pass
    return module


def _run_fixture(fixture: Path) -> tuple[int, str]:
    with tempfile.NamedTemporaryFile(prefix=".rust_rewards_fire38_", suffix=".log") as tmp:
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


class RustRewardsOrphanCheckpointFire38Tests(unittest.TestCase):
    def test_detector_and_test_compile(self) -> None:
        py_compile.compile(str(DETECTOR), doraise=True)
        py_compile.compile(str(Path(__file__)), doraise=True)

    def test_positive_fixture_flags_transfer_vault_and_vote_orphans(self) -> None:
        text = POSITIVE.read_text(encoding="utf-8")
        self.assertLess(
            text.index("self.balances.insert(from, from_balance - amount);"),
            text.index("self.settle_accrued_rewards(from);"),
        )
        self.assertLess(
            text.index("self.vault_allocations.insert(vault_id, allocation);"),
            text.index("self.sync_reward_checkpoint(vault_id);"),
        )
        self.assertLess(
            text.index("self.delegated_weight.insert(delegatee, weight);"),
            text.index("self.sync_vote_reward_checkpoint(delegatee);"),
        )

        hits, log_text = _run_fixture(POSITIVE)
        self.assertEqual(hits, 3, log_text)
        self.assertIn("balance or stake transfer write", log_text)
        self.assertIn("vault allocation or reward denominator write", log_text)
        self.assertIn("vote checkpoint or delegated weight write", log_text)
        self.assertIn("rewards-distribution-skew", log_text)
        self.assertIn("Fire38 orphan checkpoint lift", log_text)

    def test_negative_fixture_settles_or_syncs_before_mutation(self) -> None:
        text = NEGATIVE.read_text(encoding="utf-8")
        self.assertLess(
            text.index("self.settle_accrued_rewards(from);"),
            text.index("self.balances.insert(from, from_balance - amount);"),
        )
        self.assertLess(
            text.index("self.sync_reward_checkpoint(vault_id);"),
            text.index("self.vault_allocations.insert(vault_id, allocation);"),
        )
        self.assertLess(
            text.index("self.sync_vote_reward_checkpoint(delegatee);"),
            text.index("self.delegated_weight.insert(delegatee, weight);"),
        )
        self.assertIn("string_bait", text)

        hits, log_text = _run_fixture(NEGATIVE)
        self.assertEqual(hits, 0, log_text)

    def test_detector_declares_candidate_only_provenance(self) -> None:
        module = _load_detector()
        self.assertEqual(
            module.DETECTOR_ID,
            "rust_wave1.rewards_orphan_checkpoint_fire38",
        )
        self.assertEqual(module.SUBMISSION_POSTURE, "NOT_SUBMIT_READY")
        self.assertEqual(
            module.VERIFICATION_TIER,
            "tier-3-synthetic-taxonomy-anchored",
        )
        detector_text = DETECTOR.read_text(encoding="utf-8")
        self.assertIn("R40/R76/R80 evidence honesty", detector_text)
        self.assertIn("Class: rewards-distribution-skew", detector_text)


if __name__ == "__main__":
    unittest.main()
