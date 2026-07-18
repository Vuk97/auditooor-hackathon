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
DETECTOR = REPO_ROOT / "detectors" / "rust_wave1" / "gov_param_snapshot_or_timelock_fire16.py"
FIXTURES = REPO_ROOT / "detectors" / "rust_wave1" / "test_fixtures"
DETECTOR_ID = "gov_param_snapshot_or_timelock_fire16"
_HIT_RE = re.compile(rf"^=== {DETECTOR_ID}\s+\((\d+) hits\)", re.MULTILINE)


def _run_fixture(fixture_name: str) -> tuple[int, str]:
    with tempfile.NamedTemporaryFile(prefix=".rust_gov_param_fire16_", suffix=".log") as tmp:
        proc = subprocess.run(
            [
                sys.executable,
                str(RUST_DETECT),
                str(FIXTURES),
                "--only",
                DETECTOR_ID,
                "--file",
                str(FIXTURES / fixture_name),
                "--log",
                tmp.name,
            ],
            cwd=REPO_ROOT,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            timeout=120,
        )
        if proc.returncode != 0:
            raise AssertionError(proc.stdout)
        log_text = Path(tmp.name).read_text(encoding="utf-8", errors="ignore")

    match = _HIT_RE.search(log_text)
    return (int(match.group(1)) if match else 0, log_text)


class RustGovParamSnapshotOrTimelockFire16Tests(unittest.TestCase):
    def test_detector_compiles(self) -> None:
        py_compile.compile(str(DETECTOR), doraise=True)

    def test_fire16_positive_fixture_fires_on_all_three_variants(self) -> None:
        hits, log_text = _run_fixture("gov_param_snapshot_or_timelock_fire16_positive.rs")
        self.assertEqual(hits, 3, log_text)
        self.assertIn("snapshot-vote-power", log_text)
        self.assertIn("timelock-surplus-value-trap", log_text)
        self.assertIn("unguarded-governance-parameter-mutation", log_text)

    def test_fire16_negative_fixture_is_silent(self) -> None:
        hits, log_text = _run_fixture("gov_param_snapshot_or_timelock_fire16_negative.rs")
        self.assertEqual(hits, 0, log_text)

    def test_seed_current_balance_vote_positive_fires(self) -> None:
        hits, log_text = _run_fixture(
            "castvote_uses_current_balance_instead_of_snapshot_at_proposal_start_positive.rs"
        )
        self.assertGreaterEqual(hits, 1, log_text)
        self.assertIn("snapshot-vote-power", log_text)

    def test_seed_current_balance_vote_negative_is_silent(self) -> None:
        hits, log_text = _run_fixture(
            "castvote_uses_current_balance_instead_of_snapshot_at_proposal_start_negative.rs"
        )
        self.assertEqual(hits, 0, log_text)

    def test_seed_timelock_value_positive_fires(self) -> None:
        hits, log_text = _run_fixture("eth_can_be_locked_inside_timelock_contract_positive.rs")
        self.assertGreaterEqual(hits, 1, log_text)
        self.assertIn("timelock-surplus-value-trap", log_text)

    def test_seed_timelock_value_negative_is_silent(self) -> None:
        hits, log_text = _run_fixture("eth_can_be_locked_inside_timelock_contract_negative.rs")
        self.assertEqual(hits, 0, log_text)

    def test_seed_public_governance_intent_positive_fires(self) -> None:
        hits, log_text = _run_fixture(
            "public_servicenft_updateimpact_bypasses_governance_only_intent_positive.rs"
        )
        self.assertGreaterEqual(hits, 1, log_text)
        self.assertIn("unguarded-governance-parameter-mutation", log_text)

    def test_seed_public_governance_intent_negative_is_silent(self) -> None:
        hits, log_text = _run_fixture(
            "public_servicenft_updateimpact_bypasses_governance_only_intent_negative.rs"
        )
        self.assertEqual(hits, 0, log_text)


if __name__ == "__main__":
    unittest.main()
