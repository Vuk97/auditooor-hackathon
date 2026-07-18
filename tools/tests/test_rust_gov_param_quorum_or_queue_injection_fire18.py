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
WAVE1_DIR = REPO_ROOT / "detectors" / "rust_wave1"
FIXTURES = WAVE1_DIR / "test_fixtures"

DETECTOR = "gov_param_quorum_or_queue_injection_fire18"
DETECTOR_PATH = WAVE1_DIR / f"{DETECTOR}.py"
POSITIVE = FIXTURES / f"{DETECTOR}_positive.rs"
NEGATIVE = FIXTURES / f"{DETECTOR}_negative.rs"
_HIT_RE = re.compile(rf"^=== {re.escape(DETECTOR)}\s+\((\d+) hits\)", re.MULTILINE)


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
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=False,
            timeout=60,
        )
        if proc.returncode != 0:
            raise AssertionError(proc.stderr or proc.stdout)
        log_text = log_path.read_text(encoding="utf-8", errors="ignore")
        match = _HIT_RE.search(log_text)
        return (int(match.group(1)) if match else 0), log_text
    finally:
        log_path.unlink(missing_ok=True)


class RustGovParamQuorumOrQueueInjectionFire18Tests(unittest.TestCase):
    def test_detector_compiles(self) -> None:
        py_compile.compile(str(DETECTOR_PATH), doraise=True)

    def test_positive_fixture_fires_on_quorum_queue_ttl_and_execute_variants(self) -> None:
        hits, log_text = _run_fixture(POSITIVE)
        self.assertGreaterEqual(hits, 5, log_text)
        self.assertIn("quorum-quadratic-linear-mismatch", log_text)
        self.assertIn("quorum-against-abstain-mixup", log_text)
        self.assertIn("queued-action-hash-collision", log_text)
        self.assertIn("schedule-missing-ttl", log_text)
        self.assertIn("unguarded-proposal-external-call", log_text)

    def test_negative_fixture_is_silent_with_snapshot_units_unique_keys_ttl_and_auth(self) -> None:
        hits, log_text = _run_fixture(NEGATIVE)
        self.assertEqual(hits, 0, log_text)

    def test_confirmed_quadratic_quorum_miss_fires(self) -> None:
        hits, log_text = _run_fixture(
            FIXTURES / "quadratic_voting_incompatible_with_quorum_fraction_arithmetic_positive.rs"
        )
        self.assertGreaterEqual(hits, 1, log_text)
        self.assertIn("quorum-quadratic-linear-mismatch", log_text)

    def test_confirmed_queue_duplicate_action_miss_fires(self) -> None:
        hits, log_text = _run_fixture(
            FIXTURES / "queued_proposal_with_repeated_actions_cannot_be_executed_positive.rs"
        )
        self.assertGreaterEqual(hits, 1, log_text)
        self.assertIn("queued-action-hash-collision", log_text)

    def test_confirmed_abstain_against_mixup_miss_fires(self) -> None:
        hits, log_text = _run_fixture(
            FIXTURES / "quorum_wrongly_counts_against_abstain_not_for_abstain_positive.rs"
        )
        self.assertGreaterEqual(hits, 1, log_text)
        self.assertIn("quorum-against-abstain-mixup", log_text)

    def test_confirmed_negative_companions_stay_silent(self) -> None:
        for fixture_name in [
            "quadratic_voting_incompatible_with_quorum_fraction_arithmetic_negative.rs",
            "queued_proposal_with_repeated_actions_cannot_be_executed_negative.rs",
            "quorum_wrongly_counts_against_abstain_not_for_abstain_negative.rs",
        ]:
            hits, log_text = _run_fixture(FIXTURES / fixture_name)
            self.assertEqual(hits, 0, f"{fixture_name}\n{log_text}")


if __name__ == "__main__":
    unittest.main()
