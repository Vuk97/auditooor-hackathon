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
DETECTOR = (
    REPO_ROOT
    / "detectors"
    / "rust_wave1"
    / "missing_recipient_or_account_binding_fire18.py"
)
FIXTURES = REPO_ROOT / "detectors" / "rust_wave1" / "test_fixtures"
DETECTOR_ID = "missing_recipient_or_account_binding_fire18"
POSITIVE = FIXTURES / f"{DETECTOR_ID}_positive.rs"
NEGATIVE = FIXTURES / f"{DETECTOR_ID}_negative.rs"

CONFIRMED_FIRE16 = FIXTURES / "missing_recipient_policy_fire16_positive.rs"
CONFIRMED_COINTYPE = FIXTURES / "r94_loop_cointype_wrap_unvalidated_positive.rs"
CONFIRMED_COINTYPE_CLEAN = FIXTURES / "r94_loop_cointype_wrap_unvalidated_negative.rs"
CONFIRMED_CPI = FIXTURES / "r94_loop_cpi_remaining_accounts_unvalidated_positive.rs"
CONFIRMED_CPI_CLEAN = FIXTURES / "r94_loop_cpi_remaining_accounts_unvalidated_negative.rs"

_HIT_RE = re.compile(rf"^=== {DETECTOR_ID}\s+\((\d+) hits\)", re.MULTILINE)


def _run_fixture(fixture: Path) -> tuple[int, str]:
    with tempfile.NamedTemporaryFile(prefix=".rust_fire18_missing_recipient_", suffix=".log") as tmp:
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
            timeout=120,
        )
        if proc.returncode != 0:
            raise AssertionError(proc.stdout)
        text = Path(tmp.name).read_text(encoding="utf-8", errors="ignore")
    match = _HIT_RE.search(text)
    return (int(match.group(1)) if match else 0, text)


class RustMissingRecipientOrAccountBindingFire18Test(unittest.TestCase):
    def test_detector_compiles(self) -> None:
        py_compile.compile(str(DETECTOR), doraise=True)

    def test_positive_fixture_fires_on_all_bound_shapes(self) -> None:
        hits, log_text = _run_fixture(POSITIVE)
        self.assertEqual(hits, 4, log_text)
        self.assertIn("recipient", log_text)
        self.assertIn("coin type or origin asset", log_text)
        self.assertIn("remaining_accounts", log_text)
        self.assertIn("payload.owner", log_text)

    def test_negative_fixture_is_silent(self) -> None:
        hits, log_text = _run_fixture(NEGATIVE)
        self.assertEqual(hits, 0, log_text)

    def test_confirmed_missing_recipient_policy_fire16_positive_replays(self) -> None:
        hits, log_text = _run_fixture(CONFIRMED_FIRE16)
        self.assertGreaterEqual(hits, 3, log_text)

    def test_confirmed_cointype_wrap_positive_replays(self) -> None:
        hits, log_text = _run_fixture(CONFIRMED_COINTYPE)
        self.assertGreaterEqual(hits, 1, log_text)

    def test_confirmed_cointype_wrap_clean_is_silent(self) -> None:
        hits, log_text = _run_fixture(CONFIRMED_COINTYPE_CLEAN)
        self.assertEqual(hits, 0, log_text)

    def test_confirmed_cpi_remaining_accounts_positive_replays(self) -> None:
        hits, log_text = _run_fixture(CONFIRMED_CPI)
        self.assertGreaterEqual(hits, 1, log_text)

    def test_confirmed_cpi_remaining_accounts_clean_is_silent(self) -> None:
        hits, log_text = _run_fixture(CONFIRMED_CPI_CLEAN)
        self.assertEqual(hits, 0, log_text)


if __name__ == "__main__":
    unittest.main()
