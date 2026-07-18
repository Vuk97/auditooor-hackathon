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
    / "bridge_domain_or_share_unlock_bypass_fire19.py"
)
TEST_FILE = HERE / "test_rust_bridge_domain_or_share_unlock_bypass_fire19.py"
FIXTURES = REPO_ROOT / "detectors" / "rust_wave1" / "test_fixtures"
DETECTOR_ID = "bridge_domain_or_share_unlock_bypass_fire19"
_HIT_RE = re.compile(rf"^=== {DETECTOR_ID}\s+\((\d+) hits\)", re.MULTILINE)


def _run_fixture(fixture_name: str) -> tuple[int, str]:
    with tempfile.NamedTemporaryFile(prefix=".rust_bridge_fire19_", suffix=".log") as tmp:
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


class RustBridgeDomainOrShareUnlockBypassFire19Tests(unittest.TestCase):
    def test_detector_and_test_compile(self) -> None:
        py_compile.compile(str(DETECTOR), doraise=True)
        py_compile.compile(str(TEST_FILE), doraise=True)

    def test_positive_fixture_fires_all_three_seed_shapes(self) -> None:
        hits, log_text = _run_fixture(
            "bridge_domain_or_share_unlock_bypass_fire19_positive.rs"
        )
        self.assertGreaterEqual(hits, 3, log_text)
        self.assertIn("checked burn", log_text)
        self.assertIn("caller-controlled target", log_text)
        self.assertIn("raw failure payload", log_text)

    def test_negative_fixture_is_silent(self) -> None:
        hits, log_text = _run_fixture(
            "bridge_domain_or_share_unlock_bypass_fire19_negative.rs"
        )
        self.assertEqual(hits, 0, log_text)

    def test_confirmed_share_unlock_miss_fires(self) -> None:
        hits, log_text = _run_fixture(
            "depositandbridge_bypasses_shareunlocktime_positive.rs"
        )
        self.assertGreaterEqual(hits, 1, log_text)
        self.assertIn("checked burn", log_text)

    def test_confirmed_generic_bridge_target_miss_fires(self) -> None:
        hits, log_text = _run_fixture(
            "generic_bridge_facet_allows_arbitrary_target_call_steals_via_user_allowance_positive.rs"
        )
        self.assertGreaterEqual(hits, 1, log_text)
        self.assertIn("caller-controlled target", log_text)

    def test_confirmed_layerzero_payload_miss_fires(self) -> None:
        hits, log_text = _run_fixture(
            "layerzero_channel_blocked_via_variable_gas_cost_payload_save_positive.rs"
        )
        self.assertGreaterEqual(hits, 1, log_text)
        self.assertIn("raw failure payload", log_text)


if __name__ == "__main__":
    unittest.main()
