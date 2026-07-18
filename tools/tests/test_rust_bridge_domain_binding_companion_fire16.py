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
DETECTOR = REPO_ROOT / "detectors" / "rust_wave1" / "bridge_domain_binding_companion_fire16.py"
FIXTURES = REPO_ROOT / "detectors" / "rust_wave1" / "test_fixtures"
DETECTOR_ID = "bridge_domain_binding_companion_fire16"
_HIT_RE = re.compile(rf"^=== {DETECTOR_ID}\s+\((\d+) hits\)", re.MULTILINE)


def _run_fixture(fixture_name: str) -> tuple[int, str]:
    with tempfile.NamedTemporaryFile(prefix=".rust_bridge_fire16_", suffix=".log") as tmp:
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


class RustBridgeDomainBindingCompanionFire16Tests(unittest.TestCase):
    def test_detector_compiles(self) -> None:
        py_compile.compile(str(DETECTOR), doraise=True)

    def test_positive_fixture_fires_all_three_seed_shapes(self) -> None:
        hits, log_text = _run_fixture("bridge_domain_binding_companion_fire16_positive.rs")
        self.assertGreaterEqual(hits, 3, log_text)
        self.assertIn("value", log_text)
        self.assertIn("fee", log_text)
        self.assertIn("source_chain_selector", log_text)
        self.assertIn("checkpoint", log_text)

    def test_negative_fixture_is_silent(self) -> None:
        hits, log_text = _run_fixture("bridge_domain_binding_companion_fire16_negative.rs")
        self.assertEqual(hits, 0, log_text)

    def test_signal_hash_forge_seed_fires(self) -> None:
        hits, log_text = _run_fixture(
            "bridge_signal_hash_forge_drain_protocol_via_collision_positive.rs"
        )
        self.assertGreaterEqual(hits, 1, log_text)
        self.assertIn("value", log_text)

    def test_signal_hash_forge_clean_is_silent(self) -> None:
        hits, log_text = _run_fixture(
            "bridge_signal_hash_forge_drain_protocol_via_collision_negative.rs"
        )
        self.assertEqual(hits, 0, log_text)

    def test_validator_set_seed_fires(self) -> None:
        hits, log_text = _run_fixture(
            "bridge_validator_set_hash_not_domain_separated_positive.rs"
        )
        self.assertGreaterEqual(hits, 1, log_text)
        self.assertIn("checkpoint", log_text)

    def test_validator_set_clean_is_silent(self) -> None:
        hits, log_text = _run_fixture(
            "bridge_validator_set_hash_not_domain_separated_negative.rs"
        )
        self.assertEqual(hits, 0, log_text)

    def test_ccip_source_chain_seed_fires(self) -> None:
        hits, log_text = _run_fixture(
            "ccip_ccipreceive_missing_source_chain_validation_positive.rs"
        )
        self.assertGreaterEqual(hits, 1, log_text)
        self.assertIn("source_chain_selector", log_text)

    def test_ccip_source_chain_clean_is_silent(self) -> None:
        hits, log_text = _run_fixture(
            "ccip_ccipreceive_missing_source_chain_validation_negative.rs"
        )
        self.assertEqual(hits, 0, log_text)


if __name__ == "__main__":
    unittest.main()
