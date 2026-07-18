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
DETECTOR = REPO_ROOT / "detectors" / "rust_wave1" / "bridge_proof_domain_binding_fire15.py"
FIXTURES = REPO_ROOT / "detectors" / "rust_wave1" / "test_fixtures"
DETECTOR_ID = "bridge_proof_domain_binding_fire15"
_HIT_RE = re.compile(rf"^=== {DETECTOR_ID}\s+\((\d+) hits\)", re.MULTILINE)


def _run_fixture(fixture_name: str) -> tuple[int, str]:
    with tempfile.NamedTemporaryFile(prefix=".rust_bridge_fire15_", suffix=".log") as tmp:
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


class RustBridgeProofDomainBindingFire15Tests(unittest.TestCase):
    def test_detector_compiles(self) -> None:
        py_compile.compile(str(DETECTOR), doraise=True)

    def test_fire15_positive_omitted_source_destination_recipient_and_amount_fires(
        self,
    ) -> None:
        hits, log_text = _run_fixture("bridge_proof_domain_binding_fire15_positive.rs")
        self.assertGreaterEqual(hits, 1, log_text)
        self.assertIn("source", log_text)
        self.assertIn("destination", log_text)
        self.assertIn("recipient", log_text)
        self.assertIn("amount", log_text)

    def test_fire15_negative_bound_digest_is_silent(self) -> None:
        hits, log_text = _run_fixture("bridge_proof_domain_binding_fire15_negative.rs")
        self.assertEqual(hits, 0, log_text)

    def test_confirmed_companion_miss_fires(self) -> None:
        hits, log_text = _run_fixture("bridge_proof_domain_companion_fire12_positive.rs")
        self.assertGreaterEqual(hits, 1, log_text)
        self.assertIn("recipient", log_text)
        self.assertIn("amount", log_text)

    def test_confirmed_companion_clean_is_silent(self) -> None:
        hits, log_text = _run_fixture("bridge_proof_domain_companion_fire12_negative.rs")
        self.assertEqual(hits, 0, log_text)

    def test_confirmed_source_commitment_miss_fires(self) -> None:
        hits, log_text = _run_fixture(
            "bridge_proof_domain_source_commitment_missing_positive.rs"
        )
        self.assertGreaterEqual(hits, 1, log_text)
        self.assertIn("source", log_text)
        self.assertIn("commitment", log_text)

    def test_confirmed_source_commitment_clean_is_silent(self) -> None:
        hits, log_text = _run_fixture(
            "bridge_proof_domain_source_commitment_missing_negative.rs"
        )
        self.assertEqual(hits, 0, log_text)

    def test_confirmed_non_20_byte_recipient_miss_fires(self) -> None:
        hits, log_text = _run_fixture(
            "bridge_recipient_non_20_byte_payload_silently_burns_positive.rs"
        )
        self.assertGreaterEqual(hits, 1, log_text)
        self.assertIn("Non-20-byte", log_text)

    def test_confirmed_non_20_byte_recipient_clean_is_silent(self) -> None:
        hits, log_text = _run_fixture(
            "bridge_recipient_non_20_byte_payload_silently_burns_negative.rs"
        )
        self.assertEqual(hits, 0, log_text)


if __name__ == "__main__":
    unittest.main()
