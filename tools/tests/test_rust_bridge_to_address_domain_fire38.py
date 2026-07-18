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

DETECTOR = "bridge_to_address_domain_fire38"
DETECTOR_PATH = WAVE1_DIR / f"{DETECTOR}.py"
POSITIVE = FIXTURES / f"{DETECTOR}_positive.rs"
NEGATIVE = FIXTURES / f"{DETECTOR}_negative.rs"
_HIT_RE = re.compile(rf"^=== {re.escape(DETECTOR)}\s+\((\d+) hits\)", re.MULTILINE)


def _run_fixture(fixture: Path) -> tuple[int, str]:
    with tempfile.NamedTemporaryFile(suffix=".log", delete=False) as tmp:
        log_path = Path(tmp.name)
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
            timeout=60,
        )
        if proc.returncode != 0:
            raise AssertionError(proc.stderr or proc.stdout)
        log_text = log_path.read_text(encoding="utf-8", errors="ignore")
        match = _HIT_RE.search(log_text)
        return (int(match.group(1)) if match else 0), log_text
    finally:
        log_path.unlink(missing_ok=True)


class RustBridgeToAddressDomainFire38Tests(unittest.TestCase):
    def test_detector_compiles(self) -> None:
        py_compile.compile(str(DETECTOR_PATH), doraise=True)

    def test_positive_fixture_fires_on_request_domain_omission(self) -> None:
        hits, log_text = _run_fixture(POSITIVE)
        self.assertGreaterEqual(hits, 1, log_text)
        self.assertIn("finalize_bridge_transfer", log_text)
        self.assertIn("bridge-proof-domain-bypass", log_text)
        self.assertIn("to_address", log_text)
        self.assertIn("destination_chain", log_text)
        self.assertIn("source_chain", log_text)
        self.assertIn("lane_channel", log_text)
        self.assertIn("source_commitment", log_text)
        self.assertIn("message_id", log_text)

    def test_negative_fixture_is_silent_when_request_fields_are_bound(self) -> None:
        hits, log_text = _run_fixture(NEGATIVE)
        self.assertEqual(hits, 0, log_text)

    def test_fixture_pair_contains_semantic_contrast(self) -> None:
        positive = POSITIVE.read_text(encoding="utf-8")
        negative = NEGATIVE.read_text(encoding="utf-8")

        self.assertIn("request.to_address", positive)
        self.assertIn("request.destination_chain_id", positive)
        self.assertIn("request.lane_id", positive)
        self.assertIn("request.channel_id", positive)
        self.assertIn("request.source_commitment", positive)
        self.assertIn("request.message_id", positive)
        self.assertIn("dispatch_to_address(request.to_address", positive)
        self.assertNotIn("BRIDGE_TO_ADDRESS_DOMAIN_FIRE38", positive)
        self.assertNotIn("request.to_address);", positive.split("let proof_digest")[0])

        self.assertIn("BRIDGE_TO_ADDRESS_DOMAIN_FIRE38", negative)
        self.assertIn("request.to_address", negative)
        self.assertIn("request.destination_chain_id.to_be_bytes()", negative)
        self.assertIn("request.source_chain_id.to_be_bytes()", negative)
        self.assertIn("request.lane_id.to_be_bytes()", negative)
        self.assertIn("request.channel_id.to_be_bytes()", negative)
        self.assertIn("request.source_commitment", negative)
        self.assertIn("request.message_id", negative)
        self.assertLess(
            negative.index("request.to_address"),
            negative.index("verifier.verify_merkle_proof"),
        )


if __name__ == "__main__":
    unittest.main()
