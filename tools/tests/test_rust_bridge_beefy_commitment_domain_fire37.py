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

DETECTOR = "bridge_beefy_commitment_domain_fire37"
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


class RustBridgeBeefyCommitmentDomainFire37Tests(unittest.TestCase):
    def test_detector_compiles(self) -> None:
        py_compile.compile(str(DETECTOR_PATH), doraise=True)

    def test_positive_fixture_fires_on_beefy_commitment_domain_omission(self) -> None:
        hits, log_text = _run_fixture(POSITIVE)
        self.assertGreaterEqual(hits, 1, log_text)
        self.assertIn("submit_beefy_commitment", log_text)
        self.assertIn("bridge-proof-domain-bypass", log_text)
        self.assertIn("source_chain", log_text)
        self.assertIn("destination_chain", log_text)
        self.assertIn("route", log_text)
        self.assertIn("pallet", log_text)
        self.assertIn("network", log_text)
        self.assertIn("client_namespace", log_text)

    def test_negative_fixture_is_silent_when_commitment_fields_are_bound(self) -> None:
        hits, log_text = _run_fixture(NEGATIVE)
        self.assertEqual(hits, 0, log_text)

    def test_fixture_pair_contains_semantic_contrast(self) -> None:
        positive = POSITIVE.read_text(encoding="utf-8")
        negative = NEGATIVE.read_text(encoding="utf-8")

        self.assertIn("proof.payload_hash", positive)
        self.assertIn("proof.mmr_leaf_hash", positive)
        self.assertIn("proof.validator_set_root", positive)
        self.assertIn("verifier.verify_beefy_commitment(proof_digest", positive)
        self.assertNotIn("BEEFY_COMMITMENT_DOMAIN_FIRE37", positive)
        self.assertNotIn("source_chain_id.to_be_bytes()", positive)

        self.assertIn("BEEFY_COMMITMENT_DOMAIN_FIRE37", negative)
        self.assertIn("source_chain_id.to_be_bytes()", negative)
        self.assertIn("destination_chain_id.to_be_bytes()", negative)
        self.assertIn("route_id.0.to_be_bytes()", negative)
        self.assertIn("pallet_id.0", negative)
        self.assertIn("network_id.to_be_bytes()", negative)
        self.assertIn("client_namespace.0.to_be_bytes()", negative)
        self.assertLess(
            negative.index("source_chain_id.to_be_bytes()"),
            negative.index("verifier.verify_beefy_commitment"),
        )


if __name__ == "__main__":
    unittest.main()
