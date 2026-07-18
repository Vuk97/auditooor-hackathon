from __future__ import annotations

import importlib.util
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
DETECTOR_ID = "bridge_proof_domain_source_commitment_missing"
_HIT_RE = re.compile(rf"^=== {DETECTOR_ID}\s+\((\d+) hits\)", re.MULTILINE)


def _run_fixture(fixture: Path) -> int:
    with tempfile.NamedTemporaryFile(suffix=".log", delete=False) as tf:
        log_path = Path(tf.name)
    try:
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
                str(log_path),
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=False,
        )
        if proc.returncode != 0:
            raise AssertionError(proc.stderr or proc.stdout)
        text = log_path.read_text(encoding="utf-8", errors="ignore")
        match = _HIT_RE.search(text)
        return int(match.group(1)) if match else 0
    finally:
        log_path.unlink(missing_ok=True)


def _load_backtest_module():
    path = REPO_ROOT / "tools" / "audit" / "detector-catch-rate-backtest.py"
    spec = importlib.util.spec_from_file_location("_detector_catch_rate_backtest", path)
    mod = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(mod)
    return mod


class BridgeProofDomainSourceCommitmentMissingTests(unittest.TestCase):
    def test_slug_falls_into_bridge_proof_domain_class(self) -> None:
        mod = _load_backtest_module()
        self.assertEqual(
            mod.derive_attack_class(DETECTOR_ID, None),
            "bridge-proof-domain-bypass",
        )

    def test_positive_fixture_fires(self) -> None:
        hits = _run_fixture(
            FIXTURES / "bridge_proof_domain_source_commitment_missing_positive.rs"
        )
        self.assertGreaterEqual(hits, 1)

    def test_negative_fixture_is_silent(self) -> None:
        hits = _run_fixture(
            FIXTURES / "bridge_proof_domain_source_commitment_missing_negative.rs"
        )
        self.assertEqual(hits, 0)

    def test_existing_fire2_message_digest_miss_fires(self) -> None:
        hits = _run_fixture(
            FIXTURES
            / "r94_loop_bridge_message_hash_missing_lane_or_chain_domain_positive.rs"
        )
        self.assertGreaterEqual(hits, 1)

    def test_existing_fire2_message_digest_clean_is_silent(self) -> None:
        hits = _run_fixture(
            FIXTURES / "r94_loop_bridge_message_hash_missing_lane_or_chain_domain_clean.rs"
        )
        self.assertEqual(hits, 0)


if __name__ == "__main__":
    unittest.main()
