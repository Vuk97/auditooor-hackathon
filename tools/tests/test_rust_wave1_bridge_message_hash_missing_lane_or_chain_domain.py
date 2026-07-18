from __future__ import annotations

import re
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

import yaml


HERE = Path(__file__).resolve().parent
REPO_ROOT = HERE.parent.parent
RUST_DETECT = REPO_ROOT / "tools" / "rust-detect.py"
FIXTURES = REPO_ROOT / "detectors" / "rust_wave1" / "test_fixtures"
DETECTOR_ID = "r94_loop_bridge_message_hash_missing_lane_or_chain_domain"
DETECTOR_TO_AC_MAP = REPO_ROOT / "reference" / "detector_to_attack_classes_map.yaml"
COMPLETE_MAP = REPO_ROOT / "reference" / "detector_class_map_complete.yaml"
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


class RustWave1BridgeMessageHashMissingLaneOrChainDomainTests(unittest.TestCase):
    def test_map_aliases_resolve_to_bridge_domain_bypass(self) -> None:
        detector_map = yaml.safe_load(DETECTOR_TO_AC_MAP.read_text(encoding="utf-8"))["mappings"]
        complete_map = yaml.safe_load(COMPLETE_MAP.read_text(encoding="utf-8"))["mappings"]

        for detector_id in (
            "rust_wave1.r94_loop_bridge_message_hash_missing_lane_or_chain_domain",
            "r94_loop_bridge_message_hash_missing_lane_or_chain_domain",
        ):
            self.assertEqual(detector_map[detector_id][0], "bridge-proof-domain-bypass")
            self.assertEqual(
                complete_map[detector_id]["attack_class"],
                "bridge-proof-domain-bypass",
            )

    def test_positive_fixture_fires(self) -> None:
        hits = _run_fixture(
            FIXTURES / "r94_loop_bridge_message_hash_missing_lane_or_chain_domain_positive.rs"
        )
        self.assertGreaterEqual(hits, 1)

    def test_clean_fixture_is_silent(self) -> None:
        hits = _run_fixture(
            FIXTURES / "r94_loop_bridge_message_hash_missing_lane_or_chain_domain_clean.rs"
        )
        self.assertEqual(hits, 0)

    def test_client_id_positive_fixture_fires(self) -> None:
        hits = _run_fixture(
            FIXTURES / "r94_loop_bridge_message_hash_missing_lane_or_chain_domain_client_id_positive.rs"
        )
        self.assertGreaterEqual(hits, 1)

    def test_client_id_clean_fixture_is_silent(self) -> None:
        hits = _run_fixture(
            FIXTURES / "r94_loop_bridge_message_hash_missing_lane_or_chain_domain_client_id_clean.rs"
        )
        self.assertEqual(hits, 0)

    def test_destination_domain_positive_fixture_fires(self) -> None:
        hits = _run_fixture(
            FIXTURES
            / "r94_loop_bridge_message_hash_missing_lane_or_chain_domain_destination_domain_positive.rs"
        )
        self.assertGreaterEqual(hits, 1)

    def test_destination_domain_clean_fixture_is_silent(self) -> None:
        hits = _run_fixture(
            FIXTURES
            / "r94_loop_bridge_message_hash_missing_lane_or_chain_domain_destination_domain_clean.rs"
        )
        self.assertEqual(hits, 0)

    def test_destination_chain_positive_fixture_fires(self) -> None:
        hits = _run_fixture(
            FIXTURES
            / "r94_loop_bridge_message_hash_missing_lane_or_chain_domain_destination_chain_positive.rs"
        )
        self.assertGreaterEqual(hits, 1)

    def test_destination_chain_clean_fixture_is_silent(self) -> None:
        hits = _run_fixture(
            FIXTURES
            / "r94_loop_bridge_message_hash_missing_lane_or_chain_domain_destination_chain_clean.rs"
        )
        self.assertEqual(hits, 0)


if __name__ == "__main__":
    unittest.main()
