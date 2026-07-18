from __future__ import annotations

import py_compile
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
DETECTOR = (
    REPO_ROOT
    / "detectors"
    / "rust_wave1"
    / "contextual_consensus_validation_gap_fire21.py"
)
TEST_FILE = HERE / "test_rust_contextual_consensus_validation_gap_fire21.py"
DETECTOR_ID = "contextual_consensus_validation_gap_fire21"
ATTACK_CLASS = "contextual-consensus-validation-gap"
DETECTOR_TO_AC_MAP = REPO_ROOT / "reference" / "detector_to_attack_classes_map.yaml"
COMPLETE_MAP = REPO_ROOT / "reference" / "detector_class_map_complete.yaml"
POSITIVE = FIXTURES / f"{DETECTOR_ID}_positive.rs"
NEGATIVE = FIXTURES / f"{DETECTOR_ID}_negative.rs"
_HIT_RE = re.compile(rf"^=== {DETECTOR_ID}\s+\((\d+) hits\)", re.MULTILINE)


def _run_fixture(fixture: Path) -> tuple[int, str]:
    with tempfile.NamedTemporaryFile(
        prefix=".rust_fire21_contextual_consensus_",
        suffix=".log",
    ) as tmp:
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
    return int(match.group(1)) if match else 0, text


class RustContextualConsensusValidationGapFire21Test(unittest.TestCase):
    def test_detector_and_test_compile(self) -> None:
        py_compile.compile(str(DETECTOR), doraise=True)
        py_compile.compile(str(TEST_FILE), doraise=True)

    def test_class_maps_bind_detector_to_same_class(self) -> None:
        detector_map = yaml.safe_load(DETECTOR_TO_AC_MAP.read_text(encoding="utf-8"))["mappings"]
        complete_map = yaml.safe_load(COMPLETE_MAP.read_text(encoding="utf-8"))["mappings"]

        for detector_id in (
            "rust_wave1.contextual_consensus_validation_gap_fire21",
            "contextual_consensus_validation_gap_fire21",
        ):
            with self.subTest(detector_id=detector_id):
                self.assertEqual(detector_map[detector_id][0], ATTACK_CLASS)
                self.assertEqual(complete_map[detector_id]["attack_class"], ATTACK_CLASS)
                self.assertTrue(complete_map[detector_id]["has_fixture_pair"])

    def test_positive_fixture_fires_on_contextual_anchor_and_root_gaps(self) -> None:
        hits, log_text = _run_fixture(POSITIVE)
        self.assertEqual(hits, 2, log_text)
        self.assertIn("contextual-consensus-validation-gap", log_text)
        self.assertIn("finalized state", log_text)
        self.assertIn("tree root", log_text)

    def test_negative_fixture_is_silent_when_context_is_bound(self) -> None:
        hits, log_text = _run_fixture(NEGATIVE)
        self.assertEqual(hits, 0, log_text)

    def test_confirmed_zebra_miss_is_recalled(self) -> None:
        hits, log_text = _run_fixture(
            FIXTURES / "zebra_anchor_contextual_validation_gap_positive.rs"
        )
        self.assertGreaterEqual(hits, 1, log_text)

    def test_confirmed_zebra_clean_control_is_silent(self) -> None:
        hits, log_text = _run_fixture(
            FIXTURES / "zebra_anchor_contextual_validation_gap_negative.rs"
        )
        self.assertEqual(hits, 0, log_text)


if __name__ == "__main__":
    unittest.main()
