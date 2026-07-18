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
DETECTOR_ID = "r94_loop_soroban_transfer_to_repay_missing_recipient_validation"
SPEC = REPO_ROOT / "detectors" / "_specs" / "drafts_rust_soroban" / "missing-recipient-validation.yaml"
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


class RustWave1SorobanRecipientValidationTests(unittest.TestCase):
    def test_metadata_wires_soroban_spec_and_detector_id_to_same_class(self) -> None:
        spec = yaml.safe_load(SPEC.read_text(encoding="utf-8"))
        detector_map = yaml.safe_load(DETECTOR_TO_AC_MAP.read_text(encoding="utf-8"))["mappings"]
        complete_map = yaml.safe_load(COMPLETE_MAP.read_text(encoding="utf-8"))["mappings"]

        self.assertEqual(spec["id"], "missing-recipient-validation")
        self.assertIn("missing-recipient-validation", spec["tags"])
        self.assertIn("input-validation", spec["attack_class_aliases"])
        expected_classes = {
            "rust_wave1.r94_loop_soroban_transfer_to_repay_missing_recipient_validation": "missing-recipient-validation",
            "r94_loop_soroban_transfer_to_repay_missing_recipient_validation": "missing-recipient-validation",
            "rust_wave1.financial_precision_loss_div_before_mul_or_float_cast": "precision-loss",
            "financial_precision_loss_div_before_mul_or_float_cast": "precision-loss",
            "rust_wave1.r94_loop_caller_supplied_from_passed_to_mutator_no_auth": "missing-access-control",
            "r94_loop_caller_supplied_from_passed_to_mutator_no_auth": "missing-access-control",
        }
        for detector_id, attack_class in expected_classes.items():
            self.assertEqual(detector_map[detector_id][0], attack_class)
            self.assertEqual(complete_map[detector_id]["attack_class"], attack_class)

    def test_positive_fixture_fires(self) -> None:
        hits = _run_fixture(
            FIXTURES
            / "r94_loop_soroban_transfer_to_repay_missing_recipient_validation_positive.rs"
        )
        self.assertEqual(hits, 2)

    def test_negative_fixture_is_silent(self) -> None:
        hits = _run_fixture(
            FIXTURES
            / "r94_loop_soroban_transfer_to_repay_missing_recipient_validation_negative.rs"
        )
        self.assertEqual(hits, 0)


if __name__ == "__main__":
    unittest.main()
