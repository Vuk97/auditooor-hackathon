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
DETECTOR_ID = "privileged_setter_missing_caller_bound_auth"
PREFIXED_DETECTOR_ID = "rust_wave1.privileged_setter_missing_caller_bound_auth"
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


class RustWave1PrivilegedSetterMissingCallerBoundAuthTests(unittest.TestCase):
    def test_detector_ids_route_to_admin_bypass(self) -> None:
        detector_map = yaml.safe_load(DETECTOR_TO_AC_MAP.read_text(encoding="utf-8"))["mappings"]
        complete_map = yaml.safe_load(COMPLETE_MAP.read_text(encoding="utf-8"))["mappings"]
        for detector_id in (DETECTOR_ID, PREFIXED_DETECTOR_ID):
            self.assertIn("admin-bypass", detector_map[detector_id])
            self.assertEqual(
                complete_map[detector_id]["attack_class"],
                "admin-bypass",
            )

    def test_positive_fixture_fires(self) -> None:
        hits = _run_fixture(
            FIXTURES / "privileged_setter_missing_caller_bound_auth_positive.rs"
        )
        self.assertEqual(hits, 2)

    def test_negative_fixture_is_silent(self) -> None:
        hits = _run_fixture(
            FIXTURES / "privileged_setter_missing_caller_bound_auth_negative.rs"
        )
        self.assertEqual(hits, 0)

    def test_caller_comparison_to_requested_admin_still_fires(self) -> None:
        hits = _run_fixture(
            FIXTURES / "privileged_setter_missing_caller_bound_auth_caller_compare_positive.rs"
        )
        self.assertEqual(hits, 1)

    def test_authority_comparison_to_current_admin_is_silent(self) -> None:
        hits = _run_fixture(
            FIXTURES / "privileged_setter_missing_caller_bound_auth_authority_compare_negative.rs"
        )
        self.assertEqual(hits, 0)

    def test_anchor_signer_authority_is_silent(self) -> None:
        hits = _run_fixture(
            FIXTURES / "privileged_setter_missing_caller_bound_auth_anchor_signer_negative.rs"
        )
        self.assertEqual(hits, 0)

    def test_unrelated_anchor_signer_still_fires(self) -> None:
        hits = _run_fixture(
            FIXTURES / "privileged_setter_missing_caller_bound_auth_unrelated_anchor_signer_positive.rs"
        )
        self.assertEqual(hits, 1)


if __name__ == "__main__":
    unittest.main()
