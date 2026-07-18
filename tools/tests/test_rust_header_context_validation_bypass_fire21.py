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
CLASS_MAP = REPO_ROOT / "reference" / "detector_class_map_complete.yaml"
ROUTE_MAP = REPO_ROOT / "reference" / "detector_to_attack_classes_map.yaml"

DETECTOR = "header_context_validation_bypass_fire21"
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


class RustHeaderContextValidationBypassFire21Tests(unittest.TestCase):
    def test_detector_compiles(self) -> None:
        py_compile.compile(str(DETECTOR_PATH), doraise=True)

    def test_positive_fixture_fires(self) -> None:
        hits, log_text = _run_fixture(POSITIVE)
        self.assertGreaterEqual(hits, 1, log_text)
        self.assertIn("header context validation bypass", log_text)

    def test_negative_fixture_is_silent(self) -> None:
        hits, log_text = _run_fixture(NEGATIVE)
        self.assertEqual(hits, 0, log_text)

    def test_confirmed_zebra_header_context_miss_fires(self) -> None:
        hits, log_text = _run_fixture(
            FIXTURES / "zebra_header_context_validation_gap_positive.rs"
        )
        self.assertGreaterEqual(hits, 1, log_text)

    def test_zebra_context_bound_control_is_silent(self) -> None:
        hits, log_text = _run_fixture(
            FIXTURES / "zebra_header_context_validation_gap_negative.rs"
        )
        self.assertEqual(hits, 0, log_text)

    def test_class_maps_route_detector_to_header_context_bypass(self) -> None:
        complete = CLASS_MAP.read_text(encoding="utf-8")
        route = ROUTE_MAP.read_text(encoding="utf-8")
        self.assertIn("rust_wave1.header_context_validation_bypass_fire21:", complete)
        self.assertIn("header_context_validation_bypass_fire21:", complete)
        self.assertIn("attack_class: header-context-validation-bypass", complete)
        self.assertIn("rust_wave1.header_context_validation_bypass_fire21:", route)
        self.assertIn("header-context-validation-bypass", route)


if __name__ == "__main__":
    unittest.main()
