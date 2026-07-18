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
DETECTOR = "oracle_price_manipulation_fire22"
DETECTOR_PATH = WAVE1_DIR / f"{DETECTOR}.py"
POSITIVE = FIXTURES / f"{DETECTOR}_positive.rs"
NEGATIVE = FIXTURES / f"{DETECTOR}_negative.rs"
CLASS_MAP = REPO_ROOT / "reference" / "detector_class_map_complete.yaml"
ROUTE_MAP = REPO_ROOT / "reference" / "detector_to_attack_classes_map.yaml"

_HIT_RE = re.compile(rf"^=== {DETECTOR}\s+\((\d+) hits\)", re.MULTILINE)


def _run_fixture(fixture: Path) -> tuple[int, str]:
    with tempfile.NamedTemporaryFile(
        prefix=".rust_fire22_oracle_price_",
        suffix=".log",
    ) as tmp:
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
    return int(match.group(1)) if match else 0, log_text


class RustOraclePriceManipulationFire22Test(unittest.TestCase):
    def test_detector_and_test_compile(self) -> None:
        py_compile.compile(str(DETECTOR_PATH), doraise=True)
        py_compile.compile(str(Path(__file__)), doraise=True)

    def test_positive_fixture_fires_on_four_confirmed_shapes(self) -> None:
        text = POSITIVE.read_text(encoding="utf-8")
        self.assertIn("age > self.max_heartbeat", text)
        self.assertIn("return self.last_version", text)
        self.assertIn("self.cached_price = report.price", text)
        self.assertIn("quote_balance.saturating_mul", text)

        hits, log_text = _run_fixture(POSITIVE)
        self.assertEqual(hits, 4, log_text)
        self.assertIn("heartbeat staleness", log_text)
        self.assertIn("previous oracle version", log_text)
        self.assertIn("mutable cached oracle price", log_text)
        self.assertIn("PMM/internal reserve price", log_text)
        self.assertIn("oracle-price-manipulation", log_text)

    def test_negative_fixture_is_silent_with_freshness_and_bounds(self) -> None:
        text = NEGATIVE.read_text(encoding="utf-8")
        self.assertIn("self.ensure_fresh", text)
        self.assertIn("self.ensure_deviation", text)
        self.assertIn("valid: false", text)

        hits, log_text = _run_fixture(NEGATIVE)
        self.assertEqual(hits, 0, log_text)

    def test_class_maps_route_detector_to_oracle_price_manipulation(self) -> None:
        complete = CLASS_MAP.read_text(encoding="utf-8")
        route = ROUTE_MAP.read_text(encoding="utf-8")
        self.assertIn(f"rust_wave1.{DETECTOR}:", complete)
        self.assertIn(f"{DETECTOR}:", complete)
        self.assertIn("attack_class: oracle-price-manipulation", complete)
        self.assertIn(f"rust_wave1.{DETECTOR}:", route)
        self.assertIn(f"{DETECTOR}:", route)
        self.assertIn("- oracle-price-manipulation", route)


if __name__ == "__main__":
    unittest.main()
