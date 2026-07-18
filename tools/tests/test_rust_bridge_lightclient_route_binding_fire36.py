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

DETECTOR = "bridge_lightclient_route_binding_fire36"
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


class RustBridgeLightclientRouteBindingFire36Tests(unittest.TestCase):
    def test_detector_compiles(self) -> None:
        py_compile.compile(str(DETECTOR_PATH), doraise=True)

    def test_positive_fixture_fires_on_route_binding_omission(self) -> None:
        hits, log_text = _run_fixture(POSITIVE)
        self.assertGreaterEqual(hits, 1, log_text)
        self.assertIn("verify_client_route_update", log_text)
        self.assertIn("bridge-proof-domain-bypass", log_text)
        self.assertIn("chain_id", log_text)
        self.assertIn("client_id", log_text)
        self.assertIn("route_id", log_text)
        self.assertIn("pallet_id", log_text)
        self.assertIn("verifier_namespace", log_text)

    def test_negative_fixture_is_silent_when_route_fields_are_bound(self) -> None:
        hits, log_text = _run_fixture(NEGATIVE)
        self.assertEqual(hits, 0, log_text)


if __name__ == "__main__":
    unittest.main()
