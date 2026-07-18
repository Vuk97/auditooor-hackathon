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
DETECTOR = REPO_ROOT / "detectors" / "rust_wave1" / "initializer_first_caller_config_takeover.py"
FIXTURES = REPO_ROOT / "detectors" / "rust_wave1" / "test_fixtures"
DETECTOR_ID = "initializer_first_caller_config_takeover"


def _run_fixture(fixture_name: str) -> tuple[int, str]:
    hit_re = re.compile(rf"^=== {DETECTOR_ID}\s+\((\d+) hits\)", re.MULTILINE)
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
                str(FIXTURES / fixture_name),
                "--log",
                str(log_path),
            ],
            cwd=REPO_ROOT,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=False,
        )
        if proc.returncode != 0:
            raise AssertionError(proc.stderr or proc.stdout)
        text = log_path.read_text(encoding="utf-8", errors="ignore")
        match = hit_re.search(text)
        return (int(match.group(1)) if match else 0), text
    finally:
        log_path.unlink(missing_ok=True)


class InitializerFirstCallerConfigTakeoverTests(unittest.TestCase):
    def test_detector_and_fixture_shape(self) -> None:
        py_compile.compile(str(DETECTOR), doraise=True)

        detector_text = DETECTOR.read_text(encoding="utf-8")
        positive_text = (FIXTURES / "initializer_first_caller_config_takeover_positive.rs").read_text(
            encoding="utf-8"
        )
        negative_text = (FIXTURES / "initializer_first_caller_config_takeover_negative.rs").read_text(
            encoding="utf-8"
        )

        self.assertIn("Class: initializer-front-run", detector_text)
        self.assertIn("_AUTH_GUARD_RE", detector_text)
        self.assertIn("_SAME_CHAIN_GUARD_RE", detector_text)
        self.assertIn("_CONFIG_WRITE_RE", detector_text)

        self.assertIn("pub fn setup_route", positive_text)
        self.assertIn("self.routes.insert", positive_text)
        self.assertIn("self.gateway_for.insert", positive_text)
        self.assertNotIn("require_auth", positive_text)
        self.assertNotIn("SameChain", positive_text)

        self.assertIn("admin.require_auth();", negative_text)
        self.assertIn("source_chain_id == destination_chain_id", negative_text)
        self.assertIn("return Err(RouteError::SameChain);", negative_text)

    def test_positive_fixture_fires(self) -> None:
        hits, output = _run_fixture("initializer_first_caller_config_takeover_positive.rs")
        self.assertGreaterEqual(hits, 1, output)
        self.assertIn("setup_route", output)

    def test_negative_fixture_is_silent(self) -> None:
        hits, output = _run_fixture("initializer_first_caller_config_takeover_negative.rs")
        self.assertEqual(hits, 0, output)


if __name__ == "__main__":
    unittest.main()
