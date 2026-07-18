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
WAVE1_DIR = REPO_ROOT / "detectors" / "rust_wave1"
FIXTURES = WAVE1_DIR / "test_fixtures"

DETECTOR = "admin_auth_mutation_guard_fire17"
DETECTOR_ID = f"rust_wave1.{DETECTOR}"
POSITIVE = f"{DETECTOR}_positive.rs"
NEGATIVE = f"{DETECTOR}_negative.rs"
_HIT_RE = re.compile(rf"^=== {re.escape(DETECTOR)}\s+\((\d+) hits\)", re.MULTILINE)


def _run_fixture(fixture_name: str) -> tuple[int, str]:
    with tempfile.NamedTemporaryFile(suffix=".log", delete=False) as tf:
        log_path = Path(tf.name)
    try:
        proc = subprocess.run(
            [
                sys.executable,
                str(RUST_DETECT),
                str(FIXTURES),
                "--only",
                DETECTOR,
                "--file",
                str(FIXTURES / fixture_name),
                "--log",
                str(log_path),
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=False,
            timeout=30,
        )
        if proc.returncode != 0:
            raise AssertionError(proc.stderr or proc.stdout)
        text = log_path.read_text(encoding="utf-8", errors="ignore")
        match = _HIT_RE.search(text)
        return (int(match.group(1)) if match else 0), text
    finally:
        log_path.unlink(missing_ok=True)


def _load_detector():
    script = WAVE1_DIR / f"{DETECTOR}.py"
    spec = importlib.util.spec_from_file_location(DETECTOR, script)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)  # type: ignore[union-attr]
    return module


class RustAdminAuthMutationGuardFire17Tests(unittest.TestCase):
    def test_positive_fixture_fires_on_auth_mutation_and_replay_paths(self) -> None:
        hits, log_text = _run_fixture(POSITIVE)
        self.assertEqual(hits, 3, log_text)
        self.assertIn("set_config", log_text)
        self.assertIn("env.storage", log_text)
        self.assertIn("_receive_message", log_text)
        self.assertIn("execute_admin_action", log_text)
        self.assertIn("retry_failed_message", log_text)

    def test_negative_fixture_is_silent_when_auth_precedes_effect(self) -> None:
        hits, log_text = _run_fixture(NEGATIVE)
        self.assertEqual(hits, 0, log_text)

    def test_scan_file_metadata_marks_admin_bypass_detector(self) -> None:
        module = _load_detector()
        hits = module.scan_file(str(FIXTURES / POSITIVE))
        self.assertEqual(len(hits), 3, hits)
        self.assertTrue(all(hit["detector_id"] == DETECTOR_ID for hit in hits))
        self.assertEqual(
            {hit["fn_name"] for hit in hits},
            {"set_config", "_receive_message", "retry_failed_message"},
        )
        self.assertEqual({hit["severity"] for hit in hits}, {"high"})
        self.assertEqual(
            {hit["effect_kind"] for hit in hits},
            {"soroban-storage", "cross-domain-effect"},
        )


if __name__ == "__main__":
    unittest.main()
