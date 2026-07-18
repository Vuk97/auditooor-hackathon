from __future__ import annotations

import re
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


HERE = Path(__file__).resolve().parent
REPO_ROOT = HERE.parent.parent
RUST_DETECT = REPO_ROOT / "tools" / "rust-detect.py"
FIXTURES = REPO_ROOT / "tools" / "tests" / "fixtures" / "rust-detector-runner"
DETECTOR_ID = "state_check_stale_after_external_effect_fire7"
_HIT_RE = re.compile(rf"^=== {DETECTOR_ID}\s+\((\d+) hits\)", re.MULTILINE)


def _run_fixture(fixture: Path) -> tuple[int, str]:
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
            cwd=REPO_ROOT,
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
        return int(match.group(1)) if match else 0, text
    finally:
        log_path.unlink(missing_ok=True)


class RustStateCheckStaleAfterExternalEffectFire7Tests(unittest.TestCase):
    def test_positive_fixture_flags_two_phase_stateful_check(self) -> None:
        hits, log_text = _run_fixture(
            FIXTURES
            / "positive"
            / "state_check_stale_after_external_effect_fire7.rs"
        )
        self.assertGreaterEqual(hits, 1, log_text)
        self.assertIn("parallel check_stateful TOCTOU", log_text)

    def test_guarded_fixture_is_silent(self) -> None:
        hits, log_text = _run_fixture(
            FIXTURES
            / "negative"
            / "state_check_stale_after_external_effect_fire7_guarded.rs"
        )
        self.assertEqual(hits, 0, log_text)


if __name__ == "__main__":
    unittest.main()
