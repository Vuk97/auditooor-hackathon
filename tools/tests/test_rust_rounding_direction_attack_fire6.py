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
DETECTOR_ID = "rounding_direction_attack_fire6"
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


class RustRoundingDirectionAttackFire6Tests(unittest.TestCase):
    def test_positive_fixture_flags_fee_and_withdrawal_flooring(self) -> None:
        hits, log_text = _run_fixture(
            FIXTURES / "positive" / "rounding_direction_attack_fire6.rs"
        )
        self.assertGreaterEqual(hits, 2, log_text)
        self.assertIn("Solodit #5806", log_text)
        self.assertIn("floor-style financial division", log_text)

    def test_guarded_fixture_is_silent_on_round_up_and_mul_before_div(self) -> None:
        hits, log_text = _run_fixture(
            FIXTURES / "negative" / "rounding_direction_attack_fire6_guarded.rs"
        )
        self.assertEqual(hits, 0, log_text)


if __name__ == "__main__":
    unittest.main()
