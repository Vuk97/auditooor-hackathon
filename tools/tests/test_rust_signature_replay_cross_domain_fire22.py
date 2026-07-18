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
FIXTURES = REPO_ROOT / "detectors" / "rust_wave1" / "test_fixtures"
DETECTOR_ID = "signature_replay_cross_domain_fire22"
_HIT_RE = re.compile(rf"^=== {DETECTOR_ID}\s+\((\d+) hits\)", re.MULTILINE)


def _run_file(fixture: Path) -> tuple[int, str]:
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
        return (int(match.group(1)) if match else 0, text)
    finally:
        log_path.unlink(missing_ok=True)


class RustSignatureReplayCrossDomainFire22Tests(unittest.TestCase):
    def test_positive_fixture_fires_on_all_confirmed_shapes(self) -> None:
        hits, text = _run_file(
            FIXTURES / "signature_replay_cross_domain_fire22_positive.rs"
        )
        self.assertGreaterEqual(hits, 4)
        self.assertIn("signed digest omits replay binding", text)
        self.assertIn("threshold loop counts reused signature material", text)
        self.assertIn("AA signature-validation fallback skips pre-validation hooks", text)
        self.assertIn("batch claim proof or params are paid without consume-once", text)

    def test_negative_fixture_is_silent(self) -> None:
        hits, _text = _run_file(
            FIXTURES / "signature_replay_cross_domain_fire22_negative.rs"
        )
        self.assertEqual(hits, 0)


if __name__ == "__main__":
    unittest.main()
