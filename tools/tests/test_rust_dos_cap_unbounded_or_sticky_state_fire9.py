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
DETECTOR_ID = "dos_cap_unbounded_or_sticky_state_fire9"
FIRE7_CALLBACK = "callback_before_state_finalization_fire7"
FIRE7_STALE = "state_check_stale_after_external_effect_fire7"
_HIT_RE_TEMPLATE = r"^=== {detector}\s+\((\d+) hits\)"


def _run_fixture(detector_id: str, fixture: Path) -> tuple[int, str]:
    with tempfile.NamedTemporaryFile(suffix=".log", delete=False) as tf:
        log_path = Path(tf.name)
    try:
        proc = subprocess.run(
            [
                sys.executable,
                str(RUST_DETECT),
                str(FIXTURES),
                "--only",
                detector_id,
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
        hit_re = re.compile(
            _HIT_RE_TEMPLATE.format(detector=re.escape(detector_id)),
            re.MULTILINE,
        )
        match = hit_re.search(text)
        return (int(match.group(1)) if match else 0, text)
    finally:
        log_path.unlink(missing_ok=True)


class RustDosCapUnboundedOrStickyStateFire9Tests(unittest.TestCase):
    def test_positive_fixture_fires_on_global_pending_slot_exhaustion(self) -> None:
        hits, log_text = _run_fixture(
            DETECTOR_ID,
            FIXTURES / f"{DETECTOR_ID}_positive.rs",
        )
        self.assertEqual(hits, 1, log_text)
        self.assertIn("global pending state `pending_by_user`", log_text)
        self.assertIn("collection length or cap gate", log_text)
        self.assertIn("dos-cap-weakening", log_text)

    def test_negative_fixture_is_silent_when_intake_is_bounded(self) -> None:
        hits, log_text = _run_fixture(
            DETECTOR_ID,
            FIXTURES / f"{DETECTOR_ID}_negative.rs",
        )
        self.assertEqual(hits, 0, log_text)

    def test_positive_fixture_is_not_fire7_callback_or_stale_state_logic(self) -> None:
        fixture = FIXTURES / f"{DETECTOR_ID}_positive.rs"
        for detector_id in (FIRE7_CALLBACK, FIRE7_STALE):
            hits, log_text = _run_fixture(detector_id, fixture)
            self.assertEqual(hits, 0, log_text)


if __name__ == "__main__":
    unittest.main()
