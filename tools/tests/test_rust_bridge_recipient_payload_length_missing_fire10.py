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
DETECTOR = (
    REPO_ROOT
    / "detectors"
    / "rust_wave1"
    / "bridge_recipient_payload_length_missing_fire10.py"
)
FIXTURES = REPO_ROOT / "detectors" / "rust_wave1" / "test_fixtures"
DETECTOR_ID = "bridge_recipient_payload_length_missing_fire10"
POSITIVE = FIXTURES / f"{DETECTOR_ID}_positive.rs"
NEGATIVE = FIXTURES / f"{DETECTOR_ID}_negative.rs"
LEGACY_MISS = (
    FIXTURES / "bridge_recipient_non_20_byte_payload_silently_burns_positive.rs"
)
FIRE9_GENERIC = "missing_recipient_or_sender_validation_fire9"
_HIT_RE_TEMPLATE = r"^=== {detector}\s+\((\d+) hits\)"


def _run_fixture(detector_id: str, fixture: Path) -> tuple[int, str]:
    with tempfile.NamedTemporaryFile(prefix=".rust_fire10_bridge_recipient_", suffix=".log") as tmp:
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

    hit_re = re.compile(
        _HIT_RE_TEMPLATE.format(detector=re.escape(detector_id)),
        re.MULTILINE,
    )
    match = hit_re.search(log_text)
    return (int(match.group(1)) if match else 0, log_text)


class RustBridgeRecipientPayloadLengthMissingFire10Test(unittest.TestCase):
    def test_detector_compiles(self) -> None:
        py_compile.compile(str(DETECTOR), doraise=True)

    def test_positive_fixture_fires_on_payload_decode_before_effect(self) -> None:
        hits, log_text = _run_fixture(DETECTOR_ID, POSITIVE)
        self.assertEqual(hits, 1, log_text)
        self.assertIn("exact 20-byte recipient length", log_text)
        self.assertIn("recipient/application domain binding", log_text)
        self.assertIn("message-consume effect", log_text)

    def test_negative_fixture_is_silent_when_length_and_domain_guard_precede_effect(
        self,
    ) -> None:
        hits, log_text = _run_fixture(DETECTOR_ID, NEGATIVE)
        self.assertEqual(hits, 0, log_text)

    def test_fire9_generic_recipient_detector_does_not_cover_legacy_miss(self) -> None:
        hits, log_text = _run_fixture(FIRE9_GENERIC, LEGACY_MISS)
        self.assertEqual(hits, 0, log_text)


if __name__ == "__main__":
    unittest.main()
