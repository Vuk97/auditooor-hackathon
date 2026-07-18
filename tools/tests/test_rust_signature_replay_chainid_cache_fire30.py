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
    / "rust_signature_replay_chainid_cache_fire30.py"
)
FIXTURES = REPO_ROOT / "detectors" / "rust_wave1" / "test_fixtures"
DETECTOR_ID = "rust_signature_replay_chainid_cache_fire30"
_HIT_RE = re.compile(rf"^=== {DETECTOR_ID}\s+\((\d+) hits\)", re.MULTILINE)


def _run_fixture(fixture_name: str) -> tuple[int, str]:
    with tempfile.NamedTemporaryFile(prefix=".rust_sig_cache_fire30_", suffix=".log") as tmp:
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
                tmp.name,
            ],
            cwd=REPO_ROOT,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            timeout=120,
            check=False,
        )
        if proc.returncode != 0:
            raise AssertionError(proc.stdout)
        log_text = Path(tmp.name).read_text(encoding="utf-8", errors="ignore")

    match = _HIT_RE.search(log_text)
    return (int(match.group(1)) if match else 0, log_text)


class RustSignatureReplayChainIdCacheFire30Tests(unittest.TestCase):
    def test_detector_compiles(self) -> None:
        py_compile.compile(str(DETECTOR), doraise=True)

    def test_positive_fixture_fires_on_cached_chain_and_channel_replay(self) -> None:
        hits, log_text = _run_fixture(
            "rust_signature_replay_chainid_cache_fire30_positive.rs"
        )
        self.assertGreaterEqual(hits, 2, log_text)
        self.assertIn("domain_separator", log_text)
        self.assertIn("chain_id", log_text)
        self.assertIn("channel_id", log_text)
        self.assertIn("signature-replay-cross-domain", log_text)

    def test_negative_fixture_is_silent_with_live_domain_rechecks(self) -> None:
        hits, log_text = _run_fixture(
            "rust_signature_replay_chainid_cache_fire30_negative.rs"
        )
        self.assertEqual(hits, 0, log_text)


if __name__ == "__main__":
    unittest.main()
