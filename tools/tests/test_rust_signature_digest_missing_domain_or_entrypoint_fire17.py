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
DETECTOR_ID = "signature_digest_missing_domain_or_entrypoint_fire17"
_HIT_RE = re.compile(rf"^=== {DETECTOR_ID}\s+\((\d+) hits\)", re.MULTILINE)


def _run_file(fixture: Path) -> int:
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
        return int(match.group(1)) if match else 0
    finally:
        log_path.unlink(missing_ok=True)


class RustSignatureDigestMissingDomainOrEntrypointFire17Tests(unittest.TestCase):
    def test_positive_fixture_fires(self) -> None:
        hits = _run_file(
            FIXTURES / "signature_digest_missing_domain_or_entrypoint_fire17_positive.rs"
        )
        self.assertGreaterEqual(hits, 1)

    def test_clean_fixture_is_silent(self) -> None:
        hits = _run_file(
            FIXTURES / "signature_digest_missing_domain_or_entrypoint_fire17_negative.rs"
        )
        self.assertEqual(hits, 0)

    def test_confirmed_entrypoint_userop_miss_fires(self) -> None:
        hits = _run_file(FIXTURES / "entrypoint_not_in_userophash_enables_replay_positive.rs")
        self.assertGreaterEqual(hits, 1)

    def test_confirmed_cached_eip712_domain_miss_fires(self) -> None:
        hits = _run_file(
            FIXTURES / "eip712_domain_separator_stored_as_immutable_fork_unsafe_positive.rs"
        )
        self.assertGreaterEqual(hits, 1)

    def test_generic_hash_without_replay_context_is_silent(self) -> None:
        with tempfile.NamedTemporaryFile("w", suffix=".rs", delete=False) as tf:
            path = Path(tf.name)
            tf.write(
                "pub fn hash_invoice(amount: u64, chain_id: u64) -> [u8; 32] {\n"
                "    let mut bytes = Vec::new();\n"
                "    bytes.extend_from_slice(&amount.to_be_bytes());\n"
                "    keccak256(&bytes)\n"
                "}\n"
                "fn keccak256(_bytes: &[u8]) -> [u8; 32] { [0u8; 32] }\n"
            )
        try:
            self.assertEqual(_run_file(path), 0)
        finally:
            path.unlink(missing_ok=True)


if __name__ == "__main__":
    unittest.main()
