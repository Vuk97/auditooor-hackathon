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
DETECTOR_ID = "signature_domain_or_signer_uniqueness_fire20"
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


class RustSignatureDomainOrSignerUniquenessFire20Tests(unittest.TestCase):
    def test_positive_fixture_fires(self) -> None:
        hits = _run_file(
            FIXTURES / "signature_domain_or_signer_uniqueness_fire20_positive.rs"
        )
        self.assertGreaterEqual(hits, 3)

    def test_negative_fixture_is_silent(self) -> None:
        hits = _run_file(
            FIXTURES / "signature_domain_or_signer_uniqueness_fire20_negative.rs"
        )
        self.assertEqual(hits, 0)

    def test_confirmed_eip712_nested_array_miss_fires(self) -> None:
        hits = _run_file(
            FIXTURES
            / "eip712_nested_array_hashing_incompatible_multichaincompact_uint256_2_positive.rs"
        )
        self.assertGreaterEqual(hits, 1)

    def test_confirmed_lientoken_vault_signature_skip_fires(self) -> None:
        hits = _run_file(
            FIXTURES
            / "lientoken_buyoutlien_skips_vault_signature_validation_positive.rs"
        )
        self.assertGreaterEqual(hits, 1)

    def test_confirmed_multisig_duplicate_signer_miss_fires(self) -> None:
        hits = _run_file(
            FIXTURES / "multisig_accepts_duplicate_signatures_from_same_signer_positive.rs"
        )
        self.assertGreaterEqual(hits, 1)

    def test_confirmed_clean_controls_are_silent(self) -> None:
        clean_controls = [
            "eip712_nested_array_hashing_incompatible_multichaincompact_uint256_2_negative.rs",
            "lientoken_buyoutlien_skips_vault_signature_validation_negative.rs",
            "multisig_accepts_duplicate_signatures_from_same_signer_negative.rs",
        ]
        for name in clean_controls:
            with self.subTest(name=name):
                self.assertEqual(_run_file(FIXTURES / name), 0)


if __name__ == "__main__":
    unittest.main()
