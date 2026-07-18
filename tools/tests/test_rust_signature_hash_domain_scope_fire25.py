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
WAVE1_DIR = REPO_ROOT / "detectors" / "rust_wave1"
FIXTURES = WAVE1_DIR / "test_fixtures"

DETECTOR = "signature_hash_domain_scope_fire25"
DETECTOR_PATH = WAVE1_DIR / f"{DETECTOR}.py"
POSITIVE = FIXTURES / f"{DETECTOR}_positive.rs"
NEGATIVE = FIXTURES / f"{DETECTOR}_negative.rs"
ATTACK_CLASS = "signature-hash-domain-scope-gap"
_HIT_RE = re.compile(rf"^=== {re.escape(DETECTOR)}\s+\((\d+) hits\)", re.MULTILINE)


def _run_fixture(fixture: Path) -> tuple[int, str]:
    with tempfile.NamedTemporaryFile(suffix=".log", delete=False) as tmp:
        log_path = Path(tmp.name)
    try:
        proc = subprocess.run(
            [
                sys.executable,
                str(RUST_DETECT),
                str(FIXTURES),
                "--only",
                DETECTOR,
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
            timeout=60,
        )
        if proc.returncode != 0:
            raise AssertionError(proc.stderr or proc.stdout)
        log_text = log_path.read_text(encoding="utf-8", errors="ignore")
        match = _HIT_RE.search(log_text)
        return (int(match.group(1)) if match else 0), log_text
    finally:
        log_path.unlink(missing_ok=True)


class RustSignatureHashDomainScopeFire25Tests(unittest.TestCase):
    def test_detector_and_test_compile(self) -> None:
        py_compile.compile(str(DETECTOR_PATH), doraise=True)
        py_compile.compile(str(Path(__file__)), doraise=True)

    def test_positive_fixture_fires_when_digest_omits_scope_fields(self) -> None:
        hits, log_text = _run_fixture(POSITIVE)
        self.assertEqual(hits, 1, log_text)
        self.assertIn(ATTACK_CLASS, log_text)
        self.assertIn("chain_or_network", log_text)
        self.assertIn("program_or_module", log_text)
        self.assertIn("entrypoint", log_text)
        self.assertIn("nonce", log_text)
        self.assertIn("account_owner", log_text)
        self.assertIn("resource_domain", log_text)

    def test_negative_fixture_is_silent_when_scope_fields_are_bound(self) -> None:
        hits, log_text = _run_fixture(NEGATIVE)
        self.assertEqual(hits, 0, log_text)


if __name__ == "__main__":
    unittest.main()
