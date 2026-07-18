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
    / "signature_constraint_or_fiat_shamir_forgery_fire18.py"
)
FIXTURES = REPO_ROOT / "detectors" / "rust_wave1" / "test_fixtures"
DETECTOR_ID = "signature_constraint_or_fiat_shamir_forgery_fire18"
POSITIVE = FIXTURES / f"{DETECTOR_ID}_positive.rs"
NEGATIVE = FIXTURES / f"{DETECTOR_ID}_negative.rs"
ANCHOR_MISS = FIXTURES / "anchor_account_constraint_missing_positive.rs"
WEAK_CONSTRAINT_MISS = FIXTURES / "r94_loop_constraint_inequality_when_equality_positive.rs"
FS_MISS = FIXTURES / "r94_loop_fiat_shamir_missing_observe_positive.rs"
_HIT_RE = re.compile(rf"^=== {DETECTOR_ID}\s+\((\d+) hits\)", re.MULTILINE)


def _run_fixture(fixture: Path) -> tuple[int, str]:
    with tempfile.NamedTemporaryFile(prefix=".rust_fire18_sig_forgery_", suffix=".log") as tmp:
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
        text = Path(tmp.name).read_text(encoding="utf-8", errors="ignore")
    match = _HIT_RE.search(text)
    return (int(match.group(1)) if match else 0, text)


class RustSignatureConstraintOrFiatShamirForgeryFire18Test(unittest.TestCase):
    def test_detector_compiles(self) -> None:
        py_compile.compile(str(DETECTOR), doraise=True)

    def test_positive_fixture_fires_on_missing_bindings(self) -> None:
        hits, log_text = _run_fixture(POSITIVE)
        self.assertGreaterEqual(hits, 4, log_text)
        self.assertIn("account identity is caller supplied", log_text)
        self.assertIn("weak inequality", log_text)
        self.assertIn("Fiat-Shamir challenge", log_text)
        self.assertIn("never binds it to the expected signer", log_text)

    def test_negative_fixture_is_silent(self) -> None:
        hits, log_text = _run_fixture(NEGATIVE)
        self.assertEqual(hits, 0, log_text)

    def test_confirmed_anchor_account_constraint_miss_now_fires(self) -> None:
        hits, log_text = _run_fixture(ANCHOR_MISS)
        self.assertGreaterEqual(hits, 1, log_text)

    def test_confirmed_weak_constraint_miss_now_fires(self) -> None:
        hits, log_text = _run_fixture(WEAK_CONSTRAINT_MISS)
        self.assertGreaterEqual(hits, 1, log_text)

    def test_confirmed_fiat_shamir_miss_now_fires(self) -> None:
        hits, log_text = _run_fixture(FS_MISS)
        self.assertGreaterEqual(hits, 1, log_text)

    def test_signature_words_without_missing_binding_are_silent(self) -> None:
        with tempfile.NamedTemporaryFile("w", suffix=".rs", delete=False) as tmp:
            path = Path(tmp.name)
            tmp.write(
                "pub type Pubkey = [u8; 32];\n"
                "pub fn document_signature_words(signature: &[u8], signer: Pubkey) -> bool {\n"
                "    let _ = signature.len();\n"
                "    signer != [0u8; 32]\n"
                "}\n"
            )
        try:
            hits, log_text = _run_fixture(path)
            self.assertEqual(hits, 0, log_text)
        finally:
            path.unlink(missing_ok=True)


if __name__ == "__main__":
    unittest.main()
