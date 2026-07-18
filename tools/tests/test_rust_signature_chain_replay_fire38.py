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

DETECTOR = "signature_chain_replay_fire38"
DETECTOR_PATH = WAVE1_DIR / f"{DETECTOR}.py"
POSITIVE = FIXTURES / f"{DETECTOR}_positive.rs"
NEGATIVE = FIXTURES / f"{DETECTOR}_negative.rs"
SEED_EXECUTE = (
    FIXTURES / "r94_loop_bridge_execute_calldata_missing_chainid_replay_positive.rs"
)
SEED_RETRY = (
    FIXTURES / "r94_loop_bridge_retry_settlement_award_replay_positive.rs"
)
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


class RustSignatureChainReplayFire38Tests(unittest.TestCase):
    def test_detector_and_test_compile(self) -> None:
        py_compile.compile(str(DETECTOR_PATH), doraise=True)
        py_compile.compile(str(Path(__file__)), doraise=True)

    def test_positive_fixture_fires_on_bridge_and_settlement_omissions(self) -> None:
        hits, log_text = _run_fixture(POSITIVE)
        self.assertEqual(hits, 2, log_text)
        self.assertIn("execute_signed_bridge_calldata", log_text)
        self.assertIn("retry_signed_settlement_award", log_text)
        self.assertIn("signature-replay-cross-domain", log_text)
        self.assertIn("chain_id", log_text)
        self.assertIn("endpoint", log_text)
        self.assertIn("nonce_context", log_text)
        self.assertIn("settlement_id", log_text)
        self.assertIn("purpose_domain", log_text)
        self.assertIn("contract_domain", log_text)

    def test_negative_fixture_is_silent_when_scope_is_signed(self) -> None:
        hits, log_text = _run_fixture(NEGATIVE)
        self.assertEqual(hits, 0, log_text)

    def test_seed_shapes_are_not_counted_without_signature_verification(self) -> None:
        execute_hits, execute_log = _run_fixture(SEED_EXECUTE)
        retry_hits, retry_log = _run_fixture(SEED_RETRY)
        self.assertEqual(execute_hits, 0, execute_log)
        self.assertEqual(retry_hits, 0, retry_log)

    def test_generic_signed_payload_without_bridge_or_settlement_scope_is_silent(self) -> None:
        with tempfile.NamedTemporaryFile("w", suffix=".rs", delete=False) as tmp:
            path = Path(tmp.name)
            tmp.write(
                "pub fn verify_invoice(amount: u128, signature: &[u8]) -> bool {\n"
                "    let digest = sha256(&amount.to_be_bytes());\n"
                "    verify_signature(&digest, signature)\n"
                "}\n"
                "fn sha256(_bytes: &[u8]) -> [u8; 32] { [0u8; 32] }\n"
                "fn verify_signature(_digest: &[u8; 32], _signature: &[u8]) -> bool { true }\n"
            )
        try:
            hits, log_text = _run_fixture(path)
            self.assertEqual(hits, 0, log_text)
        finally:
            path.unlink(missing_ok=True)


if __name__ == "__main__":
    unittest.main()
