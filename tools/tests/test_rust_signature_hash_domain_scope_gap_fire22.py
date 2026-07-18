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

DETECTOR = "signature_hash_domain_scope_gap_fire22"
DETECTOR_PATH = WAVE1_DIR / f"{DETECTOR}.py"
POSITIVE = FIXTURES / f"{DETECTOR}_positive.rs"
NEGATIVE = FIXTURES / f"{DETECTOR}_negative.rs"
CONFIRMED_POSITIVE = FIXTURES / "zebra_signature_hash_domain_scope_gap_positive.rs"
CONFIRMED_NEGATIVE = FIXTURES / "zebra_signature_hash_domain_scope_gap_negative.rs"
CLASS_MAP = REPO_ROOT / "reference" / "detector_class_map_complete.yaml"
ROUTE_MAP = REPO_ROOT / "reference" / "detector_to_attack_classes_map.yaml"

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


class RustSignatureHashDomainScopeGapFire22Tests(unittest.TestCase):
    def test_detector_and_test_compile(self) -> None:
        py_compile.compile(str(DETECTOR_PATH), doraise=True)
        py_compile.compile(str(Path(__file__)), doraise=True)

    def test_positive_fixture_fires_on_visible_scope_omission(self) -> None:
        hits, log_text = _run_fixture(POSITIVE)
        self.assertEqual(hits, 1, log_text)
        self.assertIn("signature digest omits visible replay scope fields", log_text)
        self.assertIn("network", log_text)
        self.assertIn("branch", log_text)
        self.assertIn("entrypoint", log_text)
        self.assertIn("transparent_scope", log_text)
        self.assertIn("shielded_scope", log_text)
        self.assertIn("transaction_context", log_text)
        self.assertIn(ATTACK_CLASS, log_text)

    def test_negative_fixture_is_silent_when_scope_fields_are_bound(self) -> None:
        hits, log_text = _run_fixture(NEGATIVE)
        self.assertEqual(hits, 0, log_text)

    def test_confirmed_fire21_zebra_seed_fires(self) -> None:
        hits, log_text = _run_fixture(CONFIRMED_POSITIVE)
        self.assertGreaterEqual(hits, 1, log_text)
        self.assertIn("zebra consensus sighash path", log_text)

    def test_confirmed_zebra_negative_stays_silent(self) -> None:
        hits, log_text = _run_fixture(CONFIRMED_NEGATIVE)
        self.assertEqual(hits, 0, log_text)

    def test_generic_hash_with_scope_names_but_no_signature_context_is_silent(self) -> None:
        with tempfile.NamedTemporaryFile("w", suffix=".rs", delete=False) as tmp:
            path = Path(tmp.name)
            tmp.write(
                "pub fn hash_invoice(network_id: u32, branch_id: u32, amount: u64) -> [u8; 32] {\n"
                "    let mut bytes = Vec::new();\n"
                "    bytes.extend_from_slice(&amount.to_le_bytes());\n"
                "    hash(&bytes)\n"
                "}\n"
                "pub fn hash(_bytes: &[u8]) -> [u8; 32] { [0u8; 32] }\n"
            )
        try:
            hits, log_text = _run_fixture(path)
            self.assertEqual(hits, 0, log_text)
        finally:
            path.unlink(missing_ok=True)

    def test_class_maps_route_detector_to_same_class(self) -> None:
        complete = CLASS_MAP.read_text(encoding="utf-8")
        route = ROUTE_MAP.read_text(encoding="utf-8")
        self.assertIn(f"rust_wave1.{DETECTOR}:", complete)
        self.assertIn(f"{DETECTOR}:", complete)
        self.assertIn(f"attack_class: {ATTACK_CLASS}", complete)
        self.assertIn(f"rust_wave1.{DETECTOR}:", route)
        self.assertIn(f"{DETECTOR}:", route)
        self.assertIn(f"- {ATTACK_CLASS}", route)


if __name__ == "__main__":
    unittest.main()
