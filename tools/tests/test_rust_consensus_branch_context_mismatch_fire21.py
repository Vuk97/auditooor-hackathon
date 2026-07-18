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
FIXTURES = REPO_ROOT / "detectors" / "rust_wave1" / "test_fixtures"
DETECTOR = "consensus_branch_context_mismatch_fire21"
DETECTOR_PATH = REPO_ROOT / "detectors" / "rust_wave1" / f"{DETECTOR}.py"
POSITIVE = FIXTURES / f"{DETECTOR}_positive.rs"
NEGATIVE = FIXTURES / f"{DETECTOR}_negative.rs"
CLASS_MAP = REPO_ROOT / "reference" / "detector_class_map_complete.yaml"
ROUTE_MAP = REPO_ROOT / "reference" / "detector_to_attack_classes_map.yaml"

SEED_POSITIVE = FIXTURES / "zebra_network_upgrade_height_gate_gap_positive.rs"
SEED_NEGATIVE = FIXTURES / "zebra_network_upgrade_height_gate_gap_negative.rs"

_HIT_RE = re.compile(rf"^=== {DETECTOR}\s+\((\d+) hits\)", re.MULTILINE)


def _run_fixture(fixture: Path) -> tuple[int, str]:
    with tempfile.NamedTemporaryFile(
        prefix=".rust_fire21_consensus_branch_",
        suffix=".log",
    ) as tmp:
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

    match = _HIT_RE.search(log_text)
    return int(match.group(1)) if match else 0, log_text


class RustConsensusBranchContextMismatchFire21Test(unittest.TestCase):
    def test_detector_and_test_compile(self) -> None:
        py_compile.compile(str(DETECTOR_PATH), doraise=True)
        py_compile.compile(str(Path(__file__)), doraise=True)

    def test_positive_fixture_fires_on_local_and_default_branch_context(self) -> None:
        text = POSITIVE.read_text(encoding="utf-8")
        self.assertIn("BranchId::current(&self.network, self.tip_height)", text)
        self.assertIn("tx.network_upgrade().unwrap_or(NetworkUpgrade::Nu5)", text)

        hits, log_text = _run_fixture(POSITIVE)
        self.assertEqual(hits, 2, log_text)
        self.assertIn("local height or network context", log_text)
        self.assertIn("defaults a missing object branch", log_text)
        self.assertIn("consensus-branch-context-mismatch", log_text)

    def test_negative_fixture_is_silent_when_branch_uses_object_context(self) -> None:
        text = NEGATIVE.read_text(encoding="utf-8")
        self.assertIn("BranchId::current(&tx.network, tx.height)", text)
        self.assertIn("let expected_upgrade", text)

        hits, log_text = _run_fixture(NEGATIVE)
        self.assertEqual(hits, 0, log_text)

    def test_confirmed_fire20_miss_is_recalled(self) -> None:
        hits, log_text = _run_fixture(SEED_POSITIVE)
        self.assertGreaterEqual(hits, 1, log_text)
        self.assertIn("consensus branch context mismatch", log_text)

    def test_confirmed_fire20_clean_control_stays_silent(self) -> None:
        hits, log_text = _run_fixture(SEED_NEGATIVE)
        self.assertEqual(hits, 0, log_text)

    def test_class_maps_route_detector_to_consensus_branch_context_mismatch(self) -> None:
        complete = CLASS_MAP.read_text(encoding="utf-8")
        route = ROUTE_MAP.read_text(encoding="utf-8")
        self.assertIn(f"rust_wave1.{DETECTOR}:", complete)
        self.assertIn(f"{DETECTOR}:", complete)
        self.assertIn("attack_class: consensus-branch-context-mismatch", complete)
        self.assertIn(f"rust_wave1.{DETECTOR}:", route)
        self.assertIn(f"{DETECTOR}:", route)
        self.assertIn("- consensus-branch-context-mismatch", route)


if __name__ == "__main__":
    unittest.main()
