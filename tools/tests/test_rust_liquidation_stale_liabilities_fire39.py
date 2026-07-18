from __future__ import annotations

import importlib.util
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
DETECTOR_ID = "liquidation_stale_liabilities_fire39"
DETECTOR = REPO_ROOT / "detectors" / "rust_wave1" / f"{DETECTOR_ID}.py"
POSITIVE = FIXTURES / f"{DETECTOR_ID}_positive.rs"
NEGATIVE = FIXTURES / f"{DETECTOR_ID}_negative.rs"

_HIT_RE = re.compile(rf"^=== {DETECTOR_ID}\s+\((\d+) hits\)", re.MULTILINE)


def _load_detector():
    spec = importlib.util.spec_from_file_location(DETECTOR_ID, DETECTOR)
    if spec is None or spec.loader is None:
        raise AssertionError(f"cannot load {DETECTOR}")
    module = importlib.util.module_from_spec(spec)
    sys.path.insert(0, str(DETECTOR.parent))
    try:
        spec.loader.exec_module(module)
    finally:
        try:
            sys.path.remove(str(DETECTOR.parent))
        except ValueError:
            pass
    return module


def _run_fixture(fixture: Path) -> tuple[int, str]:
    with tempfile.NamedTemporaryFile(prefix=".rust_liq_fire39_", suffix=".log") as tmp:
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
            timeout=60,
        )
        if proc.returncode != 0:
            raise AssertionError(proc.stdout)
        log_text = Path(tmp.name).read_text(encoding="utf-8", errors="ignore")

    match = _HIT_RE.search(log_text)
    return int(match.group(1)) if match else 0, log_text


class RustLiquidationStaleLiabilitiesFire39Tests(unittest.TestCase):
    def test_detector_and_test_compile(self) -> None:
        py_compile.compile(str(DETECTOR), doraise=True)
        py_compile.compile(str(Path(__file__)), doraise=True)

    def test_positive_fixture_flags_three_semantic_variants(self) -> None:
        text = POSITIVE.read_text(encoding="utf-8")
        self.assertIn("borrow_balance_stored(user)", text)
        self.assertIn("require(required <= collateral)", text)
        self.assertLess(
            text.index("borrower.debt -= pool_available.min(borrower.debt);"),
            text.index("save_borrower(&borrower);"),
        )

        hits, log_text = _run_fixture(POSITIVE)
        self.assertEqual(hits, 3, log_text)
        self.assertIn("stored-liability-without-accrual", log_text)
        self.assertIn("strict-underfunded-bonus-revert", log_text)
        self.assertIn("partial-settlement-zombie-debt", log_text)
        self.assertIn("liquidation stale liabilities", log_text)

    def test_negative_fixture_has_freshness_cap_and_cleanup_guards(self) -> None:
        text = NEGATIVE.read_text(encoding="utf-8")
        self.assertLess(
            text.index("accrue_interest();"),
            text.index("borrow_balance_stored(user)"),
        )
        self.assertIn("required.min(collateral)", text)
        self.assertIn("record_bad_debt", text)
        self.assertLess(
            text.index("borrower.debt = 0;"),
            text.index("save_borrower(&borrower);"),
        )

        hits, log_text = _run_fixture(NEGATIVE)
        self.assertEqual(hits, 0, log_text)

    def test_seed_recall_miss_positive_fixtures_fire(self) -> None:
        for fixture_name, expected_variant in (
            (
                "r94_loop_liquidate_uses_stored_outdated_liabilities_positive.rs",
                "stored-liability-without-accrual",
            ),
            (
                "r94_loop_liquidation_bonus_strict_reverts_when_underfunded_positive.rs",
                "strict-underfunded-bonus-revert",
            ),
            (
                "r94_loop_liquidation_partial_settlement_leaves_zombie_debt_positive.rs",
                "partial-settlement-zombie-debt",
            ),
        ):
            with self.subTest(fixture=fixture_name):
                hits, log_text = _run_fixture(FIXTURES / fixture_name)
                self.assertGreaterEqual(hits, 1, log_text)
                self.assertIn(expected_variant, log_text)

    def test_clean_seed_and_same_syntax_fixtures_stay_silent(self) -> None:
        for fixture_name in (
            "r94_loop_liquidate_uses_stored_outdated_liabilities_negative.rs",
            "r94_loop_liquidation_bonus_strict_reverts_when_underfunded_negative.rs",
            "r94_loop_liquidation_partial_settlement_leaves_zombie_debt_negative.rs",
        ):
            with self.subTest(fixture=fixture_name):
                hits, log_text = _run_fixture(FIXTURES / fixture_name)
                self.assertEqual(hits, 0, log_text)

    def test_detector_declares_candidate_only_provenance(self) -> None:
        module = _load_detector()
        self.assertEqual(
            module.DETECTOR_ID,
            "rust_wave1.liquidation_stale_liabilities_fire39",
        )
        self.assertEqual(module.SUBMISSION_POSTURE, "NOT_SUBMIT_READY")
        self.assertEqual(
            module.VERIFICATION_TIER,
            "tier-3-synthetic-taxonomy-anchored",
        )
        self.assertEqual(module.ATTACK_CLASS, "liquidation-trigger-poison")
        detector_text = DETECTOR.read_text(encoding="utf-8")
        self.assertIn("R40/R76/R80 caveat", detector_text)
        self.assertIn("MCP receipt: .auditooor/memory_context_receipt.json", detector_text)


if __name__ == "__main__":
    unittest.main()
