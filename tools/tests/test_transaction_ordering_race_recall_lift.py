"""Recall-lift smoke test for the transaction-ordering-race umbrella DSL.

This lane is capability work only. The test compiles the owned DSL to a
temporary detector through pattern-compile, then evaluates the fixture pair
through the same predicate engine used by compiled detectors. No generated
wave detector is required for this umbrella row.
"""
from __future__ import annotations

import importlib.util
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
TOOL = ROOT / "tools" / "pattern-compile.py"
PATTERN = "transaction-ordering-race-umbrella"
REFERENCE = ROOT / "reference" / "patterns.dsl" / f"{PATTERN}.yaml"
FIXTURE_DIR = ROOT / "detectors" / "fixtures" / "transaction_ordering_race_umbrella"
POSITIVE = FIXTURE_DIR / "positive.sol"
CLEAN = FIXTURE_DIR / "clean.sol"
SMOKE = FIXTURE_DIR / "smoke.json"


def _imports_ok() -> bool:
    try:
        import slither  # noqa: F401
        import yaml  # noqa: F401
        return True
    except Exception:
        return False


def _load_pattern_compile():
    spec = importlib.util.spec_from_file_location("pattern_compile", TOOL)
    mod = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(mod)
    return mod


def _load_spec() -> dict:
    import yaml

    return yaml.safe_load(REFERENCE.read_text(encoding="utf-8"))


def _hits(spec: dict, sol_path: Path) -> int:
    os.environ["AUDITOOOR_FIXTURE_SMOKE_MODE"] = "1"
    if str(ROOT / "detectors") not in sys.path:
        sys.path.insert(0, str(ROOT / "detectors"))
    from _predicate_engine import eval_function_match, eval_preconditions
    from _template_utils import is_leaf_helper, is_vendored_or_test_contract
    from slither import Slither

    sl = Slither(str(sol_path))
    preconditions = spec.get("preconditions") or []
    match = spec.get("match") or []
    hits = 0
    for contract in sl.contracts:
        if is_vendored_or_test_contract(contract):
            continue
        if not eval_preconditions(contract, preconditions):
            continue
        for function in contract.functions_and_modifiers_declared:
            if is_leaf_helper(function):
                continue
            if eval_function_match(function, match):
                hits += 1
    return hits


class TransactionOrderingRaceRecallLiftTest(unittest.TestCase):
    def test_pattern_compile_accepts_umbrella_yaml(self) -> None:
        compiler = _load_pattern_compile()
        with tempfile.TemporaryDirectory(
            prefix=".pattern_compile_transaction_ordering_race_",
            dir=ROOT,
        ) as tmp:
            out_dir = Path(tmp) / "wave17"
            compiled = compiler.compile_pattern(
                REFERENCE,
                out_dir,
                strict_yaml_shapes=True,
                strict_unsupported_keys=True,
            )
            self.assertTrue(compiled)
            generated = out_dir / "transaction_ordering_race_umbrella.py"
            self.assertTrue(generated.is_file(), f"missing generated detector: {generated}")
            detector_text = generated.read_text(encoding="utf-8")
            self.assertIn(f'ARGUMENT = "{PATTERN}"', detector_text)
            self.assertIn("transaction-ordering-race-umbrella: pattern matched", detector_text)

    def test_reference_yaml_points_at_owned_fixture_pair(self) -> None:
        text = REFERENCE.read_text(encoding="utf-8")
        self.assertIn(
            "vuln: detectors/fixtures/transaction_ordering_race_umbrella/positive.sol",
            text,
        )
        self.assertIn(
            "clean: detectors/fixtures/transaction_ordering_race_umbrella/clean.sol",
            text,
        )
        self.assertIn("transaction-ordering-race", text)
        self.assertIn("coverage_claim: detector_fixture_smoke_only", text)
        self.assertIn("submission_posture: NOT_SUBMIT_READY", text)
        self.assertIn("promotion_allowed: false", text)

    def test_fixture_smoke_metadata_matches_expected_lift(self) -> None:
        payload = json.loads(SMOKE.read_text(encoding="utf-8"))
        self.assertEqual(payload["schema"], "auditooor.canonical_detector_fixture_smoke.v1")
        self.assertEqual(payload["pattern"], PATTERN)
        self.assertEqual(payload["status"], "passed_vulnerable_clean_smoke")
        self.assertEqual(payload["positive_hits"], 5)
        self.assertEqual(payload["clean_hits"], 0)
        self.assertFalse(payload["promotion_allowed"])
        self.assertEqual(payload["submission_posture"], "NOT_SUBMIT_READY")

    def test_positive_fixture_fires_across_subfamilies_and_clean_stays_quiet(self) -> None:
        if not _imports_ok():
            self.skipTest("pyyaml / slither-analyzer not importable")
        spec = _load_spec()
        self.assertEqual(_hits(spec, POSITIVE), 5)
        self.assertEqual(_hits(spec, CLEAN), 0)


if __name__ == "__main__":
    unittest.main()
