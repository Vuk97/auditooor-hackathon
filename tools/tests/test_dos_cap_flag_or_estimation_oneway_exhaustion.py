from __future__ import annotations

import importlib.util
import os
import sys
import tempfile
import unittest
from pathlib import Path

import yaml


ROOT = Path(__file__).resolve().parents[2]
PATTERN = "dos-cap-flag-or-estimation-oneway-exhaustion"
REFERENCE = ROOT / "reference" / "patterns.dsl" / f"{PATTERN}.yaml"
POSITIVE = ROOT / "patterns" / "fixtures" / f"{PATTERN}_vuln.sol"
CLEAN = ROOT / "patterns" / "fixtures" / f"{PATTERN}_clean.sol"
FLAG_VULN = ROOT / "patterns" / "fixtures" / "boolean-flag-permanent-dos-on-receipt_vuln.sol"
FLAG_CLEAN = ROOT / "patterns" / "fixtures" / "boolean-flag-permanent-dos-on-receipt_clean.sol"
GAS_VULN = ROOT / "patterns" / "fixtures" / "gas-estimation-cross-chain-undercount_vuln.sol"
GAS_CLEAN = ROOT / "patterns" / "fixtures" / "gas-estimation-cross-chain-undercount_clean.sol"
VESTING_VULN = ROOT / "patterns" / "fixtures" / "vesting-raw-balance-releasable-dust-dos_vuln.sol"
EXCESS_ETH_VULN = ROOT / "patterns" / "fixtures" / "deposit-accepts-excess-native-eth_vuln.sol"
FLASHLOAN_POSITIVE = (
    ROOT
    / "detectors"
    / "fixtures"
    / "a_flashloan_will_be_broken_if_the_usdt_fee_is_more_than_zero"
    / "ssi-fix-011_positive.sol"
)
PATTERN_COMPILE = ROOT / "tools" / "pattern-compile.py"
CLASSIFIER_TOOL = ROOT / "tools" / "audit" / "detector-class-map-builder.py"


def _load_module(path: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _imports_ok() -> bool:
    try:
        import slither  # noqa: F401

        return True
    except Exception:
        return False


def _load_spec() -> dict:
    return yaml.safe_load(REFERENCE.read_text(encoding="utf-8"))


def _hits(spec: dict, sol_path: Path) -> int:
    os.environ["AUDITOOOR_FIXTURE_SMOKE_MODE"] = "1"
    os.environ["AUDITOOOR_SLITHER_NOCACHE"] = "1"
    if str(ROOT / "detectors") not in sys.path:
        sys.path.insert(0, str(ROOT / "detectors"))
    from _predicate_engine import eval_function_match, eval_preconditions
    from _template_utils import is_leaf_helper, is_vendored_or_test_contract
    from slither import Slither

    slither = Slither(str(sol_path))
    hits = 0
    for contract in slither.contracts:
        if is_vendored_or_test_contract(contract):
            continue
        if not eval_preconditions(contract, spec.get("preconditions") or []):
            continue
        for function in contract.functions_and_modifiers_declared:
            if is_leaf_helper(function):
                continue
            if eval_function_match(function, spec.get("match") or []):
                hits += 1
    return hits


class DosCapFlagOrEstimationOnewayExhaustionTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.compiler = _load_module(PATTERN_COMPILE, "pattern_compile")
        cls.classifier = _load_module(CLASSIFIER_TOOL, "detector_class_map_builder")

    def test_pattern_compiles_under_strict_guards(self) -> None:
        with tempfile.TemporaryDirectory(prefix=".pattern_compile_dos_cap_", dir=ROOT) as tmp:
            out_dir = Path(tmp) / "wave17"
            compiled = self.compiler.compile_pattern(
                REFERENCE,
                out_dir,
                strict_yaml_shapes=True,
                strict_unsupported_keys=True,
            )
            self.assertTrue(compiled)
            generated = out_dir / "dos_cap_flag_or_estimation_oneway_exhaustion.py"
            self.assertTrue(generated.is_file(), f"missing generated detector: {generated}")
            text = generated.read_text(encoding="utf-8")
            self.assertIn(f'ARGUMENT = "{PATTERN}"', text)

    def test_taxonomy_maps_to_dos_cap_weakening(self) -> None:
        spec = _load_spec()
        self.assertEqual(
            self.classifier.classify_pattern(spec, PATTERN)["attack_class"],
            "dos-cap-weakening",
        )
        self.assertEqual(spec["promotion_allowed"], False)
        self.assertEqual(spec["coverage_claim"], "detector_fixture_smoke_only")
        self.assertEqual(spec["submission_posture"], "NOT_SUBMIT_READY")

    def test_fixture_pair_models_sticky_flag_and_raw_gas_cap(self) -> None:
        positive = POSITIVE.read_text(encoding="utf-8")
        clean = CLEAN.read_text(encoding="utf-8")

        self.assertIn("hasReceived[receiver] = true;", positive)
        self.assertIn("bridge.sendMessage{value: msg.value}(target, data, gasLimit);", positive)
        self.assertNotIn("clearReceipt", positive)
        self.assertNotIn("OVERHEAD_GAS", positive)

        self.assertIn("hasReceived[receiver] = false;", clean)
        self.assertIn("OVERHEAD_GAS", clean)
        self.assertIn("retryMessage", clean)

    def test_positive_and_start_samples_fire_clean_controls_stay_silent(self) -> None:
        if not _imports_ok():
            self.skipTest("slither-analyzer is not importable")

        spec = _load_spec()
        self.assertEqual(_hits(spec, POSITIVE), 2)
        self.assertEqual(_hits(spec, CLEAN), 0)
        self.assertEqual(_hits(spec, FLAG_VULN), 1)
        self.assertEqual(_hits(spec, FLAG_CLEAN), 0)
        self.assertEqual(_hits(spec, GAS_VULN), 2)
        self.assertEqual(_hits(spec, GAS_CLEAN), 0)

    def test_adjacent_broad_dos_shapes_do_not_fire(self) -> None:
        if not _imports_ok():
            self.skipTest("slither-analyzer is not importable")

        spec = _load_spec()
        self.assertEqual(_hits(spec, VESTING_VULN), 0)
        self.assertEqual(_hits(spec, EXCESS_ETH_VULN), 0)
        self.assertEqual(_hits(spec, FLASHLOAN_POSITIVE), 0)


if __name__ == "__main__":
    unittest.main()
