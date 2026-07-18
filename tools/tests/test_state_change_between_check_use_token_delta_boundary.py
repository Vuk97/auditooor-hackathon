from __future__ import annotations

import importlib.util
import os
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
PATTERN = "state-change-between-check-and-use-token-delta-boundary"
REFERENCE = ROOT / "reference" / "patterns.dsl" / f"{PATTERN}.yaml"
POSITIVE = ROOT / "patterns" / "fixtures" / f"{PATTERN}_vuln.sol"
CLEAN = ROOT / "patterns" / "fixtures" / f"{PATTERN}_clean.sol"
EC_VULN = ROOT / "patterns" / "fixtures" / "ec-fot-token-in-non-fot-pool_vuln.sol"
EC_CLEAN = ROOT / "patterns" / "fixtures" / "ec-fot-token-in-non-fot-pool_clean.sol"
PAYMASTER_VULN = ROOT / "patterns" / "fixtures" / "erc4337-paymaster-no-sender-validation_vuln.sol"
FEE_CAP_VULN = ROOT / "patterns" / "fixtures" / "fx-v4core-swap-fee-equality-check_vuln.sol"
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
        import yaml  # noqa: F401

        return True
    except Exception:
        return False


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
    hits = 0
    for contract in sl.contracts:
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


class StateChangeBetweenCheckUseTokenDeltaBoundaryTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.compiler = _load_module(PATTERN_COMPILE, "pattern_compile")
        cls.classifier = _load_module(CLASSIFIER_TOOL, "detector_class_map_builder")

    def test_pattern_compiles_under_strict_guards(self) -> None:
        with tempfile.TemporaryDirectory(
            prefix=".pattern_compile_state_change_token_delta_",
            dir=ROOT,
        ) as tmp:
            out_dir = Path(tmp) / "wave17"
            compiled = self.compiler.compile_pattern(
                REFERENCE,
                out_dir,
                strict_yaml_shapes=True,
                strict_unsupported_keys=True,
            )
            self.assertTrue(compiled)
            generated = out_dir / "state_change_between_check_and_use_token_delta_boundary.py"
            self.assertTrue(generated.is_file(), f"missing generated detector: {generated}")
            text = generated.read_text(encoding="utf-8")
            self.assertIn(f'ARGUMENT = "{PATTERN}"', text)

    def test_classifier_maps_to_state_change_between_check_and_use(self) -> None:
        spec = _load_spec()
        self.assertEqual(
            self.classifier.classify_pattern(spec, PATTERN)["attack_class"],
            "state-change-between-check-and-use",
        )

    def test_fixture_pair_models_nominal_amount_after_token_boundary(self) -> None:
        positive = POSITIVE.read_text(encoding="utf-8")
        clean = CLEAN.read_text(encoding="utf-8")

        self.assertIn("function swap(uint256 amount0In, uint256 amount1Out, address to)", positive)
        self.assertIn("amount0In * uint256(reserve1)", positive)
        self.assertIn("token1.transfer(to, amount1Out)", positive)
        self.assertNotIn("amount0In = balance0", positive)

        self.assertIn("uint256 amount0In = balance0", clean)
        self.assertIn("balance0 - (reserve0 - amount0Out)", clean)

    def test_positive_and_ec_miss_fire_clean_controls_stay_silent(self) -> None:
        if not _imports_ok():
            self.skipTest("pyyaml / slither-analyzer not importable")
        spec = _load_spec()
        self.assertEqual(_hits(spec, POSITIVE), 1)
        self.assertEqual(_hits(spec, CLEAN), 0)
        self.assertEqual(_hits(spec, EC_VULN), 1)
        self.assertEqual(_hits(spec, EC_CLEAN), 0)

    def test_adjacent_starting_samples_are_not_falsely_unified(self) -> None:
        if not _imports_ok():
            self.skipTest("pyyaml / slither-analyzer not importable")
        spec = _load_spec()
        self.assertEqual(_hits(spec, PAYMASTER_VULN), 0)
        self.assertEqual(_hits(spec, FEE_CAP_VULN), 0)


if __name__ == "__main__":
    unittest.main()
