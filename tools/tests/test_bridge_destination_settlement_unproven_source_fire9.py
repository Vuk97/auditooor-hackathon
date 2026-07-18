from __future__ import annotations

import importlib.util
import os
import sys
import tempfile
import unittest
from pathlib import Path

import yaml


ROOT = Path(__file__).resolve().parents[2]
PATTERN = "bridge-destination-settlement-unproven-source-fire9"
REFERENCE = ROOT / "reference" / "patterns.dsl" / f"{PATTERN}.yaml"
POSITIVE = ROOT / "detectors" / "test_fixtures" / "positive" / f"{PATTERN}.sol"
NEGATIVE = ROOT / "detectors" / "test_fixtures" / "negative" / f"{PATTERN}.sol"
PATTERN_COMPILE = ROOT / "tools" / "pattern-compile.py"
CLASSIFIER_TOOL = ROOT / "tools" / "audit" / "detector-class-map-builder.py"
BACKTEST_TOOL = ROOT / "tools" / "audit" / "detector-catch-rate-backtest.py"


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
    detectors_dir = str(ROOT / "detectors")
    if detectors_dir not in sys.path:
        sys.path.insert(0, detectors_dir)

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


class BridgeDestinationSettlementUnprovenSourceFire9Test(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.compiler = _load_module(PATTERN_COMPILE, "pattern_compile_fire9")
        cls.classifier = _load_module(CLASSIFIER_TOOL, "detector_class_map_builder_fire9")
        cls.backtest = _load_module(BACKTEST_TOOL, "detector_catch_rate_backtest_fire9")

    def test_pattern_compiles_under_strict_guards(self) -> None:
        with tempfile.TemporaryDirectory(
            prefix=".pattern_compile_bridge_destination_source_fire9_",
            dir=ROOT,
        ) as tmp:
            out_dir = Path(tmp) / "wave99"
            compiled = self.compiler.compile_pattern(
                REFERENCE,
                out_dir,
                strict_yaml_shapes=True,
                strict_unsupported_keys=True,
            )
            self.assertTrue(compiled)
            generated = out_dir / "bridge_destination_settlement_unproven_source_fire9.py"
            self.assertTrue(generated.is_file(), f"missing generated detector: {generated}")
            self.assertIn(f'ARGUMENT = "{PATTERN}"', generated.read_text(encoding="utf-8"))

    def test_taxonomy_maps_to_bridge_proof_domain_bypass(self) -> None:
        spec = _load_spec()
        self.assertEqual(
            self.classifier.classify_pattern(spec, PATTERN)["attack_class"],
            "bridge-proof-domain-bypass",
        )
        self.assertEqual(
            self.backtest.derive_attack_class(PATTERN, spec.get("tags")),
            "bridge-proof-domain-bypass",
        )

    def test_fixture_pair_models_unproven_and_proven_source_commitment(self) -> None:
        positive = POSITIVE.read_text(encoding="utf-8")
        negative = NEGATIVE.read_text(encoding="utf-8")

        self.assertIn("function settleFromSource(", positive)
        self.assertIn("require(acceptedRoots[acceptedRoot]", positive)
        self.assertIn("settledCommitments[sourceCommitment] = true;", positive)
        self.assertIn("token.transfer(recipient, amount)", positive)
        self.assertNotIn("MerkleProof.verify", positive)

        self.assertIn("function settleFromSource(", negative)
        self.assertIn("require(acceptedRoots[acceptedRoot]", negative)
        self.assertIn("MerkleProof.verify(merkleProof, acceptedRoot, sourceCommitment)", negative)
        self.assertIn("settledCommitments[sourceCommitment] = true;", negative)

    def test_positive_fixture_fires_and_negative_control_stays_silent(self) -> None:
        if not _imports_ok():
            self.skipTest("slither-analyzer is not importable")

        spec = _load_spec()
        self.assertEqual(_hits(spec, POSITIVE), 1)
        self.assertEqual(_hits(spec, NEGATIVE), 0)


if __name__ == "__main__":
    unittest.main()
