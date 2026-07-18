"""Regression coverage for Revert StableSwap Hooks capability seeds.

These detectors are hand-written cross-file Slither seeds, so keep a hermetic
shape test alongside the Slither fixture smoke. The Revert workspace is read
only here; assertions operate on source text and detector regexes.
"""

from __future__ import annotations

import importlib.util
import re
import sys
import tempfile
import types
import unittest
from pathlib import Path

import yaml


REPO = Path(__file__).resolve().parents[2]

STABLE_FEE = "stable-v4-fee-sentinel-domain-mismatch"
AMP_ZERO = "stableswap-amp-zero-config-liveness"
MISSING_RECIPIENT_CONFIG = "missing-recipient-stableswap-config-domain-validation"


def _write_minimal_stableswap_workspace(root: Path) -> Path:
    files = {
        "src/factories/StableSwapHooksFactory.sol": "contract StableSwapHooksFactory { function create() external {} }\n",
        "src/interfaces/IStableSwapHooks.sol": "interface IStableSwapHooks { function swap() external; }\n",
        "src/Amp.sol": """
contract Amp {
    uint256 constant MAX_AMP = 1_000_000;
    constructor(uint256 _baseAmp) {
        if (_baseAmp >= MAX_AMP) revert();
    }
    function startAmpRamp(uint256 scaledNextAmp) external {
        uint256 currentAmp = getCurrentAmp();
        if (scaledNextAmp > currentAmp * MAX_AMP_MULTIPLIER) revert();
    }
    function getCurrentAmp() public pure returns (uint256) { return 0; }
}
""",
        "src/Base.sol": """
contract Base {
    struct PoolKey { uint24 fee; }
    function init(uint256 lpFee) external {
        PoolKey memory key = PoolKey({fee: toUint24(lpFee)});
    }
    function toUint24(uint256 value) internal pure returns (uint24) { return uint24(value); }
}
""",
        "src/Fees.sol": """
contract Fees {
    uint256 constant FEE_PRECISION = 1e6;
    function getFee(uint256 amount, uint256 lpFeePercentage) external pure returns (uint256) {
        return amount * lpFeePercentage / FEE_PRECISION;
    }
}
""",
        "src/Swap.sol": "contract Swap { function swap() external {} }\n",
        "src/libraries/StableSwapMath.sol": """
library StableSwapMath {
    function getInvariant(uint256 amplification) internal pure returns (uint256) {
        uint256 ampTimesCoins = amplification;
        return AMP_PRECISION / ampTimesCoins;
    }
}
""",
    }
    for rel, text in files.items():
        path = root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
    return root


def _install_slither_stub() -> None:
    if "slither.detectors.abstract_detector" in sys.modules:
        return

    slither_mod = types.ModuleType("slither")
    detectors_mod = types.ModuleType("slither.detectors")
    abstract_mod = types.ModuleType("slither.detectors.abstract_detector")

    class AbstractDetector:  # pragma: no cover - import shim only
        pass

    class DetectorClassification:  # pragma: no cover - import shim only
        MEDIUM = "MEDIUM"

    abstract_mod.AbstractDetector = AbstractDetector
    abstract_mod.DetectorClassification = DetectorClassification
    sys.modules.setdefault("slither", slither_mod)
    sys.modules.setdefault("slither.detectors", detectors_mod)
    sys.modules["slither.detectors.abstract_detector"] = abstract_mod


def _load_detector(argument: str):
    _install_slither_stub()
    path = REPO / "detectors" / "wave18" / f"{argument.replace('-', '_')}.py"
    spec = importlib.util.spec_from_file_location(argument.replace("-", "_"), path)
    mod = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(mod)
    return mod


def _pattern(argument: str) -> dict:
    path = REPO / "reference" / "patterns.dsl" / f"{argument}.yaml"
    return yaml.safe_load(path.read_text(encoding="utf-8"))


def _match_regex(spec: dict, key: str) -> str:
    for row in spec["match"]:
        if key in row:
            return row[key]
    raise AssertionError(f"missing predicate {key}")


class StableCapabilityDslRegistryTest(unittest.TestCase):
    def test_handwritten_pattern_dsl_is_parseable_and_points_at_fixture_pairs(self) -> None:
        for argument in (STABLE_FEE, AMP_ZERO):
            with self.subTest(argument=argument):
                spec = _pattern(argument)
                self.assertEqual(spec["pattern"], argument)
                self.assertEqual(spec["status"], "handwritten-detector")
                self.assertEqual(spec["severity"], "MEDIUM")
                self.assertEqual(spec["confidence"], "MEDIUM")
                self.assertIn("fixtures", spec)
                for fixture_path in spec["fixtures"].values():
                    fixture = REPO / fixture_path
                    self.assertTrue(fixture.is_file(), f"missing fixture {fixture}")

    def test_tier_registry_matches_detector_files_and_fixture_stems(self) -> None:
        registry = yaml.safe_load((REPO / "detectors" / "_tier_registry.yaml").read_text(encoding="utf-8"))
        tiers = registry["tiers"]
        for argument in (STABLE_FEE, AMP_ZERO):
            with self.subTest(argument=argument):
                entry = tiers[argument]
                self.assertEqual(entry["tier"], "E")
                self.assertIn("wave18", entry["waves"])
                detector = REPO / "detectors" / "wave18" / f"{argument.replace('-', '_')}.py"
                self.assertTrue(detector.is_file())
                stem = REPO / entry["fixture_pair"]
                self.assertTrue(stem.with_name(stem.name + "_vuln.sol").is_file())
                self.assertTrue(stem.with_name(stem.name + "_clean.sol").is_file())


class MissingRecipientStableSwapConfigDomainValidationTest(unittest.TestCase):
    def test_pattern_is_parseable_and_classifies_as_missing_recipient(self) -> None:
        spec = _pattern(MISSING_RECIPIENT_CONFIG)
        self.assertEqual(spec["pattern"], MISSING_RECIPIENT_CONFIG)
        self.assertIn("missing-recipient-validation", spec["tags"])
        for fixture_path in spec["fixtures"].values():
            self.assertTrue((REPO / fixture_path).is_file(), f"missing fixture {fixture_path}")

        backtest_path = REPO / "tools" / "audit" / "detector-catch-rate-backtest.py"
        bt_spec = importlib.util.spec_from_file_location("detector_catch_rate_backtest", backtest_path)
        backtest = importlib.util.module_from_spec(bt_spec)
        assert bt_spec.loader is not None
        bt_spec.loader.exec_module(backtest)
        self.assertEqual(
            backtest.derive_attack_class(MISSING_RECIPIENT_CONFIG, spec.get("tags")),
            "missing-recipient-validation",
        )

    def test_fixture_pair_exercises_amp_and_fee_domain_guards(self) -> None:
        spec = _pattern(MISSING_RECIPIENT_CONFIG)
        contains_rx = re.compile(_match_regex(spec, "function.body_contains_regex"), re.IGNORECASE)
        guard_rx = re.compile(_match_regex(spec, "function.body_not_contains_regex"), re.IGNORECASE)
        vuln = (REPO / spec["fixtures"]["vuln"]).read_text(encoding="utf-8")
        clean = (REPO / spec["fixtures"]["clean"]).read_text(encoding="utf-8")

        self.assertRegex(vuln, contains_rx)
        self.assertIsNone(guard_rx.search(vuln))
        self.assertRegex(clean, contains_rx)
        self.assertRegex(clean, guard_rx)

    def test_phase_g_revert_sources_have_missing_config_domain_shape(self) -> None:
        amp_path = Path("/Users/wolf/audits/revert-stableswap-hooks/external/stableswap-hooks/src/Amp.sol")
        factory_path = Path(
            "/Users/wolf/audits/revert-stableswap-hooks/external/stableswap-hooks/src/factories/StableSwapHooksFactory.sol"
        )
        if not amp_path.is_file() or not factory_path.is_file():
            self.skipTest("Phase G Revert StableSwap external sources are not present")

        spec = _pattern(MISSING_RECIPIENT_CONFIG)
        contains_rx = re.compile(_match_regex(spec, "function.body_contains_regex"), re.IGNORECASE)
        guard_rx = re.compile(_match_regex(spec, "function.body_not_contains_regex"), re.IGNORECASE)
        amp = amp_path.read_text(encoding="utf-8")
        factory = factory_path.read_text(encoding="utf-8")

        self.assertRegex(amp, contains_rx)
        self.assertIsNone(guard_rx.search(amp))
        self.assertRegex(factory, contains_rx)
        self.assertIsNone(guard_rx.search(factory))


class StableV4FeeSentinelDomainMismatchShapeTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.mod = _load_detector(STABLE_FEE)

    def test_fixture_pair_hits_vulnerable_and_suppresses_clean(self) -> None:
        vuln = (REPO / "patterns" / "fixtures" / f"{STABLE_FEE}_vuln.sol").read_text(encoding="utf-8")
        clean = (REPO / "patterns" / "fixtures" / f"{STABLE_FEE}_clean.sol").read_text(encoding="utf-8")

        self.assertRegex(vuln, self.mod._POOLKEY_FEE_RE)
        self.assertRegex(vuln, self.mod._FEE_ARITH_RE)
        self.assertIsNone(self.mod._SENTINEL_GUARD_RE.search(vuln))

        self.assertRegex(clean, self.mod._POOLKEY_FEE_RE)
        self.assertRegex(clean, self.mod._FEE_ARITH_RE)
        self.assertRegex(clean, self.mod._SENTINEL_GUARD_RE)

    def test_revert_source_has_target_hit_shape(self) -> None:
        with tempfile.TemporaryDirectory(prefix="stableswap_fee_shape_") as td:
            ws = _write_minimal_stableswap_workspace(Path(td))
            base = (ws / "src" / "Base.sol").read_text(encoding="utf-8")
            fees = (ws / "src" / "Fees.sol").read_text(encoding="utf-8")
            combined = base + "\n" + fees

            self.assertRegex(base, self.mod._POOLKEY_FEE_RE)
            self.assertRegex(combined, self.mod._FEE_ARITH_RE)
            self.assertIsNone(self.mod._SENTINEL_GUARD_RE.search(base))


class StableswapAmpZeroConfigLivenessShapeTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.mod = _load_detector(AMP_ZERO)

    def test_fixture_pair_hits_vulnerable_and_suppresses_clean(self) -> None:
        vuln = (REPO / "patterns" / "fixtures" / f"{AMP_ZERO}_vuln.sol").read_text(encoding="utf-8")
        clean = (REPO / "patterns" / "fixtures" / f"{AMP_ZERO}_clean.sol").read_text(encoding="utf-8")

        self.assertRegex(vuln, self.mod._AMP_MATH_RE)
        self.assertRegex(vuln, self.mod._ONLY_UPPER_BOUND_RE)
        self.assertIsNone(self.mod._ZERO_AMP_GUARD_RE.search(vuln))
        self.assertRegex(vuln, self.mod._RECOVERY_FROM_ZERO_BLOCK_RE)

        self.assertRegex(clean, self.mod._AMP_MATH_RE)
        self.assertRegex(clean, self.mod._ONLY_UPPER_BOUND_RE)
        self.assertRegex(clean, self.mod._ZERO_AMP_GUARD_RE)

    def test_revert_source_has_target_hit_shape(self) -> None:
        with tempfile.TemporaryDirectory(prefix="stableswap_amp_shape_") as td:
            ws = _write_minimal_stableswap_workspace(Path(td))
            amp = (ws / "src" / "Amp.sol").read_text(encoding="utf-8")
            math = (ws / "src" / "libraries" / "StableSwapMath.sol").read_text(encoding="utf-8")

            self.assertRegex(amp, self.mod._ONLY_UPPER_BOUND_RE)
            constructor_start = amp.index("constructor(uint256 _baseAmp)")
            constructor_end = amp.index("function startAmpRamp", constructor_start)
            constructor = amp[constructor_start:constructor_end]
            self.assertIsNone(self.mod._ZERO_AMP_GUARD_RE.search(constructor))
            self.assertRegex(math, self.mod._AMP_MATH_RE)
            self.assertRegex(amp, self.mod._RECOVERY_FROM_ZERO_BLOCK_RE)


class FactoryConfigLivenessRoutingRegressionTest(unittest.TestCase):
    def test_revert_source_routes_factory_config_liveness_packet(self) -> None:
        smc_path = REPO / "tools" / "source-mining-campaign.py"
        spec = importlib.util.spec_from_file_location("source_mining_campaign", smc_path)
        smc = importlib.util.module_from_spec(spec)
        assert spec.loader is not None
        spec.loader.exec_module(smc)

        with tempfile.TemporaryDirectory(prefix="stableswap_factory_route_") as td:
            ws = _write_minimal_stableswap_workspace(Path(td))
            domains = smc.slice_domains(ws)
            routed = set(domains.get("factory-config-liveness", []))

            self.assertIn("src/factories/StableSwapHooksFactory.sol", routed)
            self.assertIn("src/interfaces/IStableSwapHooks.sol", routed)
            self.assertIn("src/Amp.sol", routed)
            self.assertIn("src/Base.sol", routed)
            self.assertIn("src/Fees.sol", routed)
            self.assertIn("src/Swap.sol", routed)


if __name__ == "__main__":
    unittest.main()
