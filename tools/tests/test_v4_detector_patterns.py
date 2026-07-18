#!/usr/bin/env python3
"""Tests for the 4 v4-hook detector patterns shipped per
`docs/REVERT_GAP_ANALYSIS_2026-05-08.md`:

  - detectors/wave17/v4_hook_take_before_pricing_state_mutation.py (#29)
  - detectors/wave17/exact_output_floor_input_drain.py (#8)
  - detectors/wave17/v4_hook_beforeswap_slippage_bypass.py (#991)
  - detectors/wave17/v4_settle_without_prior_sync.py (#995)

Stdlib-only. Each detector exposes a regex-based `scan(source, path)`
API; tests load the module via importlib (avoids polluting sys.path
and stays independent of the wave17 Slither plumbing).
"""
from __future__ import annotations

import importlib.util
import sys
import unittest
from pathlib import Path


REPO = Path(__file__).resolve().parents[2]
WAVE17 = REPO / "detectors" / "wave17"
FIXTURES = REPO / "detectors" / "fixtures" / "solidity"


def _load(module_name: str):
    if module_name in sys.modules:
        return sys.modules[module_name]
    path = WAVE17 / f"{module_name}.py"
    spec = importlib.util.spec_from_file_location(module_name, path)
    assert spec and spec.loader, f"failed to load {path}"
    mod = importlib.util.module_from_spec(spec)
    # register before exec so @dataclass can resolve __module__ via sys.modules
    sys.modules[module_name] = mod
    spec.loader.exec_module(mod)
    return mod


def _read(path: Path) -> str:
    return path.read_text(encoding="utf-8")


class V4HookTakeBeforePricingTest(unittest.TestCase):
    DETECTOR = "v4_hook_take_before_pricing_state_mutation"

    def test_fires_on_vulnerable_fixture(self) -> None:
        mod = _load(self.DETECTOR)
        src = _read(FIXTURES / self.DETECTOR / "vulnerable.sol")
        findings = mod.scan(src, "vulnerable.sol")
        self.assertGreaterEqual(len(findings), 1)
        f = findings[0]
        self.assertEqual(f.detector, "v4-hook-take-before-pricing-state-mutation")
        self.assertEqual(f.severity, "High")
        self.assertEqual(f.function, "_handleRemoveLiquidityCallback")

    def test_skips_clean_fixture(self) -> None:
        mod = _load(self.DETECTOR)
        src = _read(FIXTURES / self.DETECTOR / "clean.sol")
        findings = mod.scan(src, "clean.sol")
        self.assertEqual(findings, [])


class ExactOutputFloorInputDrainTest(unittest.TestCase):
    DETECTOR = "exact_output_floor_input_drain"

    def test_fires_on_vulnerable_fixture(self) -> None:
        mod = _load(self.DETECTOR)
        src = _read(FIXTURES / self.DETECTOR / "vulnerable.sol")
        findings = mod.scan(src, "vulnerable.sol")
        self.assertGreaterEqual(len(findings), 1)
        f = findings[0]
        self.assertEqual(f.detector, "exact-output-floor-input-drain")
        self.assertEqual(f.function, "_swapExactOutput")
        self.assertEqual(f.severity, "High")

    def test_skips_clean_fixture(self) -> None:
        mod = _load(self.DETECTOR)
        src = _read(FIXTURES / self.DETECTOR / "clean.sol")
        findings = mod.scan(src, "clean.sol")
        self.assertEqual(findings, [])


class V4HookBeforeSwapSlippageBypassTest(unittest.TestCase):
    DETECTOR = "v4_hook_beforeswap_slippage_bypass"

    def test_fires_on_vulnerable_fixture(self) -> None:
        mod = _load(self.DETECTOR)
        src = _read(FIXTURES / self.DETECTOR / "vulnerable.sol")
        findings = mod.scan(src, "vulnerable.sol")
        self.assertGreaterEqual(len(findings), 1)
        f = findings[0]
        self.assertEqual(f.detector, "v4-hook-beforeswap-slippage-bypass")
        self.assertEqual(f.function, "_beforeSwap")
        self.assertEqual(f.severity, "Medium")

    def test_skips_clean_fixture(self) -> None:
        mod = _load(self.DETECTOR)
        src = _read(FIXTURES / self.DETECTOR / "clean.sol")
        findings = mod.scan(src, "clean.sol")
        self.assertEqual(findings, [])


class V4SettleWithoutPriorSyncTest(unittest.TestCase):
    DETECTOR = "v4_settle_without_prior_sync"

    def test_fires_on_vulnerable_fixture_with_sibling_asymmetry(self) -> None:
        mod = _load(self.DETECTOR)
        src = _read(FIXTURES / self.DETECTOR / "vulnerable.sol")
        findings = mod.scan(src, "vulnerable.sol")
        self.assertGreaterEqual(len(findings), 1)
        f = findings[0]
        self.assertEqual(f.detector, "v4-settle-without-prior-sync")
        # sibling-branch asymmetry: ERC20 branch calls sync -> Medium
        self.assertEqual(f.severity, "Medium")
        self.assertIn("sibling", f.message.lower())

    def test_skips_clean_fixture(self) -> None:
        mod = _load(self.DETECTOR)
        src = _read(FIXTURES / self.DETECTOR / "clean.sol")
        findings = mod.scan(src, "clean.sol")
        self.assertEqual(findings, [])


# --- Real-codebase fire verification (Revert StableSwapHooks workspace) ---
#
# These tests are GUARDED by the presence of the audit workspace. They
# are skipped in CI / on machines where the workspace is not present so
# the suite stays portable.

REVERT_SRC = Path("/Users/wolf/audits/revert-stableswap-hooks/external/stableswap-hooks/src")


class RevertWorkspaceFiresTest(unittest.TestCase):
    @unittest.skipUnless(REVERT_SRC.exists(), "revert workspace not present")
    def test_take_pattern_fires_on_liquidity_sol(self) -> None:
        mod = _load("v4_hook_take_before_pricing_state_mutation")
        src = (REVERT_SRC / "Liquidity.sol").read_text(encoding="utf-8")
        findings = mod.scan(src, "Liquidity.sol")
        self.assertGreaterEqual(len(findings), 1)

    @unittest.skipUnless(REVERT_SRC.exists(), "revert workspace not present")
    def test_exact_output_pattern_fires_on_swap_sol(self) -> None:
        mod = _load("exact_output_floor_input_drain")
        src = (REVERT_SRC / "Swap.sol").read_text(encoding="utf-8")
        findings = mod.scan(src, "Swap.sol")
        self.assertGreaterEqual(len(findings), 1)

    @unittest.skipUnless(REVERT_SRC.exists(), "revert workspace not present")
    def test_settle_pattern_fires_on_liquidity_sol(self) -> None:
        # Cantina #995 trigger lives in Liquidity.sol (native settle in
        # _handleAddLiquidityCallback, sibling ERC20 branch syncs).
        mod = _load("v4_settle_without_prior_sync")
        src = (REVERT_SRC / "Liquidity.sol").read_text(encoding="utf-8")
        findings = mod.scan(src, "Liquidity.sol")
        self.assertGreaterEqual(len(findings), 1)


if __name__ == "__main__":
    unittest.main()
