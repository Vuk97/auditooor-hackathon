#!/usr/bin/env python3
"""Tests for the 2 wave17 anchoring-trap detectors shipped per Revert
Cantina post-mortem (Findings #15 + #102 — confirmed Medium):

  - detectors/wave17/wrapper_passes_zero_slippage_to_internal_call.py (#15)
  - detectors/wave17/dual_direction_swap_math_asymmetry.py (#102)

Stdlib-only. Each detector exposes a regex-based `scan(source, path)`
API; tests load the module via importlib (avoids polluting sys.path
and stays independent of the wave17 Slither plumbing).

Mirrors the structure of `test_v4_detector_patterns.py`.
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
    sys.modules[module_name] = mod
    spec.loader.exec_module(mod)
    return mod


def _read(path: Path) -> str:
    return path.read_text(encoding="utf-8")


class WrapperPassesZeroSlippageTest(unittest.TestCase):
    DETECTOR = "wrapper_passes_zero_slippage_to_internal_call"
    FIXTURE_DIR = "wrapper_passes_zero_slippage"

    def test_fires_on_vulnerable_fixture(self) -> None:
        mod = _load(self.DETECTOR)
        src = _read(FIXTURES / self.FIXTURE_DIR / "vulnerable.sol")
        findings = mod.scan(src, "vulnerable.sol")
        self.assertGreaterEqual(len(findings), 1)
        f = findings[0]
        self.assertEqual(f.detector, "wrapper-passes-zero-slippage-to-internal-call")
        self.assertEqual(f.severity, "Medium")
        # Expect the function name to be the periphery entrypoint
        self.assertEqual(f.function, "zapIn")

    def test_skips_clean_fixture(self) -> None:
        mod = _load(self.DETECTOR)
        src = _read(FIXTURES / self.FIXTURE_DIR / "clean.sol")
        findings = mod.scan(src, "clean.sol")
        self.assertEqual(findings, [])


class DualDirectionSwapMathAsymmetryTest(unittest.TestCase):
    DETECTOR = "dual_direction_swap_math_asymmetry"
    FIXTURE_DIR = "dual_direction_swap_math_asymmetry"

    def test_fires_on_vulnerable_fixture(self) -> None:
        mod = _load(self.DETECTOR)
        src = _read(FIXTURES / self.FIXTURE_DIR / "vulnerable.sol")
        findings = mod.scan(src, "vulnerable.sol")
        self.assertGreaterEqual(len(findings), 1)
        f = findings[0]
        self.assertEqual(f.detector, "dual-direction-swap-math-asymmetry")
        self.assertEqual(f.severity, "Medium")
        self.assertEqual(f.function, "_swapExactInput")
        self.assertIn("subtracts", f.message)
        self.assertIn("adds", f.message)

    def test_skips_clean_fixture(self) -> None:
        mod = _load(self.DETECTOR)
        src = _read(FIXTURES / self.FIXTURE_DIR / "clean.sol")
        findings = mod.scan(src, "clean.sol")
        self.assertEqual(findings, [])


# --- Real-codebase fire verification (Revert StableSwapHooks workspace) ---
#
# These tests are GUARDED by the presence of the audit workspace. They
# are skipped on machines where the workspace is not present so the suite
# stays portable.

REVERT_ROOT = Path("/Users/wolf/audits/revert-stableswap-hooks/external/stableswap-hooks/src")
REVERT_PERIPHERY = REVERT_ROOT / "periphery"


class RevertWorkspaceFiresTest(unittest.TestCase):
    @unittest.skipUnless(
        (REVERT_PERIPHERY / "StableSwapZapIn.sol").exists(),
        "revert workspace not present",
    )
    def test_wrapper_zero_slippage_fires_on_zapin(self) -> None:
        mod = _load("wrapper_passes_zero_slippage_to_internal_call")
        src = (REVERT_PERIPHERY / "StableSwapZapIn.sol").read_text(encoding="utf-8")
        findings = mod.scan(src, "StableSwapZapIn.sol")
        self.assertGreaterEqual(len(findings), 1)
        # The vulnerable call lives at line 429 (per audit memory).
        # We accept anything in the surrounding window (425-435) to
        # tolerate minor source drift.
        hit_lines = {f.line for f in findings}
        self.assertTrue(
            any(425 <= ln <= 435 for ln in hit_lines),
            f"expected fire near line 429, got lines {sorted(hit_lines)}",
        )

    @unittest.skipUnless(
        (REVERT_ROOT / "Swap.sol").exists(),
        "revert workspace not present",
    )
    def test_dual_direction_fires_on_swap_sol(self) -> None:
        mod = _load("dual_direction_swap_math_asymmetry")
        src = (REVERT_ROOT / "Swap.sol").read_text(encoding="utf-8")
        findings = mod.scan(src, "Swap.sol")
        self.assertGreaterEqual(len(findings), 1)
        # The mirror pair is _swapExactInput / _swapExactOutput.
        names = {f.function for f in findings}
        self.assertIn("_swapExactInput", names)


if __name__ == "__main__":
    unittest.main()
