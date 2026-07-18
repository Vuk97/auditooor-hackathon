#!/usr/bin/env python3
"""Focused totalSupply-read helper regression tests for INV-MON-011."""

from __future__ import annotations

import importlib.util
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock


_HERE = Path(__file__).resolve().parent
_ROOT = _HERE.parent.parent

_LTIR_PATH = _ROOT / "tools" / "live-target-intelligence-report.py"
_LTIR_SPEC = importlib.util.spec_from_file_location(
    "live_target_intelligence_report_mon011_tests",
    _LTIR_PATH,
)
ltir_mod = importlib.util.module_from_spec(_LTIR_SPEC)
assert _LTIR_SPEC.loader is not None
_LTIR_SPEC.loader.exec_module(ltir_mod)

_SLITHER_PATH = _ROOT / "tools" / "slither_predicates.py"
_SLITHER_SPEC = importlib.util.spec_from_file_location(
    "slither_predicates_for_mon011_tests",
    _SLITHER_PATH,
)
slither_mod = importlib.util.module_from_spec(_SLITHER_SPEC)
assert _SLITHER_SPEC.loader is not None
_SLITHER_SPEC.loader.exec_module(slither_mod)


class _FakeNode(SimpleNamespace):
    def __init__(self, *, high_level_calls: list[object] | None = None) -> None:
        super().__init__(high_level_calls=high_level_calls or [])


class _FakeFunction:
    def __init__(self, source: str, *, high_level_call_names: tuple[str, ...] = ()) -> None:
        calls = [(None, SimpleNamespace(name=name)) for name in high_level_call_names]
        self.nodes = [_FakeNode(high_level_calls=calls)]
        self.source_mapping = SimpleNamespace(content=source)
        self.name = "quote"
        self.visibility = "external"


class _RegexOnlyFunction:
    def __init__(self, source: str) -> None:
        self.source_mapping = SimpleNamespace(content=source)


class Mon011TotalSupplyPredicateTests(unittest.TestCase):
    def _semantic(self, source: str, *, snippet: str = "") -> list[str]:
        return ltir_mod._semantic_p1_matches(
            "mon011-total-supply",
            matched_p1=["INV-MON-011"],
            file_line="src/Supply.sol:1",
            snippet=snippet,
            source_context=source,
            source_contract_context=source,
        )

    def _semantic_with_candidate(
        self,
        source: str,
        candidate_function: _FakeFunction,
        *,
        snippet: str = "vault.totalSupply()",
    ) -> list[str]:
        with mock.patch.object(
            ltir_mod,
            "_slither_candidate_functions_for_predicate",
            return_value=[candidate_function],
        ):
            return self._semantic(source, snippet=snippet)

    def test_mon_011_positive_read_side_supply_decision_input(self) -> None:
        source = """
        contract RewardVault {
          IERC20 public vault;
          uint256 constant MIN_SUPPLY = 1e18;
          function issue(uint256 assets) external view returns (uint256 shares) {
            uint256 supply = vault.totalSupply();
            require(supply >= MIN_SUPPLY, "too small");
            shares = assets * 1e18 / supply;
          }
        }
        """
        fn = _FakeFunction(source, high_level_call_names=("totalSupply",))

        self.assertTrue(slither_mod.check(fn, "has_total_supply"))
        self.assertEqual(self._semantic_with_candidate(source, fn), ["INV-MON-011"])
        self.assertEqual(self._semantic(source, snippet="vault.totalSupply()"), ["INV-MON-011"])

    def test_mon_011_write_side_supply_mutation_stays_out(self) -> None:
        source = """
        contract SupplyAdmin {
          uint256 public totalSupply;
          function setSupply(uint256 supply) external {
            totalSupply = supply;
            _totalSupply = supply;
          }
        }
        """
        fn = _FakeFunction(source)

        self.assertFalse(slither_mod.check(fn, "has_total_supply"))
        self.assertEqual(self._semantic(source), [])

    def test_mon_011_informational_getter_stays_out(self) -> None:
        source = """
        contract SupplyView {
          uint256 public totalSupply;
          function display() external view returns (uint256) {
            return totalSupply;
          }
        }
        """
        fn = _RegexOnlyFunction(source)

        self.assertFalse(slither_mod.check(fn, "has_total_supply"))
        self.assertEqual(self._semantic(source), [])


if __name__ == "__main__":
    unittest.main(verbosity=2)
