#!/usr/bin/env python3
"""Focused native-custody predicate tests for live-target intelligence."""

from __future__ import annotations

import importlib.util
import unittest
from pathlib import Path
from unittest import mock


_HERE = Path(__file__).resolve().parent
_TOOL_PATH = _HERE.parent / "live-target-intelligence-report.py"
_spec = importlib.util.spec_from_file_location(
    "live_target_intelligence_report_custody_predicates", _TOOL_PATH
)
ltir_mod = importlib.util.module_from_spec(_spec)
assert _spec.loader is not None
_spec.loader.exec_module(ltir_mod)


class _FakeSourceMapping:
    def __init__(self, content: str) -> None:
        self.content = content


class _FakeFunction:
    def __init__(self, source: str, *, name: str = "payout", visibility: str = "external") -> None:
        self.name = name
        self.visibility = visibility
        self.modifiers = []
        self.nodes = []
        self.source_mapping = _FakeSourceMapping(source)


class NativeCustodyPredicateTests(unittest.TestCase):
    def _semantic(self, source: str, *, snippet: str = "") -> list[str]:
        return ltir_mod._semantic_p1_matches(
            "custody-native-balance",
            matched_p1=["INV-CUST-010"],
            file_line="src/NativeEscrow.sol:1",
            snippet=snippet,
            source_context=source,
            source_contract_context=source,
        )

    def test_cust_010_matches_native_balance_guarded_payout(self) -> None:
        source = """
        contract NativeEscrow {
          function payout(address payable to, uint256 owed) external {
            uint256 bal = address(this).balance;
            require(bal >= owed, "insufficient");
            (bool ok,) = to.call{value: owed}("");
            require(ok);
          }
        }
        """
        self.assertEqual(self._semantic(source, snippet='to.call{value: owed}("")'), ["INV-CUST-010"])

    def test_cust_010_matches_direct_native_wrapper_input(self) -> None:
        source = """
        contract NativeWrapper {
          IWETH public immutable weth;
          function wrapAll() external {
            weth.deposit{value: address(this).balance}();
          }
        }
        """
        self.assertEqual(self._semantic(source, snippet="weth.deposit{value: address(this).balance}()"), ["INV-CUST-010"])

    def test_cust_010_rejects_erc20_balanceof_only_flow(self) -> None:
        source = """
        contract TokenEscrow {
          function payout(IERC20 token, address to, uint256 owed) external {
            uint256 bal = token.balanceOf(address(this));
            require(bal >= owed, "insufficient");
            token.transfer(to, owed);
          }
        }
        """
        self.assertEqual(self._semantic(source), [])

    def test_cust_010_rejects_view_only_or_log_only_balance_reads(self) -> None:
        view_only = """
        contract NativeView {
          function getBalance() external view returns (uint256) {
            return address(this).balance;
          }
        }
        """
        log_only = """
        contract NativeLog {
          event BalanceSeen(uint256 amount);
          function ping() external {
            emit BalanceSeen(address(this).balance);
          }
        }
        """
        self.assertEqual(self._semantic(view_only), [])
        self.assertEqual(self._semantic(log_only), [])

    def test_cust_010_rejects_string_literal_only_balance_reads(self) -> None:
        source = """
        contract NativeString {
          function ping() external {
            require(true, "address(this).balance >= owed");
          }
        }
        """
        self.assertEqual(self._semantic(source), [])

    def test_cust_010_consumes_reads_self_balance_helper_when_slither_candidates_exist(self) -> None:
        source = """
        contract NativeEscrow {
          function payout(address payable to, uint256 owed) external {
            uint256 bal = address(this).balance;
            require(bal >= owed, "insufficient");
            (bool ok,) = to.call{value: owed}("");
            require(ok);
          }
        }
        """
        fake_function = _FakeFunction(source)
        seen_labels: list[str] = []

        def fake_ast_check(function: object, label: str) -> bool:
            self.assertIs(function, fake_function)
            seen_labels.append(label)
            return label == "reads_self_balance"

        with mock.patch.object(
            ltir_mod,
            "_slither_candidate_functions_for_predicate",
            return_value=[fake_function],
        ), mock.patch.object(ltir_mod, "_slither_ast_check", side_effect=fake_ast_check):
            self.assertEqual(self._semantic(source, snippet='to.call{value: owed}("")'), ["INV-CUST-010"])

        self.assertIn("reads_self_balance", seen_labels)


if __name__ == "__main__":
    unittest.main()
