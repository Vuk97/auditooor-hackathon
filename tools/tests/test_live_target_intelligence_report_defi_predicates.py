#!/usr/bin/env python3
"""Focused DeFi CAP-021 expansion predicate tests."""

from __future__ import annotations

import importlib.util
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock


_HERE = Path(__file__).resolve().parent
_TOOL_PATH = _HERE.parent / "live-target-intelligence-report.py"
_spec = importlib.util.spec_from_file_location(
    "live_target_intelligence_report_defi_predicates", _TOOL_PATH
)
ltir_mod = importlib.util.module_from_spec(_spec)
assert _spec.loader is not None
_spec.loader.exec_module(ltir_mod)


class Cap021DefiPredicateMatchTest(unittest.TestCase):
    def _semantic(self, inv_id: str, source: str) -> list[str]:
        return ltir_mod._semantic_p1_matches(
            "cap021-defi-direct",
            matched_p1=[inv_id],
            file_line="src/Vault.sol:1",
            snippet="",
            source_context=source,
            source_contract_context=source,
        )

    def test_defi_001_fee_on_transfer_requires_balance_delta_credit(self) -> None:
        tp = """
        contract Vault {
          IERC20 public asset;
          mapping(address => uint256) public shares;
          function deposit(uint256 amount) external {
            asset.safeTransferFrom(msg.sender, address(this), amount);
            shares[msg.sender] += amount;
          }
        }
        """
        fp = """
        contract Vault {
          IERC20 public asset;
          mapping(address => uint256) public shares;
          function deposit(uint256 amount) external {
            uint256 balanceBefore = asset.balanceOf(address(this));
            asset.safeTransferFrom(msg.sender, address(this), amount);
            uint256 balanceAfter = asset.balanceOf(address(this));
            uint256 received = balanceAfter - balanceBefore;
            shares[msg.sender] += received;
          }
        }
        """
        self.assertEqual(self._semantic("INV-DEFI-001", tp), ["INV-DEFI-001"])
        self.assertEqual(self._semantic("INV-DEFI-001", fp), [])

    def test_defi_002_rebasing_asset_uses_share_or_index_accounting(self) -> None:
        tp = """
        contract RebaseVault {
          IERC20 public stETH;
          function totalAssets() public view returns (uint256) {
            return stETH.balanceOf(address(this));
          }
        }
        """
        fp = """
        contract RebaseVault {
          IStEth public stETH;
          function totalAssets() public view returns (uint256) {
            return stETH.getPooledEthByShares(totalShares);
          }
        }
        """
        self.assertEqual(self._semantic("INV-DEFI-002", tp), ["INV-DEFI-002"])
        self.assertEqual(self._semantic("INV-DEFI-002", fp), [])

    def test_defi_003_oracle_uses_twap_or_freshness_guard(self) -> None:
        tp = """
        contract Oracle {
          IUniswapV3Pool public pool;
          function getPrice() external view returns (uint256) {
            (uint160 sqrtPriceX96,,,,,,) = pool.slot0();
            return uint256(sqrtPriceX96);
          }
        }
        """
        fp = """
        contract Oracle {
          AggregatorV3Interface public feed;
          uint256 constant MAX_STALENESS = 1 hours;
          function getPrice() external view returns (uint256) {
            (, int256 answer,, uint256 updatedAt,) = feed.latestRoundData();
            require(block.timestamp - updatedAt <= MAX_STALENESS, "stale");
            return uint256(answer);
          }
        }
        """
        self.assertEqual(self._semantic("INV-DEFI-003", tp), ["INV-DEFI-003"])
        self.assertEqual(self._semantic("INV-DEFI-003", fp), [])


class _FakeNode(SimpleNamespace):
    def __init__(self, expression: str = "", **kwargs: object) -> None:
        super().__init__(expression=expression, **kwargs)


class _FakeFunction:
    def __init__(self, *, name: str, visibility: str, source: str) -> None:
        self.name = name
        self.visibility = visibility
        self.modifiers = []
        self.nodes = [_FakeNode(source)]
        self.source_mapping = SimpleNamespace(content=source)


class _FakeSlitherModule:
    def __init__(self, labels: dict[str, bool], calls: list[str]) -> None:
        self.labels = labels
        self.calls = calls

    def check(self, function: object, label: str) -> bool:
        del function
        self.calls.append(label)
        return self.labels.get(label, False)


class Defi004SafeApprovePredicateTest(unittest.TestCase):
    def _semantic(self, source: str) -> list[str]:
        return ltir_mod._semantic_p1_matches(
            "defi004-safeapprove",
            matched_p1=["INV-DEFI-004"],
            file_line="src/Vault.sol:1",
            snippet="safeApprove",
            source_context=source,
            source_contract_context=source,
        )

    def _semantic_with_fake_slither(
        self,
        source: str,
        candidate_function: _FakeFunction,
    ) -> tuple[list[str], list[str]]:
        calls: list[str] = []
        fake_module = _FakeSlitherModule({"has_safe_approve": True}, calls)

        with mock.patch.object(
            ltir_mod,
            "_load_slither_predicates_module",
            return_value=fake_module,
        ), mock.patch.object(
            ltir_mod,
            "_slither_candidate_functions_for_predicate",
            return_value=[candidate_function],
        ):
            semantic = self._semantic(source)

        return semantic, calls

    def test_defi_004_accepts_external_integration_safeapprove_then_deposit(self) -> None:
        source = """
        contract VaultAdapter {
          using SafeERC20 for IERC20;
          function depositToRouter(IERC20 token, address router, uint256 amount) external {
            token.safeApprove(router, amount);
            IRouter(router).deposit(amount);
          }
        }
        """
        semantic, calls = self._semantic_with_fake_slither(
            source,
            _FakeFunction(
                name="depositToRouter",
                visibility="external",
                source=source,
            ),
        )
        self.assertEqual(semantic, ["INV-DEFI-004"])
        self.assertEqual(calls, ["has_safe_approve"])
        self.assertEqual(self._semantic(source), ["INV-DEFI-004"])

    def test_defi_004_rejects_safeapprove_library_body(self) -> None:
        source = """
        library SafeERC20 {
          function safeApprove(IERC20 token, address spender, uint256 value) internal {
            token.approve(spender, value);
          }
        }
        """
        semantic, calls = self._semantic_with_fake_slither(
            source,
            _FakeFunction(name="safeApprove", visibility="internal", source=source),
        )
        self.assertEqual(semantic, [])
        self.assertEqual(calls, ["has_safe_approve"])

    def test_defi_004_rejects_reset_only_safeapprove(self) -> None:
        source = """
        contract VaultAdapter {
          using SafeERC20 for IERC20;
          function resetAllowance(IERC20 token, address spender) external {
            token.safeApprove(spender, 0);
          }
        }
        """
        semantic, calls = self._semantic_with_fake_slither(
            source,
            _FakeFunction(name="resetAllowance", visibility="external", source=source),
        )
        self.assertEqual(semantic, [])
        self.assertEqual(calls, ["has_safe_approve"])

    def test_defi_004_rejects_wrapper_without_downstream_allowance_action(self) -> None:
        source = """
        contract VaultAdapter {
          using SafeERC20 for IERC20;
          function prepareAllowance(IERC20 token, address router, uint256 amount) external {
            token.safeApprove(router, amount);
            emit AllowancePrepared(router, amount);
          }
        }
        """
        semantic, calls = self._semantic_with_fake_slither(
            source,
            _FakeFunction(name="prepareAllowance", visibility="external", source=source),
        )
        self.assertEqual(semantic, [])
        self.assertEqual(calls, ["has_safe_approve"])


if __name__ == "__main__":
    unittest.main()
