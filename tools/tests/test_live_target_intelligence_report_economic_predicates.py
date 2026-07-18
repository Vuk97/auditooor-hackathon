#!/usr/bin/env python3
"""Focused economic domain matcher/predicate coverage for live-target report."""

from __future__ import annotations

import importlib.util
import unittest
from pathlib import Path


_HERE = Path(__file__).resolve().parent
_TOOL_PATH = _HERE.parent / "live-target-intelligence-report.py"
_SPEC = importlib.util.spec_from_file_location(
    "live_target_intelligence_report_economic_predicates", _TOOL_PATH
)
_LTIR = importlib.util.module_from_spec(_SPEC)
assert _SPEC is not None and _SPEC.loader is not None
_SPEC.loader.exec_module(_LTIR)


class EconomicDomainMatcherConventionTest(unittest.TestCase):
    def test_keyword_resolver_maps_economic_assertion_slugs(self) -> None:
        cases = [
            ("insurance-fund-draw", "conservation", "custody-and-accounting"),
            ("collateral-pool", "freshness", "custody-and-accounting"),
            ("yield-diversion", "monotonicity", "custody-and-accounting"),
            ("governance-vote-dilution", "conservation", "authorization"),
        ]
        for slug, exp_p1, exp_p3 in cases:
            p1, p3 = _LTIR._resolve_cluster_category(slug)
            self.assertEqual(p1, exp_p1, slug)
            self.assertEqual(p3, exp_p3, slug)

    def test_matcher_returns_expected_p1_ids_for_economic_domain(self) -> None:
        fake_p1_index = {
            "conservation|solidity": ["INV-CON-006"],
            "freshness|solidity": ["INV-FRESH-005"],
            "monotonicity|solidity": ["INV-MON-006"],
            "conservation|go": ["INV-CON-004"],
        }
        self.assertIn(
            "INV-CON-006",
            _LTIR._match_p1_for_cluster(
                "insurance-fund-draw",
                p1_index=fake_p1_index,
                file_hint="src/Vault.sol:101",
            ),
        )
        self.assertIn(
            "INV-FRESH-005",
            _LTIR._match_p1_for_cluster(
                "collateral-pool",
                p1_index=fake_p1_index,
                file_hint="src/RiskEngine.sol:22",
            ),
        )
        self.assertIn(
            "INV-MON-006",
            _LTIR._match_p1_for_cluster(
                "yield-diversion",
                p1_index=fake_p1_index,
                file_hint="src/YieldVault.sol:9",
            ),
        )
        self.assertIn(
            "INV-CON-004",
            _LTIR._match_p1_for_cluster(
                "governance-vote-dilution",
                p1_index=fake_p1_index,
                file_hint="protocol/x/clob/keeper/stake.go:77",
            ),
        )


class EconomicPredicateSemanticTest(unittest.TestCase):
    def _semantic(self, inv_id: str, source: str) -> list[str]:
        return _LTIR._semantic_p1_matches(
            "economic-assertions",
            matched_p1=[inv_id],
            file_line="src/Econ.sol:1",
            snippet="",
            source_context=source,
            source_contract_context=source,
        )

    def test_inv_con_006_insurance_fund_draw_requires_historical_guard(self) -> None:
        tp = """
        contract InsuranceFund {
          AggregatorV3Interface public feed;
          function drawInsuranceFund(uint256 amount) external {
            (, int256 px,,,) = feed.latestRoundData();
            require(px > 0, "bad");
            payout(amount);
          }
        }
        """
        fp = """
        contract InsuranceFund {
          AggregatorV3Interface public feed;
          uint256 constant MAX_STALENESS = 1 hours;
          function drawInsuranceFund(uint256 amount) external {
            (, int256 px,, uint256 updatedAt,) = feed.latestRoundData();
            require(block.timestamp - updatedAt <= MAX_STALENESS, "stale");
            require(px > 0, "bad");
            payout(amount);
          }
        }
        """
        self.assertEqual(self._semantic("INV-CON-006", tp), ["INV-CON-006"])
        self.assertEqual(self._semantic("INV-CON-006", fp), [])

    def test_inv_fresh_005_collateral_pool_avoids_self_priced_read(self) -> None:
        tp = """
        contract RiskEngine {
          IUniswapV3Pool public collateralPool;
          function collateralValue(address account) external view returns (uint256) {
            (uint160 sqrtPriceX96,,,,,,) = collateralPool.slot0();
            return uint256(sqrtPriceX96) * balances[account];
          }
        }
        """
        fp = """
        contract RiskEngine {
          IUniswapV3Pool public collateralPool;
          AggregatorV3Interface public chainlinkFeed;
          function collateralValue(address account) external view returns (uint256) {
            (, int256 px,, uint256 updatedAt,) = chainlinkFeed.latestRoundData();
            require(block.timestamp - updatedAt <= 1 hours, "stale");
            return uint256(px) * balances[account];
          }
        }
        """
        self.assertEqual(self._semantic("INV-FRESH-005", tp), ["INV-FRESH-005"])
        self.assertEqual(self._semantic("INV-FRESH-005", fp), [])

    def test_inv_con_004_governance_vote_dilution_power_mismatch(self) -> None:
        tp = """
        func ApplyVoteUpdate(votingPower uint64, totalBondedStake uint64) {
            _ = votingPower
            _ = totalBondedStake
        }
        """
        fp = """
        func ApplyVoteUpdate(votingPower uint64, totalBondedStake uint64) error {
            if votingPower != totalBondedStake {
                return fmt.Errorf("vote power mismatch")
            }
            return nil
        }
        """
        self.assertEqual(self._semantic("INV-CON-004", tp), ["INV-CON-004"])
        self.assertEqual(self._semantic("INV-CON-004", fp), [])

    def test_inv_con_004_is_function_scoped_for_multifunction_contracts(self) -> None:
        self.assertIn("INV-CON-004", _LTIR.FUNCTION_SCOPED_P1_INVARIANTS)
        source = """
        contract GovernanceAccounting {
          function guardedVotePower(uint256 votingPower, uint256 totalBondedStake) external pure {
            require(votingPower == totalBondedStake, "balanced");
          }

          function updateVotePower(uint256 votingPower, uint256 totalBondedStake) external pure {
            votingPower;
            totalBondedStake;
          }
        }
        """
        unsafe_snippet = "function updateVotePower(uint256 votingPower, uint256 totalBondedStake) external pure"
        safe_snippet = "function guardedVotePower(uint256 votingPower, uint256 totalBondedStake) external pure"

        self.assertEqual(
            _LTIR._semantic_p1_matches(
                "governance-vote-dilution",
                matched_p1=["INV-CON-004"],
                file_line="src/GovernanceAccounting.sol:7",
                snippet=unsafe_snippet,
                source_context=source,
                source_contract_context=source,
            ),
            ["INV-CON-004"],
        )
        self.assertEqual(
            _LTIR._semantic_p1_matches(
                "governance-vote-dilution",
                matched_p1=["INV-CON-004"],
                file_line="src/GovernanceAccounting.sol:3",
                snippet=safe_snippet,
                source_context=source,
                source_contract_context=source,
            ),
            [],
        )


class EconomicWorkspaceFixtureTest(unittest.TestCase):
    def _matched_semantic(
        self,
        slug: str,
        *,
        p1_index: dict[str, list[str]],
        file_line: str,
        source: str,
    ) -> list[str]:
        matched = _LTIR._match_p1_for_cluster(slug, p1_index=p1_index, file_hint=file_line)
        return _LTIR._semantic_p1_matches(
            slug,
            matched_p1=matched,
            file_line=file_line,
            snippet="",
            source_context=source,
            source_contract_context=source,
        )

    def test_spark_fixture_economic_assertions_fire(self) -> None:
        p1_index = {
            "conservation|solidity": ["INV-CON-006"],
            "freshness|solidity": ["INV-FRESH-005"],
            "monotonicity|solidity": ["INV-MON-006"],
        }
        spark_insurance_fixture = """
        contract SparkInsuranceFund {
          AggregatorV3Interface public reserveFeed;
          function drawInsuranceFund(uint256 amount) external {
            (, int256 reservePrice,,,) = reserveFeed.latestRoundData();
            require(reservePrice > 0, "bad reserve");
            payout(amount);
          }
        }
        """
        spark_collateral_fixture = """
        contract SparkRiskEngine {
          IUniswapV3Pool public collateralPool;
          function collateralValue(address account) external view returns (uint256) {
            (uint160 sqrtPriceX96,,,,,,) = collateralPool.slot0();
            return balances[account] * uint256(sqrtPriceX96);
          }
        }
        """
        spark_yield_fixture = """
        contract SparkYieldRouter {
          uint256 public lastUpdate;
          address public yieldRecipient;
          function divertYield(uint256 newTimestamp, address recipient) external {
            lastUpdate = newTimestamp;
            yieldRecipient = recipient;
          }
        }
        """

        self.assertEqual(
            self._matched_semantic(
                "insurance-fund-draw",
                p1_index=p1_index,
                file_line="/Users/wolf/audits/spark/src/SparkInsuranceFund.sol:12",
                source=spark_insurance_fixture,
            ),
            ["INV-CON-006"],
        )
        self.assertEqual(
            self._matched_semantic(
                "collateral-pool",
                p1_index=p1_index,
                file_line="/Users/wolf/audits/spark/src/SparkRiskEngine.sol:9",
                source=spark_collateral_fixture,
            ),
            ["INV-FRESH-005"],
        )
        self.assertEqual(
            self._matched_semantic(
                "yield-diversion",
                p1_index=p1_index,
                file_line="/Users/wolf/audits/spark/src/SparkYieldRouter.sol:8",
                source=spark_yield_fixture,
            ),
            ["INV-MON-006"],
        )

    def test_dydx_fixture_governance_vote_dilution_fires(self) -> None:
        p1_index = {"conservation|go": ["INV-CON-004"]}
        dydx_governance_fixture = """
        package keeper

        func ApplyVotePower(votingPower uint64, totalBondedStake uint64) {
            ctx.EventManager().EmitEvent(types.NewVotePowerEvent(votingPower, totalBondedStake))
        }
        """

        self.assertEqual(
            self._matched_semantic(
                "governance-vote-dilution",
                p1_index=p1_index,
                file_line="/Users/wolf/audits/dydx/protocol/x/gov/keeper/vote_power.go:18",
                source=dydx_governance_fixture,
            ),
            ["INV-CON-004"],
        )


if __name__ == "__main__":
    unittest.main(verbosity=2)
