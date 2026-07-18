"""
ec-liquidation-reward-from-pool-state — generated from reference/patterns.dsl/ec-liquidation-reward-from-pool-state.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py ec-liquidation-reward-from-pool-state.yaml
Source: economic-mining-R61
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class EcLiquidationRewardFromPoolState(AbstractDetector):
    ARGUMENT = "ec-liquidation-reward-from-pool-state"
    HELP = "Liquidation bonus computed directly from manipulable pool state (totalAssets, totalSupply, getReserves) rather than a manipulation-resistant oracle."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.LOW
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/ec-liquidation-reward-from-pool-state.yaml"
    WIKI_TITLE = "Liquidation reward derived from live pool state — manipulable by donor/swapper"
    WIKI_DESCRIPTION = "The liquidation function computes the amount of collateral to seize using live pool metrics (totalAssets, totalSupply, or getReserves) that reflect the current state of an ERC-4626 vault or AMM. An attacker can inflate these metrics by donating tokens directly to the pool (bypassing the accounting layer), then liquidate an undercollateralized position to receive a disproportionate collateral alloc"
    WIKI_EXPLOIT_SCENARIO = "Vault.totalAssets() = 1000 USDC. Attacker donates 500 USDC directly to vault address, skipping deposit(). Now totalAssets() = 1500. Liquidation seizes 30% of vault value = 450 USDC. Attacker recovers 500+reward, protocol loses."
    WIKI_RECOMMENDATION = "Use a TWAP or Chainlink price feed — not live pool metrics — to price collateral during liquidation. If vault share prices must be used, implement donation-resistance via an internal accounting tracker (lastTotalAssets) that only increases via the official deposit() path."

    _PRECONDITIONS = [{'contract.source_matches_regex': 'liquidat|seize|forceLiquidate|repayBorrowBehalf'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': 'liquidat|seize|forceLiquidate|repayBorrowBehalf'}, {'function.has_high_level_call_named': 'totalSupply'}, {'function.has_high_level_call_named': 'totalSupply'}, {'function.has_high_level_call_named': 'totalSupply'}, {'function.has_high_level_call_named': 'totalSupply'}, {'function.has_high_level_call_named': 'totalSupply'}, {'function.has_high_level_call_named': 'totalSupply'}, {'function.has_high_level_call_named': 'totalSupply'}, {'function.has_high_level_call_named': 'totalSupply'}, {'function.has_high_level_call_named': 'totalSupply'}, {'function.has_high_level_call_named': 'totalSupply'}, {'function.has_high_level_call_named': 'totalSupply'}, {'function.has_high_level_call_named': 'totalSupply'}, {'function.has_high_level_call_named': 'totalSupply'}, {'function.has_high_level_call_named': 'totalSupply'}, {'function.body_contains_regex': 'totalAssets\\(\\)|totalSupply\\(\\)|getReserves\\(\\)|convertToAssets\\(|previewRedeem\\('}, {'function.body_contains_regex': 'bonus|reward|incentive|discount|penalty|seize'}, {'function.body_not_contains_regex': 'latestRoundData|latestAnswer|twap|TWAP|getPrice\\s*\\('}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

    _INCLUDE_LEAF_HELPERS = False
    _INVERSE_CEI = False

    def _detect(self):
        results = []
        for c in self.contracts:
            if is_vendored_or_test_contract(c):
                continue
            if not eval_preconditions(c, self._PRECONDITIONS):
                continue
            for f in c.functions_and_modifiers_declared:
                if not self._INCLUDE_LEAF_HELPERS and is_leaf_helper(f):
                    continue
                if not eval_function_match(f, self._MATCH):
                    continue
                info = [f, f" — ec-liquidation-reward-from-pool-state: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
