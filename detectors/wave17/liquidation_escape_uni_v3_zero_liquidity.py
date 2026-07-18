"""
liquidation-escape-uni-v3-zero-liquidity — generated from reference/patterns.dsl/liquidation-escape-uni-v3-zero-liquidity.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py liquidation-escape-uni-v3-zero-liquidity.yaml
Source: solodit/C0372
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class LiquidationEscapeUniV3ZeroLiquidity(AbstractDetector):
    ARGUMENT = "liquidation-escape-uni-v3-zero-liquidity"
    HELP = "Liquidation path checks a cached positionValue/collateralValue without re-fetching the current underlying liquidity. Victim can escape liquidation by depositing a zero-liquidity Uni v3 NFT as collateral OR by withdrawing in-the-money LP profit to zero out the liquidatable surplus."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/liquidation-escape-uni-v3-zero-liquidity.yaml"
    WIKI_TITLE = "Liquidation escape via zero-liquidity Uni v3 LP collateral or in-the-money withdraw"
    WIKI_DESCRIPTION = "The contract's liquidate* path asserts that a stored positionValue / collateralValue crosses a liquidation threshold, but does not refresh the underlying Uni v3 liquidity / realised profit of the collateral position before evaluating. Because the stored value and the liquidity/profit diverge, a liquidatable borrower can frontrun the keeper in one of two ways: (a) deposit a newly-minted Uni v3 posi"
    WIKI_EXPLOIT_SCENARIO = "Borrower B has an under-water position that a keeper K is about to liquidate. B observes K's pending tx in the mempool. B mints a fresh Uni v3 NFT at a range far away from the current tick with zero liquidity (cost ~0) and calls depositCollateral(nft) in the same block ahead of K. The protocol's liquidation path now reads positionValue that includes the (effectively worthless) NFT; its liquidation"
    WIKI_RECOMMENDATION = "Always compute the CURRENT liquidity / CURRENT mark value of each collateral component at liquidation time — call a refreshPosition / updateCollateral / getActiveLiquidity hook before comparing against the threshold. For Uni v3 LP collateral: resolve the (liquidity, fee growth) tuple from the NFT ma"

    _PRECONDITIONS = [{'contract.source_matches_regex': '.*'}, {'contract.has_state_var_matching': 'position|collateral|vault|liquidation'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': 'liquidate|_liquidate|liquidatePosition'}, {'function.body_contains_regex': 'positionValue|collateralValue|getCollateral|getPosition'}, {'function.body_not_contains_regex': 'updateCollateral|refreshPosition|_refreshLiquidity|getActiveLiquidity|currentLiquidity'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — liquidation-escape-uni-v3-zero-liquidity: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
