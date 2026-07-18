"""
first-deposit-revert-uninitialized-share-math — generated from reference/patterns.dsl/first-deposit-revert-uninitialized-share-math.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py first-deposit-revert-uninitialized-share-math.yaml
Source: auditooor-R75-c4-lending-wise-lending-191
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class FirstDepositRevertUninitializedShareMath(AbstractDetector):
    ARGUMENT = "first-deposit-revert-uninitialized-share-math"
    HELP = "Share-calc uses division by `totalPool` without a zero-case branch. First depositor in a fresh pool always reverts, pool is bricked unless contract has a seed/init path."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/first-deposit-revert-uninitialized-share-math.yaml"
    WIKI_TITLE = "Empty-pool bootstrap reverts on division by zero, market unusable"
    WIKI_DESCRIPTION = "Standard share-conversion math `shares = amount * totalShares / totalPool` requires `totalPool > 0`. For a freshly-deployed market, both `totalShares` and `totalPool` are zero. Solidity's integer division reverts on zero divisor. Unless the share calculation has an `if (totalPool == 0) return amount;` branch, or a dead-shares seeding pattern (ERC4626 virtual assets), any first-depositor call rever"
    WIKI_EXPLOIT_SCENARIO = "Wise Lending deploys a new USDC pool. Alice calls `depositExactAmount(nftId, USDC, 1000e6)`. Inside `_calculateShares`: `shares = 1000e6 * 0 / 0 = ???` → div-by-zero revert. No one can use the pool. Same symptom if the pool is later drained (e.g. via liquidation) to `totalPool = 0` — market permanently bricked."
    WIKI_RECOMMENDATION = "Add empty-pool branch: `if (totalPool == 0 || totalShares == 0) return amount;` (1:1 for first deposit). Additionally, burn a small number of dead shares on first deposit (ERC4626 Boring-style virtual assets / shares: OZ ERC4626Upgradeable's decimalsOffset) to prevent the post-fix inflation-donation"

    _PRECONDITIONS = [{'contract.source_matches_regex': '(?i)(pseudoTotalPool|totalLpAssets|totalAssets\\(\\))'}]
    _MATCH = [{'function.kind': 'internal_or_external'}, {'function.name_matches': '(?i)^(_?calculateShares|_?convertToShares|_?sharesForDeposit)'}, {'function.has_high_level_call_named': 'totalSupply'}, {'function.has_high_level_call_named': 'totalSupply'}, {'function.has_high_level_call_named': 'totalSupply'}, {'function.has_high_level_call_named': 'totalSupply'}, {'function.has_high_level_call_named': 'totalSupply'}, {'function.has_high_level_call_named': 'totalSupply'}, {'function.has_high_level_call_named': 'totalSupply'}, {'function.body_contains_regex': '(?i)(\\*\\s*totalShares|\\*\\s*_totalSupply|\\*\\s*totalAssets\\(\\))\\s*/\\s*(pseudoTotalPool|totalPool|underlyingLpAssetsCurrent|totalAssets)'}, {'function.body_not_contains_regex': '(?i)(totalSupply\\(\\)\\s*==\\s*0|totalShares\\s*==\\s*0|pseudoTotalPool\\s*==\\s*0|_totalSupply\\s*==\\s*0|if\\s*\\(\\s*totalAssets\\s*==\\s*0\\s*\\)\\s*return|DEAD_SHARES|VIRTUAL_SHARES)'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — first-deposit-revert-uninitialized-share-math: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
