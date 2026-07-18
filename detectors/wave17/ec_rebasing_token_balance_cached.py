"""
ec-rebasing-token-balance-cached — generated from reference/patterns.dsl/ec-rebasing-token-balance-cached.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py ec-rebasing-token-balance-cached.yaml
Source: economic-mining-R61
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class EcRebasingTokenBalanceCached(AbstractDetector):
    ARGUMENT = "ec-rebasing-token-balance-cached"
    HELP = "Rebasing token (stETH/aToken) balance cached at deposit time; rebase events cause cached vs live balance divergence enabling over/under withdrawal."
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/ec-rebasing-token-balance-cached.yaml"
    WIKI_TITLE = "Rebasing token balance cached — stETH/aToken rebase not accounted for"
    WIKI_DESCRIPTION = "The contract stores a token amount at deposit time and uses this cached value for subsequent withdrawals or collateral valuations. For rebasing tokens (stETH, Aave aTokens, elastic supply tokens), the actual held balance changes each day via protocol-level rebases. The cached deposit amount diverges from the real balance: after a positive rebase, users can withdraw more than deposited; after a sla"
    WIKI_EXPLOIT_SCENARIO = "User deposits 100 stETH. Contract stores userDeposit[user] = 100e18. 30 days pass, stETH rebases +3%. Contract holds 103 stETH. User calls withdraw(). Contract transfers storedAmount = 100 stETH. Other users lose the 3 extra stETH that the first user should have received proportionally."
    WIKI_RECOMMENDATION = "For rebasing tokens, store shares (not amounts). For stETH: store IStETH.getSharesByPooledEth(amount) at deposit, and convert back via IStETH.getPooledEthByShares(shares) at withdrawal. For Aave aTokens: use aToken.scaledBalanceOf() at deposit."

    _PRECONDITIONS = [{'contract.source_matches_regex': 'stETH|aToken|rebase|elastic|shares\\b'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.body_contains_regex': 'deposited\\[|userDeposit\\[|cachedBalance\\[|storedAmount\\['}, {'function.body_contains_regex': 'deposited\\[\\w+\\]|userDeposit\\[\\w+\\]|cachedBalance\\[\\w+\\]'}, {'function.body_not_contains_regex': 'balanceOf\\s*\\(\\s*address\\s*\\(\\s*this\\s*\\)\\s*\\)|balanceOf\\s*\\(msg\\.sender\\)|live.*balance|current.*balance'}, {'contract.source_matches_regex': 'stETH|aToken|IRebaseToken|elastic|rebas'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — ec-rebasing-token-balance-cached: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
