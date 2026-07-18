"""
dust-redeem-floor-rounds-to-zero — generated from reference/patterns.dsl/dust-redeem-floor-rounds-to-zero.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py dust-redeem-floor-rounds-to-zero.yaml
Source: solodit/dust-redeem-zero-output-class
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class DustRedeemFloorRoundsToZero(AbstractDetector):
    ARGUMENT = "dust-redeem-floor-rounds-to-zero"
    HELP = "Redeem/withdraw/unstake truncates `shares * total / supply` to zero for small shares and doesn't revert on zero output; caller burns shares for nothing."
    IMPACT = DetectorClassification.LOW
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/dust-redeem-floor-rounds-to-zero.yaml"
    WIKI_TITLE = "Dust redeem floors to zero without a zero-output revert"
    WIKI_DESCRIPTION = "The exit function computes `amount = shares * total / supply` with integer floor division. When `shares * total < supply`, the integer result is zero. The function proceeds to burn the caller's shares, debit state, and transfer zero tokens — a silent loss. Distinct from the broader vault-dust-shares-withdraw pattern: here the narrow diagnostic is the absence of a revert-on-zero-output guard, so ev"
    WIKI_EXPLOIT_SCENARIO = "A user holds 1 share in a staking contract where totalSupply = 1e18 and the underlying pool has 9e17 tokens. They call `redeem(1)`. The contract computes `amount = 1 * 9e17 / 1e18 = 0`, burns the user's 1 share, and transfers 0 tokens. The user's share is destroyed for nothing. Dust balances left from migrations, airdrop fragments, or rebase rounding accumulate to meaningful losses across a large "
    WIKI_RECOMMENDATION = "Add an explicit `require(amount > 0, \"ZeroAmount\")` (or `revert ZeroAmount()` / `revert NoValue()`) immediately after computing `amount` and before burning shares. This forces dust redeems to revert loudly instead of silently destroying the caller's position. A ceil-rounding refactor is orthogonal"

    _PRECONDITIONS = [{'contract.source_matches_regex': '.*'}, {'contract.has_state_var_matching': 'shares|totalSupply|totalAssets'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': 'redeem|_redeem|withdraw|unstake|cashOut'}, {'function.body_contains_regex': 'shares\\s*\\*\\s*total|_shares\\s*\\*\\s*total|shares\\s*\\*\\s*_total'}, {'function.body_not_contains_regex': 'require\\s*\\(\\s*assets?\\s*>\\s*0|require\\s*\\(.*amount\\s*>\\s*0|revert\\s+ZeroAmount|revert\\s+NoValue|if\\s*\\(\\s*amount\\s*==\\s*0\\s*\\)\\s*(return\\s*;|revert)'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — dust-redeem-floor-rounds-to-zero: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
