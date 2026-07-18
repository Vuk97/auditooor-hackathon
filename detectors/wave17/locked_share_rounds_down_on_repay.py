"""
locked-share-rounds-down-on-repay — generated from reference/patterns.dsl/locked-share-rounds-down-on-repay.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py locked-share-rounds-down-on-repay.yaml
Source: solodit/sherlock/jojo-exchange-H2-30140
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class LockedShareRoundsDownOnRepay(AbstractDetector):
    ARGUMENT = "locked-share-rounds-down-on-repay"
    HELP = "Locked-shares calculation against outstanding debt rounds DOWN, letting a user repay 1 wei of debt and walk away with all their collateral shares while still owing debt. With a non-trivial share price, this drains the pool."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/locked-share-rounds-down-on-repay.yaml"
    WIKI_TITLE = "Rounding direction: lockedShares = debt / price rounded DOWN lets tiny repay free full collateral"
    WIKI_DESCRIPTION = "A lending / arbitrage / vault contract lets users request partial withdrawals after partial debt repayment. The amount of collateral that must remain locked against the residual debt is computed as `locked = debt.decimalDiv(price)` with default floor rounding. For small residual debt or high share price, this quotient rounds to zero — the contract 'locks' no shares — and the user withdraws all of "
    WIKI_EXPLOIT_SCENARIO = "Attacker deposits 1 wei USDC → 1 share. Transfers $100 USDC directly to the contract; share price = $100. Opens a new account, deposits $101, mints 1 share, borrows $100 JUSD. Calls `requestWithdraw(repayJUSDAmount=1)`. `lockedShares = 1 / index = 0` (floor). `withdrawEarnUSDCAmount = 1 - 0 = 1` share = $100. Attacker burns 1 wei JUSD, exits with $100 USDC, still holds the debt position. Repeats a"
    WIKI_RECOMMENDATION = "For any quantity that constrains the user's future claim (locked collateral, owed shares, required deposit), round UP — `Math.ceilDiv(debt, index)` or `(debt + index - 1) / index`. Add an invariant test: after partial repay, total remaining claim + just-repaid should never exceed pre-tx claim."

    _PRECONDITIONS = [{'contract.source_matches_regex': '.*'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': '^(requestWithdraw|requestWithdrawAmount|withdrawMax|withdrawMaxAmount|withdrawAgainst|withdrawAgainstDebt|redeemLocked|redeemLockedShares|partialRedeem|partialRedeemShares|repayAndWithdraw|repayAndRedeem)$'}, {'function.body_contains_regex': '(lockedShares|locked\\w*Amount|remainingShares|requiredShares)\\s*=\\s*\\w+\\s*[./]\\s*\\w+|\\.decimalDiv\\s*\\(|\\.mulDiv\\s*\\([^)]*Rounding\\.(Down|Zero|Trunc)'}, {'function.body_not_contains_regex': 'divCeil|ceilDiv|mulDivUp|Math\\.ceilDiv|Rounding\\.Up|\\+\\s*\\(\\w+\\s*-\\s*1\\)\\s*\\)\\s*/'}, {'function.body_contains_regex': 'withdraw\\w*\\s*=\\s*\\w+\\s*-\\s*lockedShares|-\\s*required\\w*|-\\s*remaining\\w*'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — locked-share-rounds-down-on-repay: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
