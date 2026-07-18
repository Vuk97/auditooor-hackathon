"""
dh-paribus-liquidation-borrower-chosen-repay-token — generated from reference/patterns.dsl/dh-paribus-liquidation-borrower-chosen-repay-token.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py dh-paribus-liquidation-borrower-chosen-repay-token.yaml
Source: defihacklabs/Paribus-2025-01+Venus-THE-2025-12
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class DhParibusLiquidationBorrowerChosenRepayToken(AbstractDetector):
    ARGUMENT = "dh-paribus-liquidation-borrower-chosen-repay-token"
    HELP = "Liquidation accepts a caller-supplied repay-asset without verifying the victim actually borrowed it."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.LOW
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/dh-paribus-liquidation-borrower-chosen-repay-token.yaml"
    WIKI_TITLE = "Liquidation trusts caller-supplied repay token"
    WIKI_DESCRIPTION = "Compound-fork markets require liquidation to specify the borrow asset being repaid. Without validating that `victim.borrowBalanceOf(repayAsset) > 0` and `repayAsset` is in the victim's `accountAssets`, attacker can pass an arbitrary cToken and trigger the liquidation bonus for collateral seizure without real repayment economics."
    WIKI_EXPLOIT_SCENARIO = "Paribus 2025-01 / Venus THE 2025-12: liquidation function accepted `repayCToken` param and transferred seizure collateral based on `seizeTokens = f(repayAmount, price[repay], price[collateral])`. Attacker passed a thinly-traded cToken with manipulable price, repaid trivial amount, seized heavy collateral."
    WIKI_RECOMMENDATION = "`require(victim.borrowBalanceOf(repayCToken) > 0 && comptroller.markets(repayCToken).isListed)`. Also require repay cToken is in the victim's membership list."

    _PRECONDITIONS = [{'contract.source_matches_regex': 'liquidate|Comptroller|CToken'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': '^(liquidateBorrow|liquidate|forceLiquidate|seize)$'}, {'function.body_contains_regex': '(cTokenBorrowed|repayAsset|borrowAsset|repayToken)'}, {'function.body_not_contains_regex': 'borrowBalance\\s*\\(|accountAssets|getAccountLiquidity|isMember|markets\\[[^\\]]+\\]'}, {'function.not_in_skip_list': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — dh-paribus-liquidation-borrower-chosen-repay-token: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
