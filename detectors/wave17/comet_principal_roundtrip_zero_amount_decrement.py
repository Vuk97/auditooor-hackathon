"""
comet-principal-roundtrip-zero-amount-decrement — generated from reference/patterns.dsl/comet-principal-roundtrip-zero-amount-decrement.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py comet-principal-roundtrip-zero-amount-decrement.yaml
Source: auditooor-R71-fixdiff-mined-compound-comet-bf20ccfa9
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class CometPrincipalRoundtripZeroAmountDecrement(AbstractDetector):
    ARGUMENT = "comet-principal-roundtrip-zero-amount-decrement"
    HELP = "Helper splitting a principal delta into repay/supply (or withdraw/borrow) components assumes `newPrincipal >= oldPrincipal` (or the symmetric inverse). When both `principalValue` and `presentValue` round toward the protocol, a zero-amount operation can produce `newPrincipal < oldPrincipal`, underflo"
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/comet-principal-roundtrip-zero-amount-decrement.yaml"
    WIKI_TITLE = "Principal-delta split helper underflows on rounding-induced decrement"
    WIKI_DESCRIPTION = "Comet-style markets encode user balances as `int104 principal` scaled by `baseSupplyIndex` / `baseBorrowIndex`. A pair of internal helpers — `repayAndSupplyAmount(oldPrincipal, newPrincipal)` and `withdrawAndBorrowAmount(oldPrincipal, newPrincipal)` — break a principal delta into the `(repay, supply)` or `(withdraw, borrow)` pair used to update `totalSupplyBase` and `totalBorrowBase`. The helpers "
    WIKI_EXPLOIT_SCENARIO = "Comet's `supplyBase` computed `dstPrincipalNew = principalValue(presentValue(dstPrincipal) + signed104(amount))` with `amount = 0`. Rounding losses produced `dstPrincipalNew < dstPrincipal`. Inside `repayAndSupplyAmount`, the branch `if (oldPrincipal >= 0) return (0, uint104(newPrincipal - oldPrincipal))` ran with `newPrincipal - oldPrincipal = -1`, underflowing to a near-max uint104 that was then"
    WIKI_RECOMMENDATION = "Never rely on monotonicity of `principalValue(presentValue(x))` — it is a strict downward mapping that can move the fixed point by one unit. Every helper that computes a delta across principal round-trips must either (a) clamp: `if (newPrincipal < oldPrincipal) return (0,0)` / `if (newPrincipal > ol"

    _PRECONDITIONS = [{'contract.source_matches_regex': 'principalValue|presentValue|baseSupplyIndex|baseBorrowIndex'}]
    _MATCH = [{'function.kind': 'internal'}, {'function.name_matches': '^(repayAndSupplyAmount|withdrawAndBorrowAmount|applyDelta|splitRepayAndSupply|splitWithdrawAndBorrow)$'}, {'function.body_contains_regex': 'newPrincipal\\s*<=\\s*0|newPrincipal\\s*>=\\s*0|oldPrincipal\\s*>=\\s*0|oldPrincipal\\s*<=\\s*0'}, {'function.body_not_contains_regex': 'if\\s*\\(\\s*newPrincipal\\s*<\\s*oldPrincipal\\s*\\)\\s*return|if\\s*\\(\\s*newPrincipal\\s*>\\s*oldPrincipal\\s*\\)\\s*return|return\\s*\\(\\s*0\\s*,\\s*0\\s*\\)'}, {'function.not_in_skip_list': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — comet-principal-roundtrip-zero-amount-decrement: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
