"""
integer-clamp-fee-or-debt-underflow-boundary - generated from reference/patterns.dsl/integer-clamp-fee-or-debt-underflow-boundary.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py integer-clamp-fee-or-debt-underflow-boundary.yaml
Source: auditooor-fire5-rwrq-integer-overflow-clamp-1b7ebd28e8e6
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class IntegerClampFeeOrDebtUnderflowBoundary(AbstractDetector):
    ARGUMENT = "integer-clamp-fee-or-debt-underflow-boundary"
    HELP = "Fee split or debt decay arithmetic drops a boundary clamp: all-protocol-fee swaps with an LP-fee boundary still use rounded division, or debt decay subtracts below zero."
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/integer-clamp-fee-or-debt-underflow-boundary.yaml"
    WIKI_TITLE = "Integer clamp loss in fee split or debt decay boundary"
    WIKI_DESCRIPTION = "Confirmed integer-overflow-clamp samples share a narrow boundary arithmetic shape. One AMM path with an LP-fee boundary computes protocol fee through a rounded generic split even when the LP fee is zero and the protocol should receive the whole fee. One bond path subtracts time-decayed debt without flooring at zero."
    WIKI_EXPLOIT_SCENARIO = "A swap step with lpFee=0 sends the all-protocol-fee case through `(amountIn + feeAmount) * protocolFee / PIPS_DENOMINATOR`, leaking rounding residue. Separately, a quiet bond market computes `lastDebt - decay` or `totalDebt -= decay` after decay exceeds debt, reverting the path instead of saturating to zero."
    WIKI_RECOMMENDATION = "Special-case all-protocol-fee swaps so the protocol receives the full `feeAmount`. Use saturating debt decay with a ternary floor, `Math.min`, or an equivalent guard before subtracting."

    _PRECONDITIONS = [{'contract.source_matches_regex': '(?i)(protocolFee|lpFee|PIPS|feeAmount|totalDebt|lastDebt|debt|decay|bond|market)'}]
    _MATCH = [{'function.kind': 'any'}, {'function.name_matches': '(?i)^(quote|swap|_swap|computeSwap|swapStep|debtDecay|_currentDebt|_decayDebt|marketPrice|_marketPrice|findMarketFor|_updateDebt|totalDebt)\\w*$'}, {'function.body_contains_regex': '(?is)(((?=[\\s\\S]*\\b(lpFee|swapFee)\\b)[\\s\\S]*?((amountIn|step\\.amountIn)\\s*\\+\\s*(feeAmount|step\\.feeAmount)[^;]*\\*\\s*protocolFee\\s*\\/\\s*(PIPS|PIPS_DENOMINATOR|1_?000_?000|1e6)|\\*\\s*protocolFee\\s*\\/\\s*(PIPS|PIPS_DENOMINATOR|1_?000_?000|1e6)))|debt\\s*-\\s*decay|lastDebt\\s*-\\s*decay|totalDebt\\s*-=\\s*decay)'}, {'function.body_contains_regex': '(?is)(protocolFee|feeAmount|amountIn|totalDebt|lastDebt|debt|decay)'}, {'function.body_not_contains_regex': '(?is)(swapFee\\s*==\\s*protocolFee|lpFee\\s*==\\s*0\\s*\\?.*feeAmount|Math\\.min\\s*\\(|ClampMath\\.min\\s*\\(|saturat|decay\\s*>\\s*(lastDebt|debt|market\\.totalDebt)\\s*\\?|if\\s*\\([^)]*(lastDebt|debt|market\\.totalDebt)\\s*>=\\s*decay|if\\s*\\([^)]*decay\\s*>=\\s*(lastDebt|debt|market\\.totalDebt))'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" - integer-clamp-fee-or-debt-underflow-boundary: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
