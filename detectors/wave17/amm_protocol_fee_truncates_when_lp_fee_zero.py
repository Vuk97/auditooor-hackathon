"""
amm-protocol-fee-truncates-when-lp-fee-zero — generated from reference/patterns.dsl/amm-protocol-fee-truncates-when-lp-fee-zero.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py amm-protocol-fee-truncates-when-lp-fee-zero.yaml
Source: auditooor-R71-fixdiff-mined-uniswap-v4-38437343
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class AmmProtocolFeeTruncatesWhenLpFeeZero(AbstractDetector):
    ARGUMENT = "amm-protocol-fee-truncates-when-lp-fee-zero"
    HELP = "Protocol-fee share computed as `(amountIn + feeAmount) * protocolFee / PIPS` rounds down; when LP fee is zero the generic formula short-changes the protocol by 1 wei per step."
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/amm-protocol-fee-truncates-when-lp-fee-zero.yaml"
    WIKI_TITLE = "Protocol-fee share rounds down when LP fee is zero — protocol loses whole-fee entitlement"
    WIKI_DESCRIPTION = "AMM swap engines that split a combined swap fee into LP and protocol portions using `(amountIn + feeAmount) * protocolFee / PIPS_DENOMINATOR` rely on div-round-down. When LP fee is configured to zero (all fee goes to protocol) this formula mis-allocates the rounding residue to LPs — a single pip per swap step. Need special case: when `swapFee == protocolFee`, assign full feeAmount to protocol."
    WIKI_EXPLOIT_SCENARIO = "Uniswap v4 PR #905: pool with lpFee=0 and 100-pip protocol fee. Over N swap steps, protocol under-paid by up to N pips; at volume, accumulated leak is non-trivial and favors LPs."
    WIKI_RECOMMENDATION = "When `swapFee == protocolFee` (lpFee == 0), bypass the generic formula: `delta = step.feeAmount`. Otherwise use the generic rounded-down split."

    _PRECONDITIONS = [{'contract.source_matches_regex': '.*'}]
    _MATCH = [{'function.kind': 'internal'}, {'function.name_matches': '^(swap|_swap|computeSwap|swapStep)'}, {'function.body_contains_regex': 'protocolFee\\s*\\/\\s*(PIPS|1_?000_?000|1e6)|\\*\\s*protocolFee\\s*\\/'}, {'function.body_contains_regex': 'amountIn\\s*\\+\\s*feeAmount|step\\.amountIn\\s*\\+\\s*step\\.feeAmount'}, {'function.body_not_contains_regex': 'swapFee\\s*==\\s*protocolFee|lpFee\\s*==\\s*0\\s*\\?.*feeAmount'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — amm-protocol-fee-truncates-when-lp-fee-zero: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
