"""
mint-fee-rounds-to-zero — generated from reference/patterns.dsl/mint-fee-rounds-to-zero.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py mint-fee-rounds-to-zero.yaml
Source: solodit/fee-math
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class MintFeeRoundsToZero(AbstractDetector):
    ARGUMENT = "mint-fee-rounds-to-zero"
    HELP = "Basis-point fee computed as amount*bps/10000 rounds down to zero for small amounts, letting users mint/swap/withdraw fee-free by splitting into dust-sized calls."
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/mint-fee-rounds-to-zero.yaml"
    WIKI_TITLE = "Fee math rounds to zero: amount * bps / 10000 truncates for small inputs"
    WIKI_DESCRIPTION = "The function computes its fee with the standard basis-point formula amount * feeBps / 10000 (or similar) without a ceiling-rounding mitigation. Solidity integer division truncates toward zero, so any amount smaller than ceil(10000/feeBps) produces a zero fee. An attacker repeats the operation with dust-sized inputs to fully bypass protocol fees."
    WIKI_EXPLOIT_SCENARIO = "feeBps = 30 (0.30 percent). amount = 333 wei → 333 * 30 / 10000 = 0.999 → truncates to 0. The user calls mint()/swap()/withdraw() thousands of times with amount = 333 and pays zero fees total. Protocol loses all intended revenue; at scale this also enables griefing where the pool drains without compensation."
    WIKI_RECOMMENDATION = "Round the fee UP instead of down. Use (amount * feeBps + 9999) / 10000, OpenZeppelin Math.ceilDiv, or mulDivRoundingUp. Alternatively require amount >= minAmount where minAmount * feeBps >= 10000."

    _PRECONDITIONS = [{'contract.source_matches_regex': '.*'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.body_contains_regex': '\\*\\s*(feeBps|feeRate|bpsFee|mintFee|burnFee)\\s*\\/\\s*(10000|BPS_DIVISOR|BPS)|\\*\\s*fee(_e\\d+)?\\s*\\/'}, {'function.body_not_contains_regex': '\\+\\s*(10000|9999|BPS_DIVISOR\\s*-\\s*1|bps\\s*-\\s*1)\\s*\\)?\\s*\\/|Math\\.ceilDiv|mulDivRoundingUp|roundUp'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — mint-fee-rounds-to-zero: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
