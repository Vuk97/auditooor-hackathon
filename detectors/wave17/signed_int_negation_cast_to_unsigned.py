"""
signed-int-negation-cast-to-unsigned — generated from reference/patterns.dsl/signed-int-negation-cast-to-unsigned.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py signed-int-negation-cast-to-unsigned.yaml
Source: auditooor-R75-nethermind-panoptic-v2-MEDIUM
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class SignedIntNegationCastToUnsigned(AbstractDetector):
    ARGUMENT = "signed-int-negation-cast-to-unsigned"
    HELP = "Code that expects a signed value to always be negative (e.g., a fee that charges the caller) and extracts its magnitude as `uint128(-signedFee)` silently corrupts when the signed value is actually positive: `-fee` underflows into a very-large-positive 2's complement value, which then propagates as a"
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.HIGH
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/signed-int-negation-cast-to-unsigned.yaml"
    WIKI_TITLE = "Unchecked negate-and-cast of signed fee to unsigned produces 2^128-sized pseudo-magnitudes"
    WIKI_DESCRIPTION = "Protocols often encode a sign convention ('negative fee = caller pays, positive fee = caller receives') and then use `uint128(-fee)` to obtain the magnitude in the caller-pays path. If protocol invariants guarantee the fee is always negative in that path, the cast works. But when a boundary case (e.g., a favorable oracle-vs-spot relation) produces a positive fee, `-positive` becomes negative, and "
    WIKI_EXPLOIT_SCENARIO = "Panoptic-V2 getRefundAmounts expects fees.rightSlot() to be negative for forced exercises. During unusual market conditions (deep OTM + funding regime), the computed fee is +50. `uint128(-50)` = 2^128 - 50. `ct0.convertToShares(2^128-50)` returns a huge shares count. `balanceShortage = uint248.max - balanceOf - hugeShares` yields a large negative. `if (balanceShortage > 0)` is false, so the refund"
    WIKI_RECOMMENDATION = "Before negate-and-cast, assert the sign convention: `require(fee < 0); uint128 mag = uint128(uint256(-int256(fee)));`. Better: use a dedicated helper `absU128(int128)` that branches on sign and returns 0 (or reverts) in the unexpected-sign case."

    _PRECONDITIONS = [{'contract.source_matches_regex': '(LeftRightSigned|int128|int256).*fee'}]
    _MATCH = [{'function.kind': 'internal_or_external'}, {'function.name_matches': '(?i)^(getRefundAmounts|_?refund\\w*|_?settle\\w*|_?collect\\w*|_?charge\\w*|_?applyFee\\w*|_?compute\\w*Fee\\w*|_?feeDelta\\w*|_?accrue\\w*|_?update\\w*Fee\\w*|_?forceExercise\\w*|_?exercise\\w*|_?burn\\w*|_?mint\\w*|_?premium\\w*)'}, {'function.body_contains_regex': 'uint(8|16|32|64|128|256)\\s*\\(\\s*-\\s*[a-zA-Z_][a-zA-Z_0-9]*(fees?|delta|premium)[^)]*\\)'}, {'function.body_not_contains_regex': 'require\\s*\\(\\s*[a-zA-Z_][a-zA-Z_0-9]*(fees?|delta|premium)[^)]*<\\s*0'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — signed-int-negation-cast-to-unsigned: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
