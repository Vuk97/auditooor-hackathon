"""
unchecked-overflow-wrap-int128-multiplication-before-cast — generated from reference/patterns.dsl/unchecked-overflow-wrap-int128-multiplication-before-cast.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py unchecked-overflow-wrap-int128-multiplication-before-cast.yaml
Source: auditooor-R75-nethermind-panoptic-v2-MEDIUM
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class UncheckedOverflowWrapInt128MultiplicationBeforeCast(AbstractDetector):
    ARGUMENT = "unchecked-overflow-wrap-int128-multiplication-before-cast"
    HELP = "Inside an `unchecked` block, `int256(x.rightSlot() * 2**64)` first computes the multiplication in the narrower int128 type (because both operands fit in int128) and only widens to int256 afterwards. For x > 2^63-1 (~9.22e18) this overflows int128, wraps to a large negative, then the cast propagates "
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.HIGH
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/unchecked-overflow-wrap-int128-multiplication-before-cast.yaml"
    WIKI_TITLE = "int128 operand multiplied before widening cast — overflow wraps inside unchecked"
    WIKI_DESCRIPTION = "Solidity infers the arithmetic type from the operand type. `int128_var * 2**64` executes in int128 because the literal 2**64 fits. Under an `unchecked` block (common for gas in tick-math code), multiplication silently wraps; the subsequent outer int256() cast preserves the wrapped negative. The correct idiom is `int256(int128_var) * 2**64` (cast the variable FIRST, so the multiplication is done in"
    WIKI_EXPLOIT_SCENARIO = "Panoptic's _updateSettlementPostBurn computes `int256(legPremia.rightSlot() * 2**64)`. When legPremia.rightSlot() > 2^63-1 (reachable on long-lived heavily-utilized options chunks), the multiplication wraps, the cast keeps the negative, the next `Math.max(..., 0)` clamps the running grossPremiumLast to 0. Subsequent premium claims compute `totalLiquidity * (grossAccumulator - 0)` — wildly over-cre"
    WIKI_RECOMMENDATION = "Always widen operands before multiplying: write `int256(x.rightSlot()) * 2**64` (or use OpenZeppelin SafeCast and remove the unchecked). Add a lint rule or Slither detector that flags `int256(.{1,50} \\* 2 \\*\\* \\d+)` inside unchecked scopes."

    _PRECONDITIONS = [{'contract.source_matches_regex': '(unchecked|int128|int256).*2\\s*\\*\\*\\s*64|2\\s*\\*\\*\\s*64.*(unchecked|int128|int256)'}]
    _MATCH = [{'function.kind': 'internal_or_external'}, {'function.name_matches': '(?i)^(_?updateSettlement\\w*|_?updatePremium\\w*|_?accruePremium\\w*|_?settlePremium\\w*|_?computePremium\\w*|_?premiumAccumulator\\w*|_?grossPremium\\w*|_?premia\\w*|_?updateChunk\\w*|_?mintPosition\\w*|_?burnPosition\\w*|_?roll\\w*)'}, {'function.body_contains_regex': 'int256\\s*\\(\\s*[a-zA-Z_][a-zA-Z_0-9.()]*\\.(rightSlot|leftSlot|slot[0-9])\\s*\\(\\s*\\)\\s*\\*\\s*2\\s*\\*\\*\\s*64\\s*\\)'}, {'function.body_not_contains_regex': 'int256\\s*\\(\\s*[a-zA-Z_][a-zA-Z_0-9.()]*\\.(rightSlot|leftSlot)\\s*\\(\\s*\\)\\s*\\)\\s*\\*\\s*(int256\\s*\\()?\\s*2\\s*\\*\\*\\s*64'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — unchecked-overflow-wrap-int128-multiplication-before-cast: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
