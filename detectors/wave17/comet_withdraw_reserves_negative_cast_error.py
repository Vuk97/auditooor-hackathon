"""
comet-withdraw-reserves-negative-cast-error — generated from reference/patterns.dsl/comet-withdraw-reserves-negative-cast-error.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py comet-withdraw-reserves-negative-cast-error.yaml
Source: auditooor-R71-fixdiff-mined-compound-comet-a2a494529
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class CometWithdrawReservesNegativeCastError(AbstractDetector):
    ARGUMENT = "comet-withdraw-reserves-negative-cast-error"
    HELP = "withdrawReserves compares `amount > unsigned256(getReserves())` without first checking `reserves < 0`. When reserves are negative, the signed-to-unsigned cast reverts with a generic NegativeNumber error before the specific InsufficientReserves branch fires — masking the real condition and breaking g"
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/comet-withdraw-reserves-negative-cast-error.yaml"
    WIKI_TITLE = "Reserve-withdraw casts negative reserves to uint without guard"
    WIKI_DESCRIPTION = "`getReserves()` on a Comet-style market returns an `int256` because accrued supplier interest can temporarily exceed the `baseToken.balanceOf(this)` plus borrow credits, producing negative reserves. Casting this value to `uint256` (via `unsigned256`, an `uint()` cast, or `SafeCast.toUint256`) reverts whenever the value is negative. If `withdrawReserves` performs the cast before checking the sign, "
    WIKI_EXPLOIT_SCENARIO = "A market has temporarily accrued into negative reserves during a volatile block. Governance attempts `withdrawReserves(1e6)` — the intended behaviour is a clean revert with `InsufficientReserves()` so the proposer knows to retry after the market stabilises. Instead, `unsigned256(getReserves())` reverts inside the SafeCast library with `NegativeNumber()`, which propagates up through the timelock. A"
    WIKI_RECOMMENDATION = "Add the explicit sign check first: `int reserves = getReserves(); if (reserves < 0 || amount > unsigned256(reserves)) revert InsufficientReserves();`. Preserve the single custom error across both overflow and cast paths. Audit every place in the codebase where a signed balance/reserve is cast unsign"

    _PRECONDITIONS = [{'contract.source_matches_regex': 'getReserves|totalReserves|InsufficientReserves|NegativeNumber'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.is_mutating': True}, {'function.name_matches': '^(withdrawReserves|claimReserves|rescueReserves|drainReserves)$'}, {'function.body_contains_regex': 'unsigned256\\s*\\(\\s*getReserves\\s*\\(\\s*\\)\\s*\\)|uint\\s*\\(\\s*getReserves\\s*\\(\\s*\\)\\s*\\)|uint256\\s*\\(\\s*getReserves\\s*\\(\\s*\\)\\s*\\)'}, {'function.body_not_contains_regex': 'reserves\\s*<\\s*0|getReserves\\s*\\(\\s*\\)\\s*<\\s*0|InsufficientReserves'}, {'function.not_in_skip_list': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — comet-withdraw-reserves-negative-cast-error: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
