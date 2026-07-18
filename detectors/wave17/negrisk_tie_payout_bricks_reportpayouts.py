"""
negrisk-tie-payout-bricks-reportpayouts — generated from reference/patterns.dsl/negrisk-tie-payout-bricks-reportpayouts.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py negrisk-tie-payout-bricks-reportpayouts.yaml
Source: auditooor-R77-polymarket-UmaCtfAdapter-constructPayouts
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class NegriskTiePayoutBricksReportpayouts(AbstractDetector):
    ARGUMENT = "negrisk-tie-payout-bricks-reportpayouts"
    HELP = "Literal tie-sentinel detector for UMA-style `_constructPayouts` helpers that map `0.5 ether` to `[1,1]` without a visible NegRisk/tie guard."
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.HIGH
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/negrisk-tie-payout-bricks-reportpayouts.yaml"
    WIKI_TITLE = "Tie-payout [1,1] from UMA adapter permanently bricks NegRisk-backed markets"
    WIKI_DESCRIPTION = "Fixture-smoke/source-shape proof only: this row matches a payouts helper that explicitly branches on UMA's `0.5 ether` tie/unknown sentinel and emits `[1,1]` without a visible `isNegRisk` / `allowTies` / tie-revert guard. That shape is enough to brick a NegRisk-style downstream consumer that enforces `payout0 + payout1 == 1`, but this detector is still NOT_SUBMIT_READY until corpus-backed exploit "
    WIKI_EXPLOIT_SCENARIO = "A NegRisk-backed adapter resolves through UMA. The DVM returns `0.5 ether` for an ambiguous outcome. `_constructPayouts(0.5 ether)` emits `[1,1]`, the downstream `reportPayouts` enforces `payout0 + payout1 == 1`, and `resolve()` reverts every time. A clean build adds an explicit tie/NegRisk guard in the same helper so the bad vector is never returned."
    WIKI_RECOMMENDATION = "Add a same-helper guard for the tie branch when the adapter can feed a NegRisk-style consumer. For example, gate `price == 0.5 ether` on `allowTies` / `isNegRisk`, or revert with a dedicated tie-unsupported error before returning `[1,1]`. Keep this row NOT_SUBMIT_READY until validation extends beyon"

    _PRECONDITIONS = [{'contract.has_function_matching': '(?i)_?constructPayouts|_?buildPayouts'}, {'contract.source_matches_regex': '(?i)(0\\.5\\s*ether|5[eE]17|UNKNOWN|tie)'}]
    _MATCH = [{'function.kind': 'any'}, {'function.name_matches': '(?i)_?constructPayouts|_?buildPayouts'}, {'function.body_contains_regex': '(?i)(price\\s*!=\\s*0\\s*&&\\s*price\\s*!=\\s*0\\.5\\s*ether\\s*&&\\s*price\\s*!=\\s*1\\s*ether|price\\s*==\\s*0\\.5\\s*ether|price\\s*==\\s*5[eE]17)'}, {'function.body_contains_regex': '(?is)(?:else\\s+if|if)\\s*\\(\\s*price\\s*==\\s*(?:0\\.5\\s*ether|5[eE]17)\\s*\\)\\s*\\{[\\s\\S]{0,220}?payouts\\s*\\[\\s*0\\s*\\]\\s*=\\s*1\\s*;[\\s\\S]{0,120}?payouts\\s*\\[\\s*1\\s*\\]\\s*=\\s*1'}, {'function.body_not_contains_regex': '(?i)(allowTies|isNegRisk|tie unsupported|TieUnsupported|sum of payouts|payouts\\s*\\[\\s*0\\s*\\]\\s*\\+\\s*payouts\\s*\\[\\s*1\\s*\\]\\s*(?:==|!=|>=|<=)\\s*1|payout0\\s*\\+\\s*payout1\\s*(?:==|!=|>=|<=)\\s*1)'}, {'function.not_in_skip_list': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)\\b'}]

    _INCLUDE_LEAF_HELPERS = True
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
                info = [f, f" — negrisk-tie-payout-bricks-reportpayouts: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
