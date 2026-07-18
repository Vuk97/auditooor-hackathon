"""
interest-index-compound-vs-pool-simple-mismatch — generated from reference/patterns.dsl/interest-index-compound-vs-pool-simple-mismatch.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py interest-index-compound-vs-pool-simple-mismatch.yaml
Source: auditooor-R73-code4rena-2024-07-loopfi-95
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class InterestIndexCompoundVsPoolSimpleMismatch(AbstractDetector):
    ARGUMENT = "interest-index-compound-vs-pool-simple-mismatch"
    HELP = "Per-position compounding index multiplied against a pool using simple-interest accrual — divergence accumulates and breaks the expectedLiquidity invariant."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/interest-index-compound-vs-pool-simple-mismatch.yaml"
    WIKI_TITLE = "Interest index compounds per-position while pool accrues linearly"
    WIKI_DESCRIPTION = "When the pool computes `expectedLiquidity += borrowed * rate * dt` (simple/linear) but per-position debt reads `debt * indexNow / indexPast` with `indexNow = indexPrev * (1 + rate*dt)` (compound), positions accrue more interest than the pool expects. The gap widens with each update; once borrowers repay the excess interest, `expectedLiquidity` underflows during subsequent withdrawals."
    WIKI_EXPLOIT_SCENARIO = "At t=0 borrower has 100 debt, index=1e27. Pool expects 100 * rate * 365d of interest. After 10 updates per year, the position's index path compounds an extra ~0.5% over the linear prediction. When the borrower repays the compound amount, the pool's expectedLiquidity gets a delta larger than its own linear accrual, pushing it above actual availableLiquidity — next withdrawer reverts."
    WIKI_RECOMMENDATION = "Use one accrual model. Either (a) compute `expectedLiquidity` using the same compounding index that positions read, or (b) switch the position math to linear. Add an invariant test: after arbitrary sequences of borrow/repay/warp, `|expectedLiquidity - sum(positionDebt) - sum(suppliedAssets)| < dust`"

    _PRECONDITIONS = [{'contract.source_matches_regex': '.*'}]
    _MATCH = [{'function.kind': 'internal_or_external'}, {'function.name_matches': '(?i)_calcBaseInterestIndex|calcCumulativeIndex|updateIndex'}, {'function.body_contains_regex': '(?i)(_baseInterestIndexLU|cumulativeIndex).*\\*\\s*\\(\\s*(RAY|WAD|1e27|1e18)\\s*\\+\\s*\\w*calcLinearGrowth'}, {'function.body_not_contains_regex': '(?i)(linearGrowth|simple).*index\\s*=.*indexAtStart\\s*\\+'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — interest-index-compound-vs-pool-simple-mismatch: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
