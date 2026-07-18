"""
leverage-uses-wrong-max-when-lower-bound-exists — generated from reference/patterns.dsl/leverage-uses-wrong-max-when-lower-bound-exists.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py leverage-uses-wrong-max-when-lower-bound-exists.yaml
Source: solodit/sherlock/yieldoor-H4-55035
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class LeverageUsesWrongMaxWhenLowerBoundExists(AbstractDetector):
    ARGUMENT = "leverage-uses-wrong-max-when-lower-bound-exists"
    HELP = "Liquidation health check uses a per-vault leverage cap but ignores a tighter per-pool / global cap that actually constrains positions. Positions that are liquidatable by the tighter cap go unliquidated, accumulating bad debt."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/leverage-uses-wrong-max-when-lower-bound-exists.yaml"
    WIKI_TITLE = "Liquidation threshold uses wrong max-leverage when pool cap is tighter"
    WIKI_DESCRIPTION = "The leveraged-vault contract stores a per-vault leverage cap `vp.maxTimesLeverage`, while the underlying lending pool imposes its own `maxLevTimes` that can be tighter. The user's effective max leverage is `min(vp.maxTimesLeverage, pool.maxLevTimes)`. The health check `isLiquidateable` divides by `(vp.maxTimesLeverage - 1e18)` — the looser bound — producing a smaller `base` threshold than the user"
    WIKI_EXPLOIT_SCENARIO = "Vault sets maxTimesLeverage = 5x. Lending pool later tightens maxLevTimes = 3x (admin risk reduction). A user borrows at 3x (pool-capped). Price moves down 30%. Under 3x leverage math the user is underwater and should be liquidated, but `isLiquidateable` still divides by (5x - 1) = 4, yielding a looser liquidation base. The position walks through the liquidation gate until it's deep in bad-debt te"
    WIKI_RECOMMENDATION = "Replace `vp.maxTimesLeverage` in the liquidation math with `Math.min(vp.maxTimesLeverage, lendingPool.maxLevTimes())`. Add a storage invariant that keeps these in sync, or read both at each call. Unit-test liquidation behavior when admin tightens pool leverage mid-position."

    _PRECONDITIONS = [{'contract.source_matches_regex': '.*'}, {'contract.has_state_var_matching': '(maxTimesLeverage|maxLeverage|maxLevTimes|maxLTV|liquidationThreshold)'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.state_mutability': 'view'}, {'function.name_matches': '(isLiquidateable|isLiquidatable|canLiquidate|healthFactor|getLTV|isHealthy|solvencyCheck)'}, {'function.body_contains_regex': '(maxTimesLeverage|maxLeverage|maxLevTimes)\\s*-\\s*1e18|owed\\w*\\s*\\*\\s*\\w+\\s*/\\s*(maxTimesLeverage|maxLeverage|maxLevTimes)'}, {'function.body_not_contains_regex': 'Math\\.min\\s*\\([^)]*(maxTimesLeverage|maxLeverage|maxLevTimes)|<\\s*(maxTimesLeverage|maxLeverage|maxLevTimes)|>\\s*(maxTimesLeverage|maxLeverage|maxLevTimes)\\s*\\?'}, {'contract.has_func_body_matching': '\\.(maxLevTimes|poolMaxLeverage|globalMaxLeverage)\\s*\\('}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — leverage-uses-wrong-max-when-lower-bound-exists: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
