"""
global-param-change-breaks-downstream-farm — generated from reference/patterns.dsl/global-param-change-breaks-downstream-farm.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py global-param-change-breaks-downstream-farm.yaml
Source: auditooor-R75-code4rena-2024-07-munchables-76
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class GlobalParamChangeBreaksDownstreamFarm(AbstractDetector):
    ARGUMENT = "global-param-change-breaks-downstream-farm"
    HELP = "farm loop uses plotMetadata.lastUpdated as the cutoff when the plot is considered dirty, but lastUpdated can predate the user's lastToilDate, causing underflow and freezing the user's funds."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/global-param-change-breaks-downstream-farm.yaml"
    WIKI_TITLE = "Dirty-plot fallback timestamp predates user last-action, causing underflow and DoS"
    WIKI_DESCRIPTION = "In `_farmPlots`, when a user's staked plotId exceeds the new `numPlots`, the code sets `timestamp = plotMetadata[landlord].lastUpdated` and marks the token dirty. Accrual is then `schnibbles = (timestamp - lastToilDate) * rate`. But `lastUpdated` is only set when `initialize` or `updateRate` is called — if it's older than `lastToilDate` (user acted after the last admin update), the subtraction und"
    WIKI_EXPLOIT_SCENARIO = "Admin initializes a landlord at t=0 (lastUpdated = 0 → never updated again). User stakes at t=100, lastToilDate=100. Admin raises PRICE_PER_PLOT making the user's plot invalid. At t=200 user calls farmPlots → timestamp = lastUpdated = 0; schnibbles = 0 - 100 → underflow panic. User's NFT is frozen."
    WIKI_RECOMMENDATION = "When marking a plot dirty, set `timestamp = max(lastUpdated, lastToilDate)` — or explicitly skip accrual when lastUpdated < lastToilDate. Add a post-condition assert `timestamp >= lastToilDate`."

    _PRECONDITIONS = [{'contract.source_matches_regex': '.*'}]
    _MATCH = [{'function.kind': 'internal'}, {'function.name_matches': '(?i)_farmPlots|_accrue\\w*|_updatePosition'}, {'function.body_contains_regex': '(?i)_getNumPlots|getMaxPlots|_getCapacity'}, {'function.body_contains_regex': '(?i)if\\s*\\(\\s*_getNumPlots\\s*\\([^)]*\\)\\s*<\\s*\\w*\\.plotId'}, {'function.body_contains_regex': '(?i)timestamp\\s*=\\s*\\w+\\.lastUpdated'}, {'function.body_contains_regex': '(?i)(timestamp\\s*-\\s*\\w*lastToilDate|timestamp\\s*-\\s*\\w*lastUpdate)'}, {'function.not_in_skip_list': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — global-param-change-breaks-downstream-farm: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
