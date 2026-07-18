"""
c4-forsale-bypass-compensate — generated from reference/patterns.dsl/c4-forsale-bypass-compensate.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py c4-forsale-bypass-compensate.yaml
Source: code4arena/slice_aa-size
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class C4ForsaleBypassCompensate(AbstractDetector):
    ARGUMENT = "c4-forsale-bypass-compensate"
    HELP = "Alternate entrypoint (`compensate`, `settle`) reads the same position/listing as the main `sell`/`buy` path but does not require `forSale == true`. An attacker can settle a non-listed asset, bypassing the listing workflow."
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.LOW
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/c4-forsale-bypass-compensate.yaml"
    WIKI_TITLE = "Alternate entrypoint bypasses forSale/isListed flag"
    WIKI_DESCRIPTION = "Primary `sell()` requires `position.forSale == true` before processing. Secondary `compensate()` (meant for dispute / force-settle) reads the same mapping without the flag check, letting callers settle unlisted positions."
    WIKI_EXPLOIT_SCENARIO = "User's collateral is NOT for sale but mechanic allows `compensate(positionId)` which transfers the collateral using listing-path accounting — the forSale gate is bypassed."
    WIKI_RECOMMENDATION = "Duplicate the `require(position.forSale)` (or move it into a shared internal) so alt paths cannot forget it."

    _PRECONDITIONS = [{'contract.has_state_var_matching': 'forSale|isListed|isActive|listed'}, {'contract.has_function_body_matching': 'require\\s*\\(\\s*\\w*\\.forSale|require\\s*\\(\\s*isListed|require\\s*\\(\\s*forSale\\s*\\['}, {'contract.source_matches_regex': '(?i)(position|listing|marketplace|auction|forSale|listed|Size|debtPosition|creditPosition)'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': '^(compensate|settle|forceSettle|adminSettle|alternateCompensate|alternateSettle|alternateExecute|alternateClaim|alternateRepay|alternateClose|alternateLiquidate)$'}, {'function.body_contains_regex': 'forSale|isListed|isActive|listed'}, {'function.body_not_contains_regex': 'require\\s*\\(\\s*\\w*\\.forSale|require\\s*\\(\\s*isListed|require\\s*\\(\\s*forSale\\s*\\[|if\\s*\\(\\s*!forSale'}, {'function.not_source_matches_regex': '(_requireListed|_assertForSale|_checkForSale|modifier\\s+onlyListed|modifier\\s+whenListed)'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}]

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
                info = [f, f" — c4-forsale-bypass-compensate: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
