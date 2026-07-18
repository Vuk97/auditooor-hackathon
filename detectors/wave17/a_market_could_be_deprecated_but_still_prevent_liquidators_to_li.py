"""
a-market-could-be-deprecated-but-still-prevent-liquidators-to-li — generated from reference/patterns.dsl/a-market-could-be-deprecated-but-still-prevent-liquidators-to-li.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py a-market-could-be-deprecated-but-still-prevent-liquidators-to-li.yaml
Source: Solodit
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class AMarketCouldBeDeprecatedButStillPreventLiquidatorsToLi(AbstractDetector):
    ARGUMENT = "a-market-could-be-deprecated-but-still-prevent-liquidators-to-li"
    HELP = "A market could be deprecated but still prevent liquidators to liquidate borrowers if isLiquidateBorrowPaused is true"
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/a-market-could-be-deprecated-but-still-prevent-liquidators-to-li.yaml"
    WIKI_TITLE = "A market could be deprecated but still prevent liquidators to liquidate borrowers if isLiquidateBorrowPaused istrue"
    WIKI_DESCRIPTION = "## Severity: Medium Risk\n\n## Context \n- aave-v2/MorphoGovernance.sol#L358-L366 \n- compound/MorphoGovernance.sol#L368-L376 \n\n## Description \nCurrently, when a market must be deprecated, Morpho checks that borrowing has been paused before applying the new value for the flag."
    WIKI_EXPLOIT_SCENARIO = "Per Solodit #6901: ## Severity: Medium Risk\n\n## Context \n- aave-v2/MorphoGovernance.sol#L358-L366 \n- compound/MorphoGovernance.sol#L368-L376 \n\n## Description \nCurrently, when a market must be deprecated, Morpho checks t"
    WIKI_RECOMMENDATION = "See source audit report for recommended fix."

    _PRECONDITIONS = [{'contract.source_matches_regex': '.*'}]
    _MATCH = [{'function.name_matches': '.*(isLiquidateBorrowPaused|isDeprecated|setIsLiquidateBorrowPaused|setIsBorrowPaused).*'}, {'function.not_leaf_helper': True}, {'function.not_in_skip_list': True}, {'function.reads_state_var_matching': '.*(isDeprecated|isLiquidateBorrowPaused|setIsBorrowPaused).*'}, {'function.calls_function_matching': {'regex': '.*(accrue|update|sync|validate|check|refresh).*', 'negate': True}}]

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
                info = [f, f" — a-market-could-be-deprecated-but-still-prevent-liquidators-to-li: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
