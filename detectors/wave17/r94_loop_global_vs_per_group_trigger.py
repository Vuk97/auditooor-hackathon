"""
r94-loop-global-vs-per-group-trigger — generated from reference/patterns.dsl/r94-loop-global-vs-per-group-trigger.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py r94-loop-global-vs-per-group-trigger.yaml
Source: loop-cycle-21-global-vs-per-group-sol-sibling
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class R94LoopGlobalVsPerGroupTrigger(AbstractDetector):
    ARGUMENT = "r94-loop-global-vs-per-group-trigger"
    HELP = "r94-loop-global-vs-per-group-trigger"
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.LOW
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/r94-loop-global-vs-per-group-trigger.yaml"
    WIKI_TITLE = "r94-loop-global-vs-per-group-trigger"
    WIKI_DESCRIPTION = "r94-loop-global-vs-per-group-trigger"
    WIKI_EXPLOIT_SCENARIO = "r94-loop-global-vs-per-group-trigger"
    WIKI_RECOMMENDATION = "See audit report."

    _PRECONDITIONS = [{'contract.source_matches_regex': '(adl|deleverage|liquidation|trigger|group)'}]
    _MATCH = [{'function.kind': 'external_or_public_or_internal'}, {'function.name_matches': '(?i)(adl|autoDeleverage|shouldDeleverage|checkDeleverage|computeLiqTarget|triggerAdl)'}, {'function.source_matches_regex': 'total\\w*(Debt|Utilization|Collateral|Supply)\\s*[<>]=|\nglobal\\w*(Debt|Utilization)\\s*[<>]=|\nprotocol\\w*(Debt|Utilization)\\s*[<>]=\n'}, {'function.source_matches_regex': '(group|coinType|mint|asset|bucket|tier|reserveId)'}, {'function.not_source_matches_regex': 'group\\s*\\[[^\\]]+\\]\\.\\w*(Debt|Utilization|Collateral)\\s*[<>]=|\nperGroup\\w*\\s*[<>]=\n'}]

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
                info = [f, f" — r94-loop-global-vs-per-group-trigger: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
