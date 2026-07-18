"""
glider-frontrunning-immediate-distribution-dilutes-the-re — generated from reference/patterns.dsl/glider-frontrunning-immediate-distribution-dilutes-the-re.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py glider-frontrunning-immediate-distribution-dilutes-the-re.yaml
Source: hexens-glider/frontrunning-immediate-distribution-dilutes-the-re
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class GliderFrontrunningImmediateDistributionDilutesTheRe(AbstractDetector):
    ARGUMENT = "glider-frontrunning-immediate-distribution-dilutes-the-re"
    HELP = "Frontrunning immediate distribution dilutes the rewards for legitimate users"
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/glider-frontrunning-immediate-distribution-dilutes-the-re.yaml"
    WIKI_TITLE = "Frontrunning immediate distribution dilutes the rewards for legitimate users"
    WIKI_DESCRIPTION = "Finds main contracts that have “immediate distribution”-style entrypoints which: - Are public/external functions with names like immediateDistribution / instantDistribution - Reconfigure reward/emission program parameters in-place - Use the current total stake / total supply and block.timestamp in the same function Such patterns can allow a large last-minute deposit to frontrun a one-shot reward d"
    WIKI_EXPLOIT_SCENARIO = "Transpiled from Hexens Glider query frontrunning-immediate-distribution-dilutes-the-re. Tags: rewards, immediate distribution, frontrun."
    WIKI_RECOMMENDATION = "Apply the check implied by the original Glider query — see hexens-glider source for context."

    _PRECONDITIONS = [{'contract.source_matches_regex': '.*'}, {'function.name_matches': '^(immediateDistribution|immediate_distribution|instantDistribution|instant_distribution|oneTimeDistribution|one_time_distribution)$'}]
    _MATCH = [{'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — glider-frontrunning-immediate-distribution-dilutes-the-re: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
