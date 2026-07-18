"""
r94-loop-state-mutation-between-read-and-write-delta — generated from reference/patterns.dsl/r94-loop-state-mutation-between-read-and-write-delta.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py r94-loop-state-mutation-between-read-and-write-delta.yaml
Source: loop-cycle-76-sol-sibling
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class R94LoopStateMutationBetweenReadAndWriteDelta(AbstractDetector):
    ARGUMENT = "r94-loop-state-mutation-between-read-and-write-delta"
    HELP = "r94-loop-state-mutation-between-read-and-write-delta"
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.LOW
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/r94-loop-state-mutation-between-read-and-write-delta.yaml"
    WIKI_TITLE = "r94-loop-state-mutation-between-read-and-write-delta"
    WIKI_DESCRIPTION = "r94-loop-state-mutation-between-read-and-write-delta"
    WIKI_EXPLOIT_SCENARIO = "r94-loop-state-mutation-between-read-and-write-delta"
    WIKI_RECOMMENDATION = "See audit report."

    _PRECONDITIONS = [{'contract.source_matches_regex': '(ConvictionScore|convictionDelta|governanceDelta)'}]
    _MATCH = [{'function.kind': 'internal_or_private'}, {'function.name_matches': '(?i)^(updateScore|updateConvictionScore|updateGovernanceScore|updateVotingScore|updateDelta|updateConvictionDelta|updateGovernanceDelta|updateVoteDelta|_updateScore|_updateConvictionScore|_updateConviction|_updateGovernanceScore|_updateDelta|_updateConvictionDelta|_updateGovernanceDelta|applyDelta|applyConvictionDelta|computeDelta|computeConvictionDelta)$'}, {'function.source_matches_regex': '(isGovernance|\\w+Eligible)\\s*=\\s*false\\s*;[\\s\\S]{0,300}?(getPrior\\w*|getPast\\w*|getPrev\\w*|readPrevious\\w*)\\s*\\('}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — r94-loop-state-mutation-between-read-and-write-delta: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
