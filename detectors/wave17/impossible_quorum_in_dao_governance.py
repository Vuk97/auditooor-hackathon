"""
impossible-quorum-in-dao-governance — generated from reference/patterns.dsl/impossible-quorum-in-dao-governance.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py impossible-quorum-in-dao-governance.yaml
Source: Hexens Glider query: impossible-quorum
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class ImpossibleQuorumInDaoGovernance(AbstractDetector):
    ARGUMENT = "impossible-quorum-in-dao-governance"
    HELP = "A totalSupply-style quorum input path reads totalsuppl directly without an obvious sync, update, validate, or check guard."
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/impossible-quorum-in-dao-governance.yaml"
    WIKI_TITLE = "Possible impossible-quorum source shape in DAO governance"
    WIKI_DESCRIPTION = "This graveyard detector is a source-shape approximation for DAO quorum drift bugs. It flags a totalSupply-style function that reads a totalsuppl state variable without calling a synchronizing or validating helper before returning the value used by quorum logic."
    WIKI_EXPLOIT_SCENARIO = "A governor computes quorum from a live totalSupply-like value that can drift away from the voting snapshot denominator. If no sync or validation step refreshes the denominator before quorum is checked, proposals can become impossible to pass or artificially easier to pass."
    WIKI_RECOMMENDATION = "Refresh or validate the quorum denominator from the correct checkpointed source before using it in governance math, and cover the flow with snapshot-aware tests."

    _PRECONDITIONS = [{'contract.source_matches_regex': '(?i)(govern|dao|quorum|vote|supply)'}]
    _MATCH = [{'function.name_matches': '(?i)totalSupply'}, {'function.reads_storage_matching': '(?i)totalsuppl'}, {'function.not_body_contains_regex': '(?i)(accrue|update|sync|validate|check)\\s*\\('}, {'function.not_in_skip_list': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — impossible-quorum-in-dao-governance: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
