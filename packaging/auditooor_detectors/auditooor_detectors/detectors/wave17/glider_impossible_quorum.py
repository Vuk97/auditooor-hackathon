"""
glider-impossible-quorum — generated from reference/patterns.dsl/glider-impossible-quorum.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py glider-impossible-quorum.yaml
Source: glider-query-db/impossible-quorum
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class GliderImpossibleQuorum(AbstractDetector):
    ARGUMENT = "glider-impossible-quorum"
    HELP = "Governor.quorum() reads current totalSupply but votes are tallied against a historical snapshot. After mint/burn, quorum can become unreachable or trivially reachable, bricking governance."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/glider-impossible-quorum.yaml"
    WIKI_TITLE = "Quorum computed from live supply, not proposal snapshot"
    WIKI_DESCRIPTION = "A governor that computes `quorum() = totalSupply * pct` from live supply, while votes are compared against snapshot-time holdings, creates drift: if supply increases after snapshot, quorum is impossible."
    WIKI_EXPLOIT_SCENARIO = "Proposal created with 1M supply; admin mints 10M new tokens; quorum now requires 4% of 11M = 440k votes, but only 400k voting weight exists at snapshot. Proposal dies."
    WIKI_RECOMMENDATION = "Compute quorum against `token.getPastTotalSupply(proposalSnapshot)` — OpenZeppelin Governor pattern."

    _PRECONDITIONS = [{'contract.source_matches_regex': 'quorum|proposal|vote|governor'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': '^(quorum|_quorum|quorumNumerator|quorumDenominator|quorumVotes)$'}, {'function.has_high_level_call_named': 'totalSupply'}, {'function.has_high_level_call_named': 'totalSupply'}, {'function.has_high_level_call_named': 'totalSupply'}, {'function.has_high_level_call_named': 'totalSupply'}, {'function.has_high_level_call_named': 'totalSupply'}, {'function.has_high_level_call_named': 'totalSupply'}, {'function.has_high_level_call_named': 'totalSupply'}, {'function.has_high_level_call_named': 'totalSupply'}, {'function.has_high_level_call_named': 'totalSupply'}, {'function.has_high_level_call_named': 'totalSupply'}, {'function.has_high_level_call_named': 'totalSupply'}, {'function.has_high_level_call_named': 'totalSupply'}, {'function.has_high_level_call_named': 'totalSupply'}, {'function.has_high_level_call_named': 'totalSupply'}, {'function.body_contains_regex': 'totalSupply\\s*\\(\\s*\\)|getPastTotalSupply'}, {'function.body_not_contains_regex': 'snapshotId|getPastVotes|getVotes|checkpoint|snapshot\\s*\\(|timepoint'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — glider-impossible-quorum: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
