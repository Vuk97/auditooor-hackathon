"""
w68-vote-double-count-delegation - generated from reference/patterns.dsl/w68-vote-double-count-delegation.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py w68-vote-double-count-delegation.yaml
Source: W6-8 zero-coverage detector batch (auditooor capability lift)
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class W68VoteDoubleCountDelegation(AbstractDetector):
    ARGUMENT = "w68-vote-double-count-delegation"
    HELP = "Vote counted twice via delegation and direct voting because weight sums own balance and delegated power"
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/w68-vote-double-count-delegation.yaml"
    WIKI_TITLE = "Vote counted twice via delegation and direct voting"
    WIKI_DESCRIPTION = "castVote computes weight as own balance plus delegated power, double-counting self-delegated tokens, with no per-proposal hasVoted guard."
    WIKI_EXPLOIT_SCENARIO = "Vote counted twice via delegation and direct voting because weight sums own balance and delegated power"
    WIKI_RECOMMENDATION = "Use a single snapshotted voting-power source and a per-proposal hasVoted guard."

    _PRECONDITIONS = [{'contract.source_matches_regex': '.*'}]
    _MATCH = [{'function.name_matches': '.*(castVote|vote|tally).*'}, {'function.not_leaf_helper': True}, {'function.not_in_skip_list': True}, {'function.body_contains_regex': '(?i)balanceOf\\s*(?:\\[[^\\]]+\\]|\\([^\\)]*\\))\\s*\\+\\s*delegat'}, {'function.body_not_contains_regex': '(?i)hasVoted'}]

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
                info = [f, f" - w68-vote-double-count-delegation: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
