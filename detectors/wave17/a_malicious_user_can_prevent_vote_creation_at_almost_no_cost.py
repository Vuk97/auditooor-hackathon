"""
a-malicious-user-can-prevent-vote-creation-at-almost-no-cost — generated from reference/patterns.dsl/a-malicious-user-can-prevent-vote-creation-at-almost-no-cost.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py a-malicious-user-can-prevent-vote-creation-at-almost-no-cost.yaml
Source: Solodit
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class AMaliciousUserCanPreventVoteCreationAtAlmostNoCost(AbstractDetector):
    ARGUMENT = "a-malicious-user-can-prevent-vote-creation-at-almost-no-cost"
    HELP = "A malicious user can prevent vote creation at almost no cost"
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/a-malicious-user-can-prevent-vote-creation-at-almost-no-cost.yaml"
    WIKI_TITLE = "A malicious user can prevent vote creation at almost no cost"
    WIKI_DESCRIPTION = "## GOAT Protocol Reputation Challenge\n\n## Context\n(No context files were provided by the reviewer)\n\n## Description\nA staker in the GOAT protocol can raise a reputation challenge against any other staker. This happens by creating a vote, where the challenger (attacker) and the challenged (defender) a"
    WIKI_EXPLOIT_SCENARIO = "Per Solodit #54268: ## GOAT Protocol Reputation Challenge\n\n## Context\n(No context files were provided by the reviewer)\n\n## Description\nA staker in the GOAT protocol can raise a reputation challenge against any other stak"
    WIKI_RECOMMENDATION = "See source audit report for recommended fix."

    _PRECONDITIONS = [{'contract.has_state_var_matching': '(?i)(activeVote|hasActiveVote|voteExists|currentVote|votes)'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': '.*createVote.*'}, {'function.has_param_name_matching': '(?i)(voterPercent|votePercent|percent)'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.body_contains_regex': 'validatePercent\\s*\\(\\s*(?:voterPercent_|votePercent_|voterPercent|votePercent)'}, {'function.body_contains_regex': '(?i)(activeVote|hasActiveVote|voteExists|currentVote|votes)\\s*\\['}, {'function.body_contains_regex': '(?i)voterPercent\\s*[:=]\\s*(?:voterPercent_|votePercent_|voterPercent|votePercent)'}, {'function.body_not_contains_regex': '(?i)require\\s*\\(\\s*(?:voterPercent_|votePercent_|voterPercent|votePercent)\\s*>\\s*0\\b|if\\s*\\(\\s*(?:voterPercent_|votePercent_|voterPercent|votePercent)\\s*==\\s*0\\s*\\)\\s*(?:revert|return)'}]

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
                info = [f, f" — a-malicious-user-can-prevent-vote-creation-at-almost-no-cost: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
