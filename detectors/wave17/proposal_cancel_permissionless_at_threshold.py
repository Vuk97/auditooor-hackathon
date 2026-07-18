"""
proposal-cancel-permissionless-at-threshold — generated from reference/patterns.dsl/proposal-cancel-permissionless-at-threshold.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py proposal-cancel-permissionless-at-threshold.yaml
Source: solodit/governance-proposal-cancel
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class ProposalCancelPermissionlessAtThreshold(AbstractDetector):
    ARGUMENT = "proposal-cancel-permissionless-at-threshold"
    HELP = "Governance `cancel()` lets anyone kill a live proposal when the proposer's voting power is `<=` the threshold, instead of `<`. If the proposer ever owned exactly `proposalThreshold` tokens, any voter can front-run the proposal at will."
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/proposal-cancel-permissionless-at-threshold.yaml"
    WIKI_TITLE = "Permissionless proposal cancel at threshold: `<=` vs `<` on proposer votes"
    WIKI_DESCRIPTION = "OpenZeppelin-style governors allow any account to cancel a proposal if the proposer has fallen below `proposalThreshold`. A correct implementation uses a strict `<` — at-threshold proposers are still protected. A buggy implementation uses `<=`, letting anyone cancel a proposal whose proposer holds exactly `proposalThreshold` tokens. Combined with a delegate-call flow this enables griefing: an adve"
    WIKI_EXPLOIT_SCENARIO = "Alice creates a proposal with exactly 10_000 governance tokens (the threshold). Bob calls `cancel(proposalId)`: the guard `getVotes(alice) <= proposalThreshold()` evaluates true, the proposal is marked Canceled, and the queue is cleared. Alice must re-propose, which takes another voting delay. Repeat: any at-threshold proposer is permanently censored."
    WIKI_RECOMMENDATION = "Use strict `<` in the cancel guard: `require(getPastVotes(proposer, block.number - 1) < proposalThreshold(), …)`. Additionally, allow the proposer themselves to cancel regardless of vote balance: `require(msg.sender == proposer || getPastVotes(proposer, …) < proposalThreshold(), …)`. Consider snapsh"

    _PRECONDITIONS = [{'contract.source_matches_regex': '.*'}, {'contract.has_state_var_matching': 'proposal|proposals|proposalThreshold|proposalCount'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': '^(cancel|cancelProposal|_cancelProposal)$'}, {'function.body_contains_regex': 'delete\\s+proposals|canceled\\s*=\\s*true|state\\s*=\\s*ProposalState\\.Canceled|proposal\\.canceled|\\.canceled\\s*='}, {'function.has_high_level_call_named': 'balanceOf'}, {'function.has_high_level_call_named': 'balanceOf'}, {'function.has_high_level_call_named': 'balanceOf'}, {'function.has_high_level_call_named': 'balanceOf'}, {'function.has_high_level_call_named': 'balanceOf'}, {'function.has_high_level_call_named': 'balanceOf'}, {'function.has_high_level_call_named': 'balanceOf'}, {'function.has_high_level_call_named': 'balanceOf'}, {'function.has_high_level_call_named': 'balanceOf'}, {'function.has_high_level_call_named': 'balanceOf'}, {'function.has_high_level_call_named': 'balanceOf'}, {'function.has_high_level_call_named': 'balanceOf'}, {'function.has_high_level_call_named': 'balanceOf'}, {'function.has_high_level_call_named': 'balanceOf'}, {'function.body_contains_regex': 'getVotes|getPriorVotes|getPastVotes|balanceOf|proposalThreshold'}, {'function.body_not_contains_regex': 'require\\s*\\(\\s*msg\\.sender\\s*==\\s*.*proposer|proposer\\s*==\\s*msg\\.sender'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — proposal-cancel-permissionless-at-threshold: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
