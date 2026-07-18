"""
vetoken-stake-one-wei-delegate-hijack — generated from reference/patterns.dsl/vetoken-stake-one-wei-delegate-hijack.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py vetoken-stake-one-wei-delegate-hijack.yaml
Source: solodit-novel/slice_ac-AgentVeToken
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class VetokenStakeOneWeiDelegateHijack(AbstractDetector):
    ARGUMENT = "vetoken-stake-one-wei-delegate-hijack"
    HELP = "`stake(user, amount)` / `deposit_for(user, ...)` lets anyone stake on behalf of another address and sets / overrides the delegate. Attacker stakes 1 wei and hijacks the delegate."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/vetoken-stake-one-wei-delegate-hijack.yaml"
    WIKI_TITLE = "veToken stake-on-behalf hijacks delegate"
    WIKI_DESCRIPTION = "A `deposit_for(user)` pattern that also sets `delegates[user] = ...` with no caller check (and no protection for already-set delegates) allows any attacker to call `deposit_for(victim, 1 wei)` and redirect victim's voting power."
    WIKI_EXPLOIT_SCENARIO = "Victim has 100k veToken voting for Proposal A. Attacker calls `deposit_for(victim, 1 wei)` with a payload that triggers self-delegation. Votes flip from A to attacker-controlled address, swinging outcome."
    WIKI_RECOMMENDATION = "Require `msg.sender == user`, or only set delegate when `delegates[user] == address(0)` (first-time set)."

    _PRECONDITIONS = [{'contract.source_matches_regex': 'veToken|AgentVeToken|voting-?escrow|delegate'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': '^(stake|deposit_for|createLock|increaseAmount|lockOnBehalfOf)'}, {'function.has_param_name_matching': 'user|onBehalfOf|owner|to|recipient'}, {'function.body_contains_regex': 'delegate|delegates\\s*\\['}, {'function.body_not_contains_regex': 'require\\s*\\(\\s*msg\\.sender\\s*==\\s*(\\w+user|\\w+onBehalfOf|\\w+owner|\\w+to|\\w+recipient)|delegates\\s*\\[\\s*\\w+\\s*\\]\\s*==\\s*address\\(0\\)'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — vetoken-stake-one-wei-delegate-hijack: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
