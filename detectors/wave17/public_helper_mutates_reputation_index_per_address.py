"""
public-helper-mutates-reputation-index-per-address — generated from reference/patterns.dsl/public-helper-mutates-reputation-index-per-address.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py public-helper-mutates-reputation-index-per-address.yaml
Source: auditooor-R75-code4rena-2024-08-phi-51
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class PublicHelperMutatesReputationIndexPerAddress(AbstractDetector):
    ARGUMENT = "public-helper-mutates-reputation-index-per-address"
    HELP = "Index-maintenance helper is marked public with no authorization — anyone can corrupt another user's cred/share index arrays."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.HIGH
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/public-helper-mutates-reputation-index-per-address.yaml"
    WIKI_TITLE = "Public index-maintenance helpers let attackers grief any holder's tracking array"
    WIKI_DESCRIPTION = "Functions like `_addCredIdPerAddress(credId, sender)` and `_removeCredIdPerAddress(credId, sender)` are marked `public` with no access control. They mutate `_credIdsPerAddress[sender]` and the index map. An attacker calls them in a loop with arbitrary credIds and any victim address: adds thousands of bogus credIds to victim's list (bloats gas), or deletes/reorders entries (causes index mismatch pa"
    WIKI_EXPLOIT_SCENARIO = "Victim has 3 legitimate creds. Attacker calls `_addCredIdPerAddress(999, victim)` 10_000 times on L2 where gas is cheap. Victim's `_credIdsPerAddressArrLength[victim]` = 10_003. Any function that loops over victim's creds now reverts OOG. Victim cannot sell or transfer."
    WIKI_RECOMMENDATION = "Mark helpers `internal`. If an external admin path is needed, wrap them in an `onlyRole(INDEX_MANAGER)` function. Every mutation must require `msg.sender == sender_` or a role."

    _PRECONDITIONS = [{'contract.has_state_var_matching': '(?i)(cred|reputation|share|point|score).*ids?peraddress|ids?peraddress|index.*peraddress|peraddress.*index'}]
    _MATCH = [{'function.kind': 'public'}, {'function.is_mutating': True}, {'function.name_matches': '(?i)^_?(add|remove|delete|update|move)\\w*(peraddress|index|slot)'}, {'function.has_param_of_type': 'address'}, {'function.has_param_name_matching': '(?i)^(sender|sender_|user|user_|account|account_|holder|holder_|owner|owner_)$'}, {'function.writes_storage_matching': '(?i)(cred|reputation|share|point|score).*ids?peraddress|ids?peraddress|index.*peraddress|peraddress.*index'}, {'function.body_contains_regex': '(?i)\\[\\s*(sender_?|user_?|account_?|holder_?|owner_?)\\s*\\]'}, {'function.body_contains_regex': '(?i)(\\.push\\s*\\(|delete\\s+\\w+\\s*\\[|(?:=|\\+=|-=|\\+\\+|--))'}, {'function.has_modifier': {'includes': ['onlyOwner', 'onlyAdmin', 'onlyGovernance', 'onlyGovernor', 'onlyRole', 'onlyTrusted', 'onlyInternal'], 'negate': True}}, {'function.body_not_contains_regex': '(?i)(require|if)\\s*\\([^;\\)]*msg\\.sender\\s*==\\s*(sender_?|user_?|account_?|holder_?|owner_?)|(?:sender_?|user_?|account_?|holder_?|owner_?)\\s*==\\s*msg\\.sender|onlyTrusted|onlyInternal|onlyRole|onlyOwner|onlyAdmin|onlyGovernance|onlyGovernor'}, {'function.not_in_skip_list': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — public-helper-mutates-reputation-index-per-address: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
