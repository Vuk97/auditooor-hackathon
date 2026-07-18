"""
glider-nouns-delegates-zero-address-vote-burn — generated from reference/patterns.dsl/glider-nouns-delegates-zero-address-vote-burn.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py glider-nouns-delegates-zero-address-vote-burn.yaml
Source: glider-docs/nouns-dao-delegate-zero-address-vote-burn
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class GliderNounsDelegatesZeroAddressVoteBurn(AbstractDetector):
    ARGUMENT = "glider-nouns-delegates-zero-address-vote-burn"
    HELP = "Governance token exposes `delegate(address)` / `delegateBySig(...)` that forwards to `_delegate` without checking that the delegatee is non-zero. Combined with a `delegates()` accessor that treats stored-zero as 'self', votes can be moved to address(0), burning them and potentially freezing the sour"
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/glider-nouns-delegates-zero-address-vote-burn.yaml"
    WIKI_TITLE = "delegate/delegateBySig accepts address(0) — vote burn, asset freeze"
    WIKI_DESCRIPTION = "Nouns-derived governance tokens override `delegates(address)` to return the account itself when `_delegates[account] == address(0)` (so implicit self-delegation works before any delegate call). When the public `delegate(newDelegatee)` / `delegateBySig(...)` entry forwards to `_delegate(oldDelegatee, newDelegatee)` without rejecting `newDelegatee == address(0)`, a caller can explicitly set their de"
    WIKI_EXPLOIT_SCENARIO = "EOA Alice holds 100 NOUNs, currently self-delegating. Alice signs `delegateBySig(to = address(0), ...)` and the relayer submits it. `_delegate` runs `_moveDelegates(Alice, address(0), 100)`: source decremented, no destination. Alice's 100 votes are destroyed; if the token's transfer hook also references `delegates()` during the zero-state, Alice's NFTs become non-transferable. Attacker can mass-su"
    WIKI_RECOMMENDATION = "In every delegate/delegateBySig entry check `require(newDelegatee != address(0), 'zero delegatee')` OR interpret a zero delegatee as 'delegate to self' (matching the getter semantics) rather than passing zero through to `_moveDelegates`. OpenZeppelin's Votes v5 does the latter — see `_delegate` whic"

    _PRECONDITIONS = [{'contract.source_matches_regex': '\\bmapping\\s*\\(\\s*address\\s*=>\\s*address\\s*\\)\\s+\\w*[Dd]elegates\\b|\\b_delegates\\s*\\[|function\\s+delegates\\s*\\('}, {'contract.has_function_matching': '^(delegate|delegateBySig|_delegate)$'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': '^(delegate|delegateBySig)$'}, {'function.body_contains_regex': '\\b_delegate\\s*\\('}, {'function.body_not_contains_regex': 'delegatee\\s*!=\\s*address\\s*\\(\\s*0\\s*\\)|address\\s*\\(\\s*0\\s*\\)\\s*!=\\s*delegatee|require\\s*\\([^;]*address\\s*\\(\\s*0\\s*\\)|ZeroDelegatee|ZeroAddress\\s*\\(\\s*\\)|delegatee\\s*==\\s*address\\s*\\(\\s*0\\s*\\)\\s*\\?|!=\\s*address\\(0\\)\\s*,'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — glider-nouns-delegates-zero-address-vote-burn: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
