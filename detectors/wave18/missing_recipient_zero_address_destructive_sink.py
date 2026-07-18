"""
missing-recipient-zero-address-destructive-sink — generated from reference/patterns.dsl/missing-recipient-zero-address-destructive-sink.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py missing-recipient-zero-address-destructive-sink.yaml
Source: capability-roadmap-worker-ca-2026-05-17
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class MissingRecipientZeroAddressDestructiveSink(AbstractDetector):
    ARGUMENT = "missing-recipient-zero-address-destructive-sink"
    HELP = "Burn/delegation entrypoint forwards a user-supplied address into a destructive zero-address sink without rejecting address(0)."
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/missing-recipient-zero-address-destructive-sink.yaml"
    WIKI_TITLE = "Destructive zero-address sink lacks recipient validation"
    WIKI_DESCRIPTION = "Some token and governance entrypoints use an address parameter as the sink of a destructive accounting move rather than as a plain payout recipient. If burn/burnFrom accepts address(0), balance and total-supply accounting can be corrupted or batched calls can be grief-reverted. If a Nouns-style delegate/delegateBySig path accepts address(0), votes can be moved to the zero sink and burned because t"
    WIKI_EXPLOIT_SCENARIO = "A caller passes address(0) as the burn account or delegatee. The function reaches balances[account]/totalSupply mutation or _delegate/_moveDelegates without a zero-address guard. The destructive move either reverts after entering a batched flow, corrupts token accounting in custom implementations, or burns governance voting power by decrementing the source without crediting a destination."
    WIKI_RECOMMENDATION = "Reject address(0) at every externally reachable burn/delegation boundary before forwarding the parameter to balance, supply, delegate, or vote checkpoint mutation. For delegation APIs that intentionally support clearing, normalize zero to self-delegation before calling the destructive movement helpe"

    _PRECONDITIONS = [{'contract.source_matches_regex': '(?is)(?:\\bmapping\\s*\\(\\s*address\\s*=>\\s*address\\s*\\)\\s+\\w*[Dd]elegates\\b|function\\s+delegates\\s*\\(\\s*address|\\bbalances?\\s*\\[|\\btotalSupply\\b)'}, {'contract.has_function_matching': '(?i)^(burn|burnFrom|delegate|delegateBySig)$'}, {'contract.not_source_matches_regex': '(?i)\\b(mock|test|fixture|harness)\\b'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': '(?i)^(burn|burnFrom|delegate|delegateBySig)$'}, {'function.has_param_of_type': 'address'}, {'function.has_param_name_matching': '(?i)^(account|from|owner|delegatee|newDelegatee|dst|recipient)$'}, {'function.body_contains_regex': '(?is)(?:\\b_delegate\\s*\\(|\\b_moveDelegates\\s*\\(|\\bbalances?\\s*\\[[^\\]]*(?:account|from|owner|recipient)\\b|\\btotalSupply\\s*(?:-=|=))'}, {'function.body_not_contains_regex': '(?is)(?:require\\s*\\([^;]*(?:account|from|owner|delegatee|newDelegatee|dst|recipient)\\s*!=\\s*address\\s*\\(\\s*0\\s*\\)|if\\s*\\(\\s*(?:account|from|owner|delegatee|newDelegatee|dst|recipient)\\s*==\\s*address\\s*\\(\\s*0\\s*\\)\\s*\\)\\s*revert|ZeroAddress\\s*\\(|ZeroDelegatee|InvalidRecipient|burn from zero address)'}, {'function.has_modifier': {'includes': ['nonZero', 'nonZeroAddress', 'notZero', 'notZeroAddress', 'validAddress'], 'negate': True}}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture|harness)\\b'}]

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
                info = [f, f" — missing-recipient-zero-address-destructive-sink: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
