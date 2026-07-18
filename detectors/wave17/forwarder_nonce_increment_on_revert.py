"""
forwarder-nonce-increment-on-revert — generated from reference/patterns.dsl/forwarder-nonce-increment-on-revert.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py forwarder-nonce-increment-on-revert.yaml
Source: solodit-novel/slice_aa-EIP2771
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class ForwarderNonceIncrementOnRevert(AbstractDetector):
    ARGUMENT = "forwarder-nonce-increment-on-revert"
    HELP = "EIP-2771 meta-tx forwarder increments the user's nonce before an inner low-level call and never reverts on call failure. A failed inner call still burns the nonce, allowing a griefer to desync the user's signed meta-tx queue."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/forwarder-nonce-increment-on-revert.yaml"
    WIKI_TITLE = "EIP-2771 forwarder burns nonce on inner-call failure"
    WIKI_DESCRIPTION = "Forwarder pulls a signed ForwardRequest, bumps `nonces[from]++`, then does `(bool ok, ) = req.to.call{value: req.value, gas: req.gas}(req.data)`. The return value is discarded. If the inner call reverts, the nonce is still consumed — the user's signed message is permanently wasted. Attackers can force every meta-tx to fail (e.g. out-of-gas) while still burning the nonce, effectively DoS-ing the us"
    WIKI_EXPLOIT_SCENARIO = "Alice signs a meta-tx with nonce 5. Mallory submits the request through the forwarder but under-funds gas / targets a revert path. `nonces[Alice]` increments to 6. Alice's legitimate nonce-5 signature is now dead. Mallory repeats, bricking Alice's relayer queue."
    WIKI_RECOMMENDATION = "Always `require(success, ...)` (or revert with returndata) after the inner call so a failed meta-tx does not consume the nonce — match OpenZeppelin MinimalForwarder's reference implementation."

    _PRECONDITIONS = [{'contract.has_state_var_matching': 'nonces|_nonces'}, {'contract.source_matches_regex': 'ForwardRequest|MinimalForwarder|execute|EIP2771|forwarder'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': '^(execute|executeBatch|forward|relay)$'}, {'function.body_contains_regex': 'nonces\\s*\\[[^\\]]+\\]\\s*\\+\\+|nonces\\s*\\[[^\\]]+\\]\\s*\\+=|_useNonce|_useCheckedNonce'}, {'function.has_low_level_call': {'op': 'delegatecall'}}, {'function.has_low_level_call': {'op': 'delegatecall'}}, {'function.has_low_level_call': {'op': 'delegatecall'}}, {'function.has_low_level_call': {'op': 'delegatecall'}}, {'function.has_low_level_call': {'op': 'delegatecall'}}, {'function.has_low_level_call': {'op': 'delegatecall'}}, {'function.has_low_level_call': {'op': 'delegatecall'}}, {'function.has_low_level_call': {'op': 'delegatecall'}}, {'function.has_low_level_call': {'op': 'delegatecall'}}, {'function.has_low_level_call': {'op': 'delegatecall'}}, {'function.has_low_level_call': {'op': 'delegatecall'}}, {'function.has_low_level_call': {'op': 'delegatecall'}}, {'function.has_low_level_call': {'op': 'delegatecall'}}, {'function.has_low_level_call': {'op': 'delegatecall'}}, {'function.body_contains_regex': '\\.call\\s*\\{|\\.call\\s*\\(|\\.delegatecall'}, {'function.body_not_contains_regex': 'require\\s*\\(\\s*success|require\\s*\\(\\s*ok|if\\s*\\(\\s*!\\s*success\\s*\\)|revert\\s*\\(\\s*returndata'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — forwarder-nonce-increment-on-revert: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
