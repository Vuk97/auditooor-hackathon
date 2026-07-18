"""
certora-nonce-strictly-monotonic — generated from reference/patterns.dsl/certora-nonce-strictly-monotonic.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py certora-nonce-strictly-monotonic.yaml
Source: certora-examples/Nonce/strictlyMonotonic
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class CertoraNonceStrictlyMonotonic(AbstractDetector):
    ARGUMENT = "certora-nonce-strictly-monotonic"
    HELP = "Nonce storage is written with an arbitrary (possibly lower) value — Certora `strictlyMonotonic` invariant violated; opens replay window."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/certora-nonce-strictly-monotonic.yaml"
    WIKI_TITLE = "Nonce mutator can decrease or reset, enabling signature replay"
    WIKI_DESCRIPTION = "Certora's canonical signature spec proves `nonces[user]` is strictly increasing, so any signed message with a nonce <= the stored value reverts. A function that writes `nonces[user] = N` or `nonces[user] = 0` (rather than `nonces[user]++` / `+= 1`) lets an admin (or worse, the user themselves) rewind the counter and replay a previously accepted signed action."
    WIKI_EXPLOIT_SCENARIO = "A convenience `resetNonce(user)` is added (intended only for recovery, restricted by access list that turns out to be spoofable via EIP-2771 forwarder's msg.sender). Attacker resets Alice's nonce to 0 then re-submits Alice's already-executed permit / withdraw signature, draining Alice a second time."
    WIKI_RECOMMENDATION = "Nonces must only ever increment. Use OpenZeppelin `_useNonce` / `_useCheckedNonce` helpers. Never expose a nonce setter or admin reset; if a user truly needs invalidation, offer an `invalidateNoncesUpTo(n)` that can only increase. Reproduce the Certora monotonic-nonce invariant as a property test."

    _PRECONDITIONS = [{'contract.source_matches_regex': '.*'}, {'contract.has_state_var_matching': '(?i)(nonces|_nonces|userNonce|nonceOf|sigNonce)'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.is_mutating': True}, {'function.writes_storage_matching': '(?i)(nonces|_nonces|userNonce|nonceOf|sigNonce)'}, {'function.body_contains_regex': '(?i)(nonces\\s*\\[[^\\]]+\\]\\s*=\\s*(0|[a-zA-Z_]+\\s*[^+]|[^n]))'}, {'function.body_not_contains_regex': '(?i)(nonces\\s*\\[[^\\]]+\\]\\s*\\+\\+|\\+=\\s*1|_useNonce|_useCheckedNonce|nonces\\[[^\\]]+\\]\\s*=\\s*[a-zA-Z_0-9]+\\s*\\+\\s*1)'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — certora-nonce-strictly-monotonic: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
