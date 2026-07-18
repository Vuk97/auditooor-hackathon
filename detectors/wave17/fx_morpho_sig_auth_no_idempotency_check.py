"""
fx-morpho-sig-auth-no-idempotency-check — generated from reference/patterns.dsl/fx-morpho-sig-auth-no-idempotency-check.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py fx-morpho-sig-auth-no-idempotency-check.yaml
Source: github:morpho-org/morpho-blue@94c9f57
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class FxMorphoSigAuthNoIdempotencyCheck(AbstractDetector):
    ARGUMENT = "fx-morpho-sig-auth-no-idempotency-check"
    HELP = "Signature-based authorization setter consumes the nonce even when the new value equals the current value. An attacker who obtains any valid signed authorization can replay it with identical isAuthorized state, burning the signer's nonce and invalidating all higher-nonce pre-signed messages."
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/fx-morpho-sig-auth-no-idempotency-check.yaml"
    WIKI_TITLE = "Sig-auth nonce burned on no-op — missing idempotency check before ecrecover"
    WIKI_DESCRIPTION = "EIP-712 authorization-by-signature functions that increment the signer's nonce before checking whether the new authorization state differs from the current state allow a grief attack: any valid intercepted signature can be submitted with a matching (but unchanged) isAuthorized value. The nonce increments, the state does not change, and all pre-signed authorizations with higher nonces are permanent"
    WIKI_EXPLOIT_SCENARIO = "Morpho Blue (2023): setAuthorizationWithSig(auth, sig) where auth.isAuthorized matches isAuthorized[authorizer][authorized]. Nonce increments, no state change. All future pre-signed authorizations from authorizer are now invalid."
    WIKI_RECOMMENDATION = "Check `require(newValue != currentValue, ALREADY_SET)` before any state-based nonce consumption. Alternatively, check and revert inside the nonce-validation block if the transition is a no-op."

    _PRECONDITIONS = [{'contract.source_matches_regex': '.*'}, {'contract.has_function_matching': 'WithSig$|BySig$|withSig$|bySig$'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': 'WithSig$|BySig$|withSig$|bySig$'}, {'function.has_high_level_call_named': 'recover|ecrecover'}, {'function.has_high_level_call_named': 'recover|ecrecover'}, {'function.has_high_level_call_named': 'recover|ecrecover'}, {'function.has_high_level_call_named': 'recover|ecrecover'}, {'function.has_high_level_call_named': 'recover|ecrecover'}, {'function.has_high_level_call_named': 'recover|ecrecover'}, {'function.has_high_level_call_named': 'recover|ecrecover'}, {'function.has_high_level_call_named': 'recover|ecrecover'}, {'function.has_high_level_call_named': 'recover|ecrecover'}, {'function.has_high_level_call_named': 'recover|ecrecover'}, {'function.has_high_level_call_named': 'recover|ecrecover'}, {'function.has_high_level_call_named': 'recover|ecrecover'}, {'function.has_high_level_call_named': 'recover|ecrecover'}, {'function.has_high_level_call_named': 'recover|ecrecover'}, {'function.has_high_level_call_named': 'recover|ecrecover'}, {'function.body_contains_regex': 'nonce\\[|nonce\\s*\\+\\+|ecrecover'}, {'function.body_not_contains_regex': 'isAuthorized\\s*!=|newValue\\s*!=\\s*current|ALREADY_SET'}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — fx-morpho-sig-auth-no-idempotency-check: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
