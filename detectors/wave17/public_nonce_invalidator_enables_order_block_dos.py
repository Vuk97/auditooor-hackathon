"""
public-nonce-invalidator-enables-order-block-dos - generated from reference/patterns.dsl/public-nonce-invalidator-enables-order-block-dos.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py public-nonce-invalidator-enables-order-block-dos.yaml
Source: auditooor-R75-zellic-bebop-MEDIUM
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class PublicNonceInvalidatorEnablesOrderBlockDos(AbstractDetector):
    ARGUMENT = "public-nonce-invalidator-enables-order-block-dos"
    HELP = "An externally callable (public/external) function that marks a maker/taker nonce as used can be front-run by an attacker to burn any pending signed order's nonce, permanently blocking its settlement. Nonce invalidation must either be gated to the signer or executed only inside the settlement flow."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.HIGH
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/public-nonce-invalidator-enables-order-block-dos.yaml"
    WIKI_TITLE = "Externally callable nonce-invalidator enables permanent order-block DoS"
    WIKI_DESCRIPTION = "Fixture-smoke/source-shape proof only. NOT_SUBMIT_READY. RFQ/intents systems track used nonces to prevent replay. A public invalidator that writes the maker nonce bitmap without signer/caller auth lets any third party burn a live signed order nonce before settlement, making that order unfillable until the maker signs a replacement."
    WIKI_EXPLOIT_SCENARIO = "Alice signs an RFQ aggregate order with nonce 42. A rival solver front-runs the settler's SettleAggregateOrder transaction by calling the public assertAndInvalidateAggregateOrder alone, flipping nonce 42's bit. Alice's signed order now reverts on settlement. Repeated for every order, the protocol is DoS'd."
    WIKI_RECOMMENDATION = "Change visibility of standalone invalidator functions to internal, or require msg.sender == signer/maker/taker. The nonce should only be burned as part of an atomic settlement that also transfers assets. Keep this row NOT_SUBMIT_READY until validation expands beyond the owned fixture pair."

    _PRECONDITIONS = [{'contract.source_matches_regex': '(?s)(nonce|invalidat|Settle|Fill).{0,400}(Order|Intent|Quote|Aggregate)'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': '(assertAndInvalidate|invalidate|cancel|consume)[A-Z][a-zA-Z]*'}, {'function.has_param_name_matching': '(maker|taker|signer|offerer|owner|order)'}, {'function.writes_storage_matching': '(invalidatorStorage|nonceBitmap|usedNonces|orderStatus)'}, {'function.body_contains_regex': '(invalidatorStorage|nonceBitmap|usedNonces|orderStatus)\\s*(?:\\[[^\\]]+\\]\\s*){1,3}(=|\\|=)'}, {'function.body_not_contains_regex': '(?s)(require|assert)\\s*\\([^;]*(msg\\.sender\\s*==\\s*(maker|taker|signer|offerer|owner)|(?:maker|taker|signer|offerer|owner)\\s*==\\s*msg\\.sender)'}, {'function.body_not_contains_regex': '(ECDSA\\.recover|ecrecover|isValidSignature|SignatureChecker)'}, {'function.has_modifier': {'includes': ['onlyOwner', 'onlyRole', 'onlySigner', 'onlyMaker', 'onlyTaker'], 'negate': True}}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" - public-nonce-invalidator-enables-order-block-dos: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
