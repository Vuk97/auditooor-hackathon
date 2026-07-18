"""
createart-signature-does-not-bind-config-params — generated from reference/patterns.dsl/createart-signature-does-not-bind-config-params.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py createart-signature-does-not-bind-config-params.yaml
Source: auditooor-R75-code4rena-2024-08-phi-70
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class CreateartSignatureDoesNotBindConfigParams(AbstractDetector):
    ARGUMENT = "createart-signature-does-not-bind-config-params"
    HELP = "createArt verifies a signature over signData but the config struct (receiver/artist/royalty) is a separate arg not included in the signed hash — attacker front-runs and sets themselves as beneficiary."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.HIGH
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/createart-signature-does-not-bind-config-params.yaml"
    WIKI_TITLE = "createArt signature covers signData but not config, enabling front-run with attacker-owned config"
    WIKI_DESCRIPTION = "`createArt(signData, signature, config)` checks that `signData` was signed by the trusted signer. The `config` struct — containing `artist`, `royaltyReceiver`, `royaltyBps`, `maxSupply` etc. — is a free parameter. Attacker observes the mempool, extracts signData+signature, and submits a transaction with their own config (themselves as royalty receiver). The second call (original creator) also succ"
    WIKI_EXPLOIT_SCENARIO = "Artist Alice submits createArt(signData, sig, {receiver = Alice, royaltyBps = 500}). Attacker front-runs with {receiver = Attacker, royaltyBps = 1000}. Attacker's tx mines first, setting them as royalty receiver and artist. Alice's tx later executes harmlessly. All royalties on future mints flow to Attacker."
    WIKI_RECOMMENDATION = "Include the full config struct in the signed digest: `hash = keccak256(abi.encode(signData, config))`. Use EIP-712 typed data so each field is explicitly bound."

    _PRECONDITIONS = [{'contract.source_matches_regex': '.*'}]
    _MATCH = [{'function.kind': 'external'}, {'function.name_matches': '(?i)createArt|createCollection|createCampaign|mintWithSig'}, {'function.body_contains_regex': '(?i)\\.config|CreateConfig|_?config_?\\.'}, {'function.has_high_level_call_named': 'recover|ecrecover'}, {'function.has_high_level_call_named': 'recover|ecrecover'}, {'function.has_high_level_call_named': 'recover|ecrecover'}, {'function.has_high_level_call_named': 'recover|ecrecover'}, {'function.has_high_level_call_named': 'recover|ecrecover'}, {'function.has_high_level_call_named': 'recover|ecrecover'}, {'function.has_high_level_call_named': 'recover|ecrecover'}, {'function.has_high_level_call_named': 'recover|ecrecover'}, {'function.has_high_level_call_named': 'recover|ecrecover'}, {'function.has_high_level_call_named': 'recover|ecrecover'}, {'function.has_high_level_call_named': 'recover|ecrecover'}, {'function.has_high_level_call_named': 'recover|ecrecover'}, {'function.has_high_level_call_named': 'recover|ecrecover'}, {'function.body_contains_regex': '(?i)_recoverSigner|ECDSA\\.recover|SignatureChecker'}, {'function.body_not_contains_regex': '(?i)keccak256\\s*\\([^)]*config|hash\\s*\\([^)]*config|abi\\.encode\\s*\\([^)]*config'}, {'function.not_in_skip_list': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — createart-signature-does-not-bind-config-params: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
