"""
multisig-sig-replay-nonce-missing — generated from reference/patterns.dsl/multisig-sig-replay-nonce-missing.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py multisig-sig-replay-nonce-missing.yaml
Source: auditooor
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class MultisigSigReplayNonceMissing(AbstractDetector):
    ARGUMENT = "multisig-sig-replay-nonce-missing"
    HELP = "Multisig execTransaction verifies a batch of owner signatures but does not consume a per-tx nonce — the same N signatures replay across multiple (params, data) tuples."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.LOW
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/multisig-sig-replay-nonce-missing.yaml"
    WIKI_TITLE = "Multisig execTransaction: signature set can be replayed because no per-tx nonce is consumed"
    WIKI_DESCRIPTION = "A multisig entry-point (execTransaction / executeTransaction / execute) verifies a batched set of owner signatures via ecrecover / SignatureChecker / ERC-1271, but the signed digest is not bound to, and the function does not advance, a per-contract or per-owner nonce. The same N collected signatures remain valid across different (target, value, data) tuples, so any one owner (or a leaked signature"
    WIKI_EXPLOIT_SCENARIO = "Owners sign off on a batch intended to transfer 10 ETH to a vendor. The signatures are collected on-chain in a public mempool tx. A malicious owner (or an attacker that scraped the signatures) observes that execTransaction rebuilds the digest from the `(to, value, data)` parameters but never incorporates a nonce. The attacker reassembles the same signature set and calls execTransaction with `(atta"
    WIKI_RECOMMENDATION = "Bind every execution to a per-contract monotonic `nonce` and include that nonce in the signed digest. On successful execution, advance the nonce (e.g. `nonce++`) BEFORE dispatching the inner call so the same signature set cannot be used twice. Follow the Gnosis Safe pattern: compute `transactionHash"

    _PRECONDITIONS = [{'contract.source_matches_regex': '.*'}, {'contract.has_state_var_matching': 'threshold|owners|signers|confirmations'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': '^(execTransaction|executeTransaction|execute|_execTransaction)$'}, {'function.has_high_level_call_named': 'recover|ecrecover'}, {'function.has_high_level_call_named': 'recover|ecrecover'}, {'function.has_high_level_call_named': 'recover|ecrecover'}, {'function.has_high_level_call_named': 'recover|ecrecover'}, {'function.has_high_level_call_named': 'recover|ecrecover'}, {'function.has_high_level_call_named': 'recover|ecrecover'}, {'function.has_high_level_call_named': 'recover|ecrecover'}, {'function.has_high_level_call_named': 'recover|ecrecover'}, {'function.has_high_level_call_named': 'recover|ecrecover'}, {'function.has_high_level_call_named': 'recover|ecrecover'}, {'function.has_high_level_call_named': 'recover|ecrecover'}, {'function.has_high_level_call_named': 'recover|ecrecover'}, {'function.has_high_level_call_named': 'recover|ecrecover'}, {'function.has_high_level_call_named': 'recover|ecrecover'}, {'function.has_high_level_call_named': 'recover|ecrecover'}, {'function.body_contains_regex': 'for\\s*\\([^)]*signatures|ecrecover\\s*\\(|SignatureChecker|isValidSignature'}, {'function.body_not_contains_regex': 'nonce\\s*\\+\\+|nonce\\s*=\\s*nonce\\s*\\+|nonces\\[|_nonce\\s*\\+\\s*1|transactionHash'}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — multisig-sig-replay-nonce-missing: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
