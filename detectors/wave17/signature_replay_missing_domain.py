"""
signature-replay-missing-domain — generated from reference/patterns.dsl/signature-replay-missing-domain.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py signature-replay-missing-domain.yaml
Source: solodit-cluster-C0206
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class SignatureReplayMissingDomain(AbstractDetector):
    ARGUMENT = "signature-replay-missing-domain"
    HELP = "Signature verified via ecrecover/SignatureChecker without EIP-712 domain, chainId, or nonce binding — enables cross-domain/cross-chain replay."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.LOW
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/signature-replay-missing-domain.yaml"
    WIKI_TITLE = "Signature replay: missing EIP-712 domain / nonce / chainId binding"
    WIKI_DESCRIPTION = "Signatures recovered via ecrecover or SignatureChecker must be bound to a domain separator (EIP-712), a nonce, and the current chainId. Without all three, the same signature can be replayed across contracts, chains, or repeatedly against the same contract."
    WIKI_EXPLOIT_SCENARIO = "Attacker captures a valid signature intended for one deployment. Because the digest omits the domain separator / chainId / nonce, the same signed payload is replayed on a sister deployment (different chain, different contract, or after the original was already consumed) to authorize duplicate withdrawals, permits, or meta-tx executions."
    WIKI_RECOMMENDATION = "Bind every recovered digest to (a) EIP-712 domain separator including block.chainid and address(this), (b) a per-signer nonce incremented on use, and (c) an explicit expiry/deadline. Prefer OpenZeppelin EIP712 + Nonces."

    _PRECONDITIONS = [{'contract.source_matches_regex': '.*'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.has_high_level_call_named': 'recover|ecrecover'}, {'function.has_high_level_call_named': 'recover|ecrecover'}, {'function.has_high_level_call_named': 'recover|ecrecover'}, {'function.has_high_level_call_named': 'recover|ecrecover'}, {'function.has_high_level_call_named': 'recover|ecrecover'}, {'function.has_high_level_call_named': 'recover|ecrecover'}, {'function.has_high_level_call_named': 'recover|ecrecover'}, {'function.has_high_level_call_named': 'recover|ecrecover'}, {'function.has_high_level_call_named': 'recover|ecrecover'}, {'function.has_high_level_call_named': 'recover|ecrecover'}, {'function.has_high_level_call_named': 'recover|ecrecover'}, {'function.has_high_level_call_named': 'recover|ecrecover'}, {'function.has_high_level_call_named': 'recover|ecrecover'}, {'function.has_high_level_call_named': 'recover|ecrecover'}, {'function.has_high_level_call_named': 'recover|ecrecover'}, {'function.body_contains_regex': 'ecrecover\\s*\\(|SignatureChecker\\.isValidSignature|isValidSignatureNow'}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — signature-replay-missing-domain: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
