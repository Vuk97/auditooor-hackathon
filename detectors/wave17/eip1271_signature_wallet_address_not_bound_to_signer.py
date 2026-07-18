"""
eip1271-signature-wallet-address-not-bound-to-signer — generated from reference/patterns.dsl/eip1271-signature-wallet-address-not-bound-to-signer.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py eip1271-signature-wallet-address-not-bound-to-signer.yaml
Source: auditooor-R75-zellic-bebop-CRITICAL
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class Eip1271SignatureWalletAddressNotBoundToSigner(AbstractDetector):
    ARGUMENT = "eip1271-signature-wallet-address-not-bound-to-signer"
    HELP = "EIP-1271 isValidSignature is called on a wallet address supplied by the same caller that supplies the purported maker/taker identity — nothing binds the 1271 wallet to the claimed signer. Any attacker can point walletAddress at an attacker contract that returns MAGICVALUE unconditionally and forge t"
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.HIGH
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/eip1271-signature-wallet-address-not-bound-to-signer.yaml"
    WIKI_TITLE = "EIP-1271 wallet address not bound to the claimed signer identity"
    WIKI_DESCRIPTION = "RFQ / intent / settlement contracts that accept both an 'owner address' (maker, taker, offerer) and a signature struct containing the EIP-1271 wallet address must require walletAddress == claimed_signer. Otherwise the EIP-1271 validity check is performed against an attacker-controlled contract, which can always return the magic value, allowing arbitrary trade forgery."
    WIKI_EXPLOIT_SCENARIO = "Alice has granted the RFQ aggregator token approval. A malicious taker submits an aggregate order claiming Alice as the maker but sets signature.walletAddress to a contract controlled by the attacker whose isValidSignature always returns the magic value. The signature check passes, the aggregator pulls Alice's tokens at an extremely unfavorable price."
    WIKI_RECOMMENDATION = "Require signature.walletAddress == maker_address (or drop walletAddress entirely and always call IERC1271(maker_address).isValidSignature). The EIP-1271 verifier contract must be the maker/signer's own smart wallet, not an arbitrary third-party contract."

    _PRECONDITIONS = [{'contract.source_matches_regex': 'isValidSignature|EIP1271|IERC1271'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': '^(validate|verify|check|_validate|_verify|_check)(Signature|SingleOrder|Order|Orders|Trade|Maker|Taker|MakerOrder|TakerOrder|OrderSignature|Intent)$'}, {'function.body_contains_regex': '(IERC1271|isValidSignature)\\s*\\(\\s*([a-zA-Z_][a-zA-Z_0-9]*)\\s*\\)\\.isValidSignature'}, {'function.body_not_contains_regex': 'require\\s*\\(\\s*[a-zA-Z_0-9.]+(wallet|signer|walletAddress)\\s*==\\s*[a-zA-Z_0-9.]+(maker|taker|owner|trader|offerer)'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — eip1271-signature-wallet-address-not-bound-to-signer: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
