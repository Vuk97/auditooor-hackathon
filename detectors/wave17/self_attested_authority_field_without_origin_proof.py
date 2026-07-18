"""
self-attested-authority-field-without-origin-proof - generated from reference/patterns.dsl/self-attested-authority-field-without-origin-proof.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py self-attested-authority-field-without-origin-proof.yaml
Source: lane/listing-authority-bypass-2026-06-02
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class SelfAttestedAuthorityFieldWithoutOriginProof(AbstractDetector):
    ARGUMENT = "self-attested-authority-field-without-origin-proof"
    HELP = "Attacker-supplied payload passes because an embedded authority field matches local state, but the function never proves that the authority itself approved or originated the payload."
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.LOW
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/self-attested-authority-field-without-origin-proof.yaml"
    WIKI_TITLE = "Authority claim is checked against local state without origin attestation"
    WIKI_DESCRIPTION = "Some handlers accept external payloads, orders, or proofs and validate only a self-attesting authority field inside that payload. In marketplace flows this appears as `ownerOf(assetId) == listing.seller` while the seller never signed the listing. In bridge flows it appears as `parsed.ethCustodian == address(this)` while the receipt origin is never proven. The local equality is real, but it does no"
    WIKI_EXPLOIT_SCENARIO = "A marketplace operator signs a listing for an NFT they do not own. The contract validates that `listing.seller` equals the current token owner, but it never checks a seller signature. Buyers accept the phantom listing even though the owner never approved the sale. The same invariant appears on bridges that trust an embedded destination field without proving source-chain origin."
    WIKI_RECOMMENDATION = "Bind the payload to the authority's own attestation. For listings, recover and verify a seller signature over the same struct before any state change. For proofs, verify a trusted relayer, outcome root, or light-client proof before trusting the embedded destination or custodian field."

    _PRECONDITIONS = [{'contract.source_matches_regex': '(?is)(ListingInput|seller|operatorSig|proofData|BurnResult|ethCustodian|ownerOf|verifyOutcome|ECDSA\\.recover)'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.body_contains_regex': '(?is)(ECDSA\\.recover|recover\\s*\\(|abi\\.decode\\s*\\(|parseProof)'}, {'function.body_contains_regex': '(?is)(ownerOf\\s*\\([^;{}]*\\)\\s*==\\s*(listing|order|input)\\.seller|(listing|order|input)\\.seller\\s*==\\s*ownerOf\\s*\\(|(ethCustodian|bridgeAddress|custodianAddress)\\s*==\\s*address\\s*\\(\\s*this\\s*\\))'}, {'function.body_not_contains_regex': '(?is)(verifyOutcome|outcomeRoot|merkleRoot|trustedRelayer|onlyRelayer|proofOrigin|_verifyHeader|sellerSigner\\s*==\\s*(listing|order|input)\\.seller|recoverSeller\\s*\\(|verifySeller\\s*\\(|tokenOwnerSig|assetOwnerSig|sellerSignature)'}, {'function.not_in_skip_list': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" - self-attested-authority-field-without-origin-proof: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
