"""
halborn-eip5267-eip6492-signature-delegate-verifier-miss — generated from reference/patterns.dsl/halborn-eip5267-eip6492-signature-delegate-verifier-miss.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py halborn-eip5267-eip6492-signature-delegate-verifier-miss.yaml
Source: auditooor-R75-halborn-AA-Signer-EIP6492-predeploy
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class HalbornEip5267Eip6492SignatureDelegateVerifierMiss(AbstractDetector):
    ARGUMENT = "halborn-eip5267-eip6492-signature-delegate-verifier-miss"
    HELP = "Contract verifies ERC-1271 smart-account signatures but does not handle EIP-6492 pre-deploy signatures — smart accounts that haven't been deployed yet cannot sign, breaking counterfactual-wallet UX and allowing signature-replay on old deployments."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/halborn-eip5267-eip6492-signature-delegate-verifier-miss.yaml"
    WIKI_TITLE = "Signature verifier supports ERC-1271 but not EIP-6492 (counterfactual / pre-deploy signatures)"
    WIKI_DESCRIPTION = "Smart-wallet adoption (Safe, EOA-migration, account-abstraction) uses counterfactual addresses — an address derived from CREATE2 with predictable init bytecode, not yet deployed. EIP-6492 defines a signature format (wraps a standard sig with a magic suffix `0x6492649264926492...`) that lets a verifier detect pre-deploy sigs, first deploy the account via a factory call embedded in the sig, and then"
    WIKI_EXPLOIT_SCENARIO = "Order-fill protocol supports ERC-1271 for smart-wallet sigs. Alice's Safe is counterfactual at 0xA... (not yet deployed). She signs an order with the EIP-6492 wrapper. Protocol's `isValidSignature` strips nothing, calls `IERC1271(0xA).isValidSignature(...)` — call reverts because 0xA has no code. Alice's order cannot be filled. Inverse: Bob reuses Alice's old sig against a newly-deployed factory-c"
    WIKI_RECOMMENDATION = "Use OpenZeppelin's `SignatureChecker.isValidSignatureNow(signer, hash, sig)` from version ≥5.0 which handles EIP-6492 by default (or the ambire-team reference impl). Detect the magic suffix `0x6492649264926492...`, split off the pre-deploy factory call, deploy the account, then forward to `isValidSi"

    _PRECONDITIONS = [{'contract.source_matches_regex': 'ERC1271|isValidSignature|EIP6492|smartAccount|AccountAbstraction|Delegation'}]
    _MATCH = [{'function.kind': 'external_or_public_or_internal'}, {'function.name_matches': 'isValidSignature|_validateSignature|recoverSigner|_verifySignature'}, {'function.body_contains_regex': 'IERC1271|0x1626ba7e|_isValidSignatureNow'}, {'function.body_not_contains_regex': '0x6492649264926492|EIP6492|ERC6492|predeploy.*signature|undeployedSigner|counterfactual'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — halborn-eip5267-eip6492-signature-delegate-verifier-miss: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
