"""
eip7702-erc1271-signer-impersonation — generated from reference/patterns.dsl/eip7702-erc1271-signer-impersonation.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py eip7702-erc1271-signer-impersonation.yaml
Source: auditooor-R73-eip7702-class
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class Eip7702Erc1271SignerImpersonation(AbstractDetector):
    ARGUMENT = "eip7702-erc1271-signer-impersonation"
    HELP = "SignatureChecker.isValidSignatureNow treats an EOA with code as a contract signer and calls isValidSignature (ERC-1271). With 7702, every delegated EOA now exposes its delegate's 1271 logic — signatures signed by the raw ECDSA key may no longer validate, and the 1271 code can accept arbitrary signat"
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/eip7702-erc1271-signer-impersonation.yaml"
    WIKI_TITLE = "ERC-1271 signature validation routes through 7702 delegate instead of raw ECDSA on EOA"
    WIKI_DESCRIPTION = "OpenZeppelin's SignatureChecker and most signature-verifying protocols dispatch: if `signer.code.length > 0` → call `signer.isValidSignature(hash, sig)`; else → ECDSA recover. EIP-7702 makes every delegated EOA a 'signer with code'. The recovery path is skipped in favor of the delegate's 1271 implementation. If the delegate was chosen by an attacker (or is a benign wallet with an off-by-one bug), "
    WIKI_EXPLOIT_SCENARIO = "User pre-signed a Permit2 allowance for trading. Attacker sees the pending permit in mempool. Attacker submits a 7702 authorization making the user's EOA delegate to a malicious 'AcceptAllSignatures' contract. Attacker then submits BOTH the user's original permit AND a second forged permit with the same domain/hash but larger amount. SignatureChecker hits `code.length > 0`, calls `isValidSignature"
    WIKI_RECOMMENDATION = "Do NOT blindly route to ERC-1271 on any signer with code. For OAuth-style permits where the wallet is expected to be an EOA, explicitly prefer ECDSA recovery. If 1271 support is required, require a nonce on the delegate's side as well — never accept a 1271-validated signature whose domain is the sig"

    _PRECONDITIONS = [{'contract.source_matches_regex': '(?i)isValidSignature|1271|SignatureChecker'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.body_contains_regex': '(?i)isValidSignature\\s*\\(\\s*(\\w+\\s*,\\s*)?bytes32'}, {'function.has_high_level_call_named': 'recover|ecrecover'}, {'function.has_high_level_call_named': 'recover|ecrecover'}, {'function.has_high_level_call_named': 'recover|ecrecover'}, {'function.has_high_level_call_named': 'recover|ecrecover'}, {'function.has_high_level_call_named': 'recover|ecrecover'}, {'function.has_high_level_call_named': 'recover|ecrecover'}, {'function.has_high_level_call_named': 'recover|ecrecover'}, {'function.has_high_level_call_named': 'recover|ecrecover'}, {'function.has_high_level_call_named': 'recover|ecrecover'}, {'function.has_high_level_call_named': 'recover|ecrecover'}, {'function.has_high_level_call_named': 'recover|ecrecover'}, {'function.has_high_level_call_named': 'recover|ecrecover'}, {'function.has_high_level_call_named': 'recover|ecrecover'}, {'function.has_high_level_call_named': 'recover|ecrecover'}, {'function.has_high_level_call_named': 'recover|ecrecover'}, {'function.body_contains_regex': '(?i)(ecrecover|ECDSA\\.recover|SignatureChecker\\.isValidSignatureNow)'}, {'function.body_not_contains_regex': '(?i)(isDelegated|_isDelegated|7702|authorizationList|extcodesize\\s*==\\s*23)'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — eip7702-erc1271-signer-impersonation: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
