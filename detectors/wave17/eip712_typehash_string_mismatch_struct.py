"""
eip712-typehash-string-mismatch-struct — generated from reference/patterns.dsl/eip712-typehash-string-mismatch-struct.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py eip712-typehash-string-mismatch-struct.yaml
Source: auditooor-cross-cluster
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class Eip712TypehashStringMismatchStruct(AbstractDetector):
    ARGUMENT = "eip712-typehash-string-mismatch-struct"
    HELP = "EIP-712 typehash string literal and abi.encode field list may not match — wallet signatures will fail digest comparison and every meta-tx is silently rejected. Manual field-for-field review required."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.LOW
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/eip712-typehash-string-mismatch-struct.yaml"
    WIKI_TITLE = "EIP-712 typehash string literal mismatches the encoded struct fields"
    WIKI_DESCRIPTION = "The contract declares a bytes32 TYPEHASH as keccak256 of a string of the form `Struct(type field,...)`, then at digest-construction time calls `keccak256(abi.encode(TYPEHASH, field1, field2, ...))`. EIP-712 requires the string literal, the order and types of the fields named in that literal, and the expression list passed to abi.encode to agree exactly. Any divergence — a renamed field, an extra/m"
    WIKI_EXPLOIT_SCENARIO = "A DEX declares PERMIT_TYPEHASH = keccak256('Permit(address owner,address spender,uint256 value,uint256 nonce,uint256 deadline)') but at digest time calls abi.encode(PERMIT_TYPEHASH, owner, spender, value, deadline, nonce) — deadline and nonce are swapped. Every user who calls `eth_signTypedData_v4` against the declared struct produces a signature over the correct field order; the contract hashes a"
    WIKI_RECOMMENDATION = "Audit the typehash string literal against the abi.encode field list field-by-field, byte-by-byte. Prefer OpenZeppelin's EIP712 / ECDSA / drafts-ERC20Permit base contracts which derive the struct hash from a single canonical declaration. When rolling your own, add a unit test that signs with `eth_sig"

    _PRECONDITIONS = [{'contract.source_matches_regex': '(EIP712|TYPEHASH|DOMAIN_SEPARATOR|_hashTypedDataV4|signTypedData|Permit|MetaTransaction|ECDSA|ecrecover|abi\\.encode\\s*\\(\\s*\\w*TYPEHASH)'}]
    _MATCH = [{'function.name_matches': '^(_?hash|_?hashStruct|_?hashTypedData|_?hashTypedDataV4|_?hashPermit|_?digest|_?digestTypedData|_?computeHash|_?computeDigest|_?computeTypedDataHash|_?buildHash|_?buildDigest|_?buildTypedData|permit|_?permit|_?permitWithSig|executeMetaTransaction|verifySignature|_?verifyTypedData|_?verifyPermit|_?recover|_?recoverSigner|_?recoverFromSig|_?validateSignature|_?validatePermit|_?domainSeparator|DOMAIN_SEPARATOR)$'}, {'function.computes_keccak': True}, {'function.computes_keccak': True}, {'function.computes_keccak': True}, {'function.computes_keccak': True}, {'function.computes_keccak': True}, {'function.computes_keccak': True}, {'function.computes_keccak': True}, {'function.computes_keccak': True}, {'function.computes_keccak': True}, {'function.computes_keccak': True}, {'function.computes_keccak': True}, {'function.computes_keccak': True}, {'function.computes_keccak': True}, {'function.computes_keccak': True}, {'function.computes_keccak': True}, {'function.body_contains_regex': 'keccak256\\s*\\(\\s*"[^"]*\\([^)]*\\)"|bytes32\\s+(constant|immutable)?\\s*\\w*TYPEHASH\\s*='}, {'function.body_contains_regex': 'abi\\.encode\\s*\\(\\s*\\w+_?TYPEHASH|TYPEHASH\\s*,'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(super\\._hashTypedDataV4|ERC20Permit\\.|EIP712\\.|drafts-ERC20Permit|view\\s+returns\\s*\\(\\s*bytes32\\s*\\)\\s*\\{\\s*return\\s+_DOMAIN_SEPARATOR|pure\\s+returns)'}]

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
                info = [f, f" — eip712-typehash-string-mismatch-struct: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
