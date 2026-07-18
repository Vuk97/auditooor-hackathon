"""
eip-712-domain-type-hash-mismatch-breaks-signature-based-del-x — generated from reference/patterns.dsl/eip-712-domain-type-hash-mismatch-breaks-signature-based-del-x.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py eip-712-domain-type-hash-mismatch-breaks-signature-based-del-x.yaml
Source: code4arena/2025-05-blackhole
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class Eip712DomainTypeHashMismatchBreaksSignatureBasedDelX(AbstractDetector):
    ARGUMENT = "eip-712-domain-type-hash-mismatch-breaks-signature-based-del-x"
    HELP = "EIP-712 DOMAIN_TYPEHASH field list does not match the later domain abi.encode payload."
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/eip-712-domain-type-hash-mismatch-breaks-signature-based-del-x.yaml"
    WIKI_TITLE = "EIP-712 domain type hash mismatch breaks signature-based delegation"
    WIKI_DESCRIPTION = "If a contract defines its `EIP712Domain(...)` typehash with one field list but later builds the domain separator with a different field count, off-chain signers and on-chain verification derive different domain separators. Signature-based delegation and permit flows then fail or verify the wrong digest."
    WIKI_EXPLOIT_SCENARIO = "A VotingEscrow-style contract hashes `EIP712Domain(string name,uint256 chainId,address verifyingContract)` into `DOMAIN_TYPEHASH` but computes the separator with `abi.encode(DOMAIN_TYPEHASH, nameHash, versionHash, block.chainid, address(this))`. Signatures built off-chain against the intended four-field domain do not match the three-field on-chain typehash."
    WIKI_RECOMMENDATION = "Keep the `EIP712Domain(...)` type string exactly aligned with the fields encoded into `abi.encode(DOMAIN_TYPEHASH, ...)`. If a version hash is encoded, declare `string version` in the type string; otherwise remove the extra encoded field."

    _PRECONDITIONS = []
    _MATCH = []

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
                info = [f, f" — eip-712-domain-type-hash-mismatch-breaks-signature-based-del-x: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
