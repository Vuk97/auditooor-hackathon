"""
erc7683-ordertype-hash-missing-nonce-field-eip712-desync — generated from reference/patterns.dsl/erc7683-ordertype-hash-missing-nonce-field-eip712-desync.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py erc7683-ordertype-hash-missing-nonce-field-eip712-desync.yaml
Source: auditooor-R73-fixdiff-mined-across-644239d408
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class Erc7683OrdertypeHashMissingNonceFieldEip712Desync(AbstractDetector):
    ARGUMENT = "erc7683-ordertype-hash-missing-nonce-field-eip712-desync"
    HELP = "ERC-7683 order libraries that declare `depositNonce` inside the TYPE_HASH string but omit it from the abi.encode(...) argument list in `hashOrderData` produce an EIP-712 digest that does not match the declared type. Wallets and Permit2 frontends signing the typed struct will compute a different dige"
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/erc7683-ordertype-hash-missing-nonce-field-eip712-desync.yaml"
    WIKI_TITLE = "ERC-7683 hashOrderData omits depositNonce despite its presence in TYPE_HASH — EIP-712 replay/mismatch"
    WIKI_DESCRIPTION = "Across's AcrossOrderData struct has a `depositNonce` field that the TYPE_HASH string declares; the Solidity `hashOrderData` originally abi.encode'd every other field but skipped `depositNonce`. Two related failures: (A) wallets rendering the EIP-712 typed data view include depositNonce; wallets that compute the digest from the struct (as Permit2/EIP-712 libs do) include depositNonce. Either path d"
    WIKI_EXPLOIT_SCENARIO = "User signs a gasless AcrossOrder with depositNonce=5, inputAmount=1000, outputAmount=950, recipient=Alice. Relayer submits. The verifier rebuilds the digest via hashOrderData (no depositNonce) — matches signature. On-chain state stores a depositId keyed off (msg.sender, depositNonce=5). Attacker picks the same signed blob, submits with `orderData.depositNonce=6` (not covered by hash). Verifier aga"
    WIKI_RECOMMENDATION = "Auto-generate the abi.encode argument list from the TYPE_HASH string via codegen, or write a differential test: for every field in the TYPE_HASH, perturb it in two orders and assert hashOrderData returns different values. For the speedUp/fill typehash collision, unify on a single `bytes32 updatedRec"

    _PRECONDITIONS = [{'contract.source_matches_regex': 'ERC7683|AcrossOrderData|Permit2Lib|hashOrderData|depositNonce|speedUpDeposit'}]
    _MATCH = [{'function.kind': 'external_or_public_or_internal'}, {'function.name_matches': 'hashOrderData|_hashOrderData|ACROSS_ORDER_DATA_TYPE_HASH|typeHash'}, {'function.body_contains_regex': 'depositNonce|deposit_nonce|orderData\\.depositNonce'}, {'function.body_contains_regex': 'abi\\.encode\\s*\\('}, {'function.body_not_contains_regex': 'orderData\\.depositNonce\\s*,|depositNonce\\s*,'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — erc7683-ordertype-hash-missing-nonce-field-eip712-desync: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
