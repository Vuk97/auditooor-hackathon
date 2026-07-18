"""
bridge-signature-missing-contract-address — generated from reference/patterns.dsl/bridge-signature-missing-contract-address.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py bridge-signature-missing-contract-address.yaml
Source: solodit/trailofbits/polkaswap-48894
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class BridgeSignatureMissingContractAddress(AbstractDetector):
    ARGUMENT = "bridge-signature-missing-contract-address"
    HELP = "Signature-verification hash is built via `keccak256(abi.encodePacked(...))` but omits `address(this)` and `block.chainid` (or uses a constructor-captured networkId that never refreshes on fork). Signatures become replayable across deployments and chain forks."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/bridge-signature-missing-contract-address.yaml"
    WIKI_TITLE = "Signature hash omits contract address and live chainid — cross-instance replay"
    WIKI_DESCRIPTION = "A bridge / multisig / relay contract recovers signer sets over a hash that uses only business parameters (token, amount, txHash, recipient) and omits both `address(this)` and the live `block.chainid`. If the contract is redeployed (upgraded bridge, L1+L2 pair, ChainID-fork) the same signer set signs both instances' messages with identical hashes. Any signature gathered in one deployment becomes a "
    WIKI_EXPLOIT_SCENARIO = "Bridge v1 and Bridge v2 (migration) share the same 5-of-7 validator set and share the hashing scheme `keccak256(abi.encodePacked(newPeer, txHash, networkId))`. During the migration cut-over, validators co-sign 'add Eve as peer on Bridge v2'. Attacker takes the same signatures and submits them to `addPeer` on Bridge v1, where `newPeer` and `txHash` match; the hash and signer set validate, Eve is no"
    WIKI_RECOMMENDATION = "Adopt EIP-712: compute a DOMAIN_SEPARATOR bound to `(name, version, block.chainid, address(this))`, and make DOMAIN_SEPARATOR a function — not a constant — so it refreshes on fork. Every signed payload's hash must include the domain separator via `keccak256(abi.encodePacked('\\x19\\x01', DOMAIN_SEPA"

    _PRECONDITIONS = [{'contract.source_matches_regex': '.*'}, {'contract.body_contains_regex': 'ecrecover\\s*\\(|ECDSA\\.recover|\\.recover\\s*\\('}]
    _MATCH = [{'function.kind': 'internal_or_external'}, {'function.computes_keccak': True}, {'function.computes_keccak': True}, {'function.computes_keccak': True}, {'function.computes_keccak': True}, {'function.body_contains_regex': 'keccak256\\s*\\(\\s*abi\\.encode(Packed)?\\s*\\('}, {'function.has_high_level_call_named': 'recover|ecrecover'}, {'function.has_high_level_call_named': 'recover|ecrecover'}, {'function.has_high_level_call_named': 'recover|ecrecover'}, {'function.has_high_level_call_named': 'recover|ecrecover'}, {'function.body_contains_regex': 'ecrecover\\s*\\(|\\.recover\\s*\\('}, {'function.body_not_contains_regex': 'abi\\.encode(Packed)?\\s*\\([^)]*address\\s*\\(\\s*this\\s*\\)|abi\\.encode(Packed)?\\s*\\([^)]*block\\.chainid|abi\\.encode(Packed)?\\s*\\([^)]*_DOMAIN_SEPARATOR|EIP712'}, {'function.body_not_contains_regex': 'block\\.chainid\\s*==|require\\s*\\(\\s*block\\.chainid'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — bridge-signature-missing-contract-address: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
