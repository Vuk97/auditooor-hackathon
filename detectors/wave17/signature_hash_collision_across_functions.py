"""
signature-hash-collision-across-functions — generated from reference/patterns.dsl/signature-hash-collision-across-functions.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py signature-hash-collision-across-functions.yaml
Source: solodit/trailofbits/polkaswap-48893
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class SignatureHashCollisionAcrossFunctions(AbstractDetector):
    ARGUMENT = "signature-hash-collision-across-functions"
    HELP = "Multiple signature-gated functions in the contract hash identically-shaped payloads (address, bytes32, networkId) without any function-discriminant. Signatures collected for one function can be replayed into the other."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/signature-hash-collision-across-functions.yaml"
    WIKI_TITLE = "Same hash shape across signature-gated functions allows cross-function replay"
    WIKI_DESCRIPTION = "A contract exposes several actions each authenticated by a peer-signature scheme: add peer, remove peer, prepare migration, etc. Each function hashes its payload as `keccak256(abi.encodePacked(address, bytes32, networkId))`. Because the hashes across functions are structurally identical and no function tag / EIP-712 typehash / selector is mixed in, a signature gathered for one action (migration) i"
    WIKI_EXPLOIT_SCENARIO = "Peers sign `prepareForMigration(thisContract, salt, networkId)` to start a bridge upgrade. Attacker takes the same (v,r,s) and calls `addPeerByPeer(thisContract, salt, v, r, s)`. The check `checkSignatures(keccak256(abi.encodePacked(thisContract, salt, networkId)), ...)` passes with the same recovered signer set, and the bridge contract address is added as a peer — but the bridge can never sign, s"
    WIKI_RECOMMENDATION = "Adopt EIP-712 with distinct `TYPEHASH` constants per function: `keccak256('AddPeer(address newPeer,bytes32 txHash,bytes32 networkId)')`, a separate typehash for `RemovePeer`, a separate one for `PrepareForMigration`. Hash the struct as `keccak256(abi.encode(TYPEHASH_ADDPEER, ...))`. Signatures now c"

    _PRECONDITIONS = [{'contract.source_matches_regex': '.*'}, {'contract.body_contains_regex': 'keccak256\\s*\\(\\s*abi\\.encode(Packed)?'}, {'contract.has_multiple_funcs_doing': 'checkSignatures|ecrecover'}]
    _MATCH = [{'function.kind': 'internal_or_external'}, {'function.computes_keccak': True}, {'function.computes_keccak': True}, {'function.computes_keccak': True}, {'function.body_contains_regex': 'keccak256\\s*\\(\\s*abi\\.encode(Packed)?\\s*\\('}, {'function.has_high_level_call_named': 'recover|ecrecover'}, {'function.has_high_level_call_named': 'recover|ecrecover'}, {'function.has_high_level_call_named': 'recover|ecrecover'}, {'function.body_contains_regex': 'checkSignatures\\s*\\(|ecrecover\\s*\\(|\\.recover\\s*\\('}, {'function.body_not_contains_regex': 'keccak256\\s*\\(\\s*["\\047][^"\\047]{4,}(prepareForMigration|addPeerByPeer|removePeerByPeer)|TYPEHASH\\s*=\\s*keccak256|FUNCTION_TAG|OP_\\w+\\s*='}, {'function.body_not_contains_regex': 'selector|abi\\.encode\\s*\\([^)]*\\.selector'}, {'contract.has_func_body_matching': 'keccak256\\s*\\(\\s*abi\\.encodePacked\\s*\\(\\s*\\w+,\\s*\\w+,\\s*_networkId'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — signature-hash-collision-across-functions: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
