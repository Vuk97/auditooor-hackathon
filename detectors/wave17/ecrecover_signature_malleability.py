"""
ecrecover-signature-malleability — generated from reference/patterns.dsl/ecrecover-signature-malleability.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py ecrecover-signature-malleability.yaml
Source: auditooor-classic
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class EcrecoverSignatureMalleability(AbstractDetector):
    ARGUMENT = "ecrecover-signature-malleability"
    HELP = "Direct ecrecover() call with no s-bound check — the signature (v, r, s) has a twin (v', r, N-s) that recovers to the same signer, breaking any replay guard keyed on signature uniqueness."
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/ecrecover-signature-malleability.yaml"
    WIKI_TITLE = "ECDSA signature malleability via unbounded s-component in ecrecover"
    WIKI_DESCRIPTION = "The function invokes Solidity's `ecrecover(hash, v, r, s)` precompile directly and does not constrain `s` to the lower half of the secp256k1 group (`s <= secp256k1n / 2`). secp256k1 signatures are symmetric: for every (v, r, s) there exists a second (v', r, N-s) that recovers the same address. If the contract uses signature bytes or the hash of signature bytes as a replay-protection key (nonceless"
    WIKI_EXPLOIT_SCENARIO = "A DEX stores `mapping(bytes32 => bool) usedSig;` keyed on `keccak256(abi.encodePacked(v, r, s))` to prevent order replay. Alice signs an order. Her order fills once. The attacker observes the (v, r, s) in the mempool or in calldata of the filled tx, computes s' = N - s and v' = v XOR 1, and submits the identical order with the malleable tuple. `ecrecover` returns Alice's address so the order valid"
    WIKI_RECOMMENDATION = "Never call `ecrecover` directly. Use OpenZeppelin's `ECDSA.recover` / `ECDSA.tryRecover` which enforces `s <= 0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0` and rejects `v` outside {27, 28}, per EIP-2. Prefer `SignatureChecker` when ERC-1271 smart-contract signatures are also ac"

    _PRECONDITIONS = [{'contract.source_matches_regex': '.*'}]
    _MATCH = [{'function.has_high_level_call_named': 'recover|ecrecover'}, {'function.has_high_level_call_named': 'recover|ecrecover'}, {'function.has_high_level_call_named': 'recover|ecrecover'}, {'function.has_high_level_call_named': 'recover|ecrecover'}, {'function.has_high_level_call_named': 'recover|ecrecover'}, {'function.has_high_level_call_named': 'recover|ecrecover'}, {'function.has_high_level_call_named': 'recover|ecrecover'}, {'function.has_high_level_call_named': 'recover|ecrecover'}, {'function.has_high_level_call_named': 'recover|ecrecover'}, {'function.has_high_level_call_named': 'recover|ecrecover'}, {'function.has_high_level_call_named': 'recover|ecrecover'}, {'function.has_high_level_call_named': 'recover|ecrecover'}, {'function.has_high_level_call_named': 'recover|ecrecover'}, {'function.has_high_level_call_named': 'recover|ecrecover'}, {'function.has_high_level_call_named': 'recover|ecrecover'}, {'function.body_contains_regex': 'ecrecover\\s*\\('}, {'function.body_not_contains_regex': 's\\s*<=?\\s*0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0|s\\s*<=?\\s*SECP256K1_N_DIV_2|OpenZeppelin.*ECDSA|_safeRecover|ECDSA\\.recover|ECDSA\\.tryRecover|SignatureChecker'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — ecrecover-signature-malleability: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
