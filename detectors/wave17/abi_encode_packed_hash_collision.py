"""
abi-encode-packed-hash-collision — generated from reference/patterns.dsl/abi-encode-packed-hash-collision.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py abi-encode-packed-hash-collision.yaml
Source: solodit-cluster-C0197
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class AbiEncodePackedHashCollision(AbstractDetector):
    ARGUMENT = "abi-encode-packed-hash-collision"
    HELP = "keccak256(abi.encodePacked(...)) used to form a hash — encodePacked does not length-prefix dynamic (string/bytes/array) arguments, so two distinct input tuples can collide (SWC-133)."
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.LOW
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/abi-encode-packed-hash-collision.yaml"
    WIKI_TITLE = "Hash collision via abi.encodePacked with dynamic arguments"
    WIKI_DESCRIPTION = "abi.encodePacked concatenates its arguments without length prefixes for dynamic types. When two or more of its arguments are dynamic (string, bytes, T[]) the boundary between them is ambiguous, and two different input tuples can produce the same packed bytes and therefore the same keccak256 digest. When that digest is used as an order id, a signed message, or a permit hash, the collision enables a"
    WIKI_EXPLOIT_SCENARIO = "Protocol builds an order hash as `keccak256(abi.encodePacked(user, description, tokens))` where `description` and `tokens` are dynamic. Attacker crafts a second (description', tokens') tuple whose concatenation matches the first. The signature the user produced for the intended order is now also valid for the attacker-crafted order, permitting unintended asset movement or privilege grant."
    WIKI_RECOMMENDATION = "Use abi.encode (not abi.encodePacked) whenever hashing two or more dynamic arguments. Alternatively, include explicit length prefixes or follow the EIP-712 TypedData hashing scheme which already length-prefixes via struct hashing."

    _PRECONDITIONS = [{'contract.source_matches_regex': '(keccak256|abi\\.encodePacked|EIP712|domainSeparator|typeHash|hashStruct|ecrecover|SignatureChecker|isValidSignature|permit|Order|order)'}]
    _MATCH = [{'function.kind': 'any'}, {'function.body_contains_regex': {'regex': 'keccak256\\s*\\(\\s*abi\\.encodePacked\\s*\\('}}, {'function.body_contains_regex': {'regex': 'ecrecover|SignatureChecker|isValidSignature|signatures?\\s*\\[|digest|orderHash|_hashTypedData|toEthSignedMessageHash'}}, {'function.not_source_matches_regex': '(abi\\.encode\\s*\\(\\s*(?!Packed)|_hashTypedDataV4|TYPE_HASH\\s*,\\s*keccak256|hashStruct\\s*\\(|bytes32\\s+constant\\s+\\w+_TYPEHASH)'}]

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
                info = [f, f" — abi-encode-packed-hash-collision: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
