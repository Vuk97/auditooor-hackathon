"""
ecdsa-low-s-missing — generated from reference/patterns.dsl/ecdsa-low-s-missing.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py ecdsa-low-s-missing.yaml
Source: wave4/ecdsa_low_s_check_missing
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class EcdsaLowSMissing(AbstractDetector):
    ARGUMENT = "ecdsa-low-s-missing"
    HELP = "ecrecover used without low-s check — ECDSA signature malleability (SWC-117)"
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.LOW
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/ecdsa-low-s-missing.yaml"
    WIKI_TITLE = "ECDSA Signature Malleability — Missing Low-S Check"
    WIKI_DESCRIPTION = "A contract calls ecrecover(hash, v, r, s) without verifying that s <= secp256k1n / 2. For any valid ECDSA signature (r, s, v), a second valid signature (r, n-s, v^1) exists that recovers the same address. This is exploitable when the signature is used as a unique identifier (nonce), in relayer deduplication, or commit-reveal schemes. OpenZeppelin ECDSA.recover() properly enforces low-s internally "
    WIKI_EXPLOIT_SCENARIO = "ecrecover used without low-s check — ECDSA signature malleability (SWC-117)"
    WIKI_RECOMMENDATION = "Use OpenZeppelin's ECDSA library (ECDSA.recover()) which enforces the low-s check internally, or add an explicit require(s <= 0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0) before using the recovered address."

    _PRECONDITIONS = [{'contract.source_matches_regex': 'ecrecover'}]
    _MATCH = [{'function.body_contains_regex': 'ecrecover\\s*\\('}, {'function.body_not_contains_regex': '0x7[Ff]{3}[0-9a-fA-F]{61}|HALF.?N|MAX.?S|secp256k1n'}, {'function.not_in_skip_list': True}]

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
                info = [f, f" — ecdsa-low-s-missing: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
