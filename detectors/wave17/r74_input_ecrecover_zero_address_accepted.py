"""
r74-input-ecrecover-zero-address-accepted — generated from reference/patterns.dsl/r74-input-ecrecover-zero-address-accepted.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py r74-input-ecrecover-zero-address-accepted.yaml
Source: r74b-cross-firm-cs+tob+oz
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class R74InputEcrecoverZeroAddressAccepted(AbstractDetector):
    ARGUMENT = "r74-input-ecrecover-zero-address-accepted"
    HELP = "NOT_SUBMIT_READY fixture-smoke/source-shape proof only: raw ecrecover result used as authenticated principal without asserting it is non-zero; malformed signatures silently authenticate as address(0)."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/r74-input-ecrecover-zero-address-accepted.yaml"
    WIKI_TITLE = "Recovered signer not checked against address(0)"
    WIKI_DESCRIPTION = "Fixture-smoke/source-shape proof only. NOT_SUBMIT_READY. Solidity's ecrecover precompile returns the zero address when the signature is malformed or the recovered public key is invalid. This row currently proves the owned permit-style source shape where a public entrypoint recovers `signer` with raw ecrecover, accepts `signer == owner`, and lacks a visible same-function `signer != address(0)` reje"
    WIKI_EXPLOIT_SCENARIO = "A governance wrapper exposes `allowBySig(address owner, address spender, uint amount, bytes sig)` which recovers the signer and checks `require(signer == owner)`. Attacker submits a malformed signature and `owner = address(0)`. ecrecover returns address(0). The require passes. The attacker now has approval to spend every token for which `allowance[address(0)][*]` is pre-populated (common in token "
    WIKI_RECOMMENDATION = "Immediately after raw ecrecover, `require(signer != address(0), 'bad sig');`. Prefer a vetted recover helper that reverts on malformed signatures, or use `SignatureChecker.isValidSignatureNow` for ERC-1271-aware flows. Never treat address(0) as a special authorized principal. Keep this row NOT_SUBMI"

    _PRECONDITIONS = [{'contract.source_matches_regex': '\\becrecover\\s*\\('}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.body_contains_regex': '\\baddress\\s+signer\\s*=\\s*ecrecover\\s*\\('}, {'function.body_contains_regex': '\\brequire\\s*\\(\\s*signer\\s*==\\s*owner\\b'}, {'function.body_not_contains_regex': '(require\\s*\\([^;{}]*(?:signer|recovered|from|owner)\\s*!=\\s*address\\s*\\(\\s*0\\s*\\)|if\\s*\\([^;{}]*(?:signer|recovered|from|owner)\\s*==\\s*address\\s*\\(\\s*0\\s*\\)[^;{}]*(?:revert|return)|(?:signer|recovered|from|owner)\\s*!=\\s*0x0)'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — r74-input-ecrecover-zero-address-accepted: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
