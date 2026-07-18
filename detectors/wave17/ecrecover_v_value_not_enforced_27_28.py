"""
ecrecover-v-value-not-enforced-27-28 — generated from reference/patterns.dsl/ecrecover-v-value-not-enforced-27-28.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py ecrecover-v-value-not-enforced-27-28.yaml
Source: solodit-cluster-ECR-V
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class EcrecoverVValueNotEnforced2728(AbstractDetector):
    ARGUMENT = "ecrecover-v-value-not-enforced-27-28"
    HELP = "ecrecover is called without enforcing v == 27 || v == 28. Malformed v returns address(0), which collides with default-zero owner slots and enables signature-forgery / auth-bypass."
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.LOW
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/ecrecover-v-value-not-enforced-27-28.yaml"
    WIKI_TITLE = "ecrecover v value not enforced to {27, 28}"
    WIKI_DESCRIPTION = "The EVM precompile `ecrecover(digest, v, r, s)` returns `address(0)` when the `v` parameter is outside the canonical {27, 28} pair, rather than reverting. Callers that do not enforce the v-range accept a malformed signature as a valid `address(0)` recovery. When `address(0)` is also the sentinel used to represent an empty / zero-initialized owner, approver, or governor slot, the recovered-signer c"
    WIKI_EXPLOIT_SCENARIO = "Contract maintains `mapping(uint256 => address) orderSigner` that starts unset (address(0)) for every order id. A meta-transaction entrypoint recovers the signer via `ecrecover(digest, v, r, s)` and authorizes the call if `recovered == orderSigner[id]`. An attacker submits any random (r, s) with `v = 0` (or any value outside {27, 28}); ecrecover returns address(0), which equals the unset slot, and"
    WIKI_RECOMMENDATION = "Either (a) `require(v == 27 || v == 28, \"bad v\")` before the ecrecover call, or (b) replace the raw ecrecover with OpenZeppelin's `ECDSA.recover` / `SignatureChecker`, which reject malformed `v` and low-s mallable signatures in addition to reverting on address(0). Also explicitly reject `recovered"

    _PRECONDITIONS = [{'contract.source_matches_regex': '.*'}]
    _MATCH = [{'function.kind': 'any'}, {'function.body_contains_regex': {'regex': 'ecrecover\\s*\\('}}, {'function.body_not_contains_regex': 'require\\s*\\(\\s*v\\s*==\\s*27\\s*\\|\\|\\s*v\\s*==\\s*28|require\\s*\\(\\s*v\\s*==\\s*28\\s*\\|\\|\\s*v\\s*==\\s*27|v\\s*!=\\s*27\\s*&&\\s*v\\s*!=\\s*28|ECDSA\\.recover|OpenZeppelin.*ECDSA|SignatureChecker'}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — ecrecover-v-value-not-enforced-27-28: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
