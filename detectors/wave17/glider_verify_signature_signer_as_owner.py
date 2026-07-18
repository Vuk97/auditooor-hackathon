"""
glider-verify-signature-signer-as-owner — generated from reference/patterns.dsl/glider-verify-signature-signer-as-owner.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py glider-verify-signature-signer-as-owner.yaml
Source: hexens-glider/verify-signature-sets-signer-as-owner-which-alows
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class GliderVerifySignatureSignerAsOwner(AbstractDetector):
    ARGUMENT = "glider-verify-signature-signer-as-owner"
    HELP = "`verifySignature` compares `ecrecover(...)` directly against `owner()` / `_owner`. When ownership is renounced, `owner() == address(0)` and malformed signatures cause `ecrecover` to return `address(0)` — signature verification trivially passes."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/glider-verify-signature-signer-as-owner.yaml"
    WIKI_TITLE = "verifySignature admits anyone after ownership renouncement (Port3-style)"
    WIKI_DESCRIPTION = "Direct equality between `ecrecover()` output and `owner()` is a dual vulnerability when the owner slot can become `address(0)`. Either because ownership was intentionally renounced or because the storage was never initialised on a fresh proxy. `ecrecover` returns `address(0)` for any invalid signature — so `address(0) == address(0)` is trivially true. Post-Port3 hack this pattern is well-known."
    WIKI_EXPLOIT_SCENARIO = "Admin-only action is gated by `verifySignature` which compares to `owner()`. Governance renounces ownership. Attacker sends an invalid signature (e.g. v=0) — ecrecover returns 0, owner is 0, check passes, attacker invokes admin action."
    WIKI_RECOMMENDATION = "Require `ecrecover != address(0)` before the owner comparison AND require `owner() != address(0)` separately. Better: use OpenZeppelin's `SignatureChecker.isValidSignatureNow` which handles this class of bugs correctly."

    _PRECONDITIONS = [{'contract.source_matches_regex': 'ecrecover|owner\\s*\\(\\)|_owner'}]
    _MATCH = [{'function.name_matches': '^(verifySignature|_verifySignature|checkSig|validateSignature)$'}, {'function.kind': 'any'}, {'function.has_high_level_call_named': 'recover|ecrecover'}, {'function.has_high_level_call_named': 'recover|ecrecover'}, {'function.has_high_level_call_named': 'recover|ecrecover'}, {'function.has_high_level_call_named': 'recover|ecrecover'}, {'function.has_high_level_call_named': 'recover|ecrecover'}, {'function.has_high_level_call_named': 'recover|ecrecover'}, {'function.has_high_level_call_named': 'recover|ecrecover'}, {'function.has_high_level_call_named': 'recover|ecrecover'}, {'function.has_high_level_call_named': 'recover|ecrecover'}, {'function.has_high_level_call_named': 'recover|ecrecover'}, {'function.has_high_level_call_named': 'recover|ecrecover'}, {'function.has_high_level_call_named': 'recover|ecrecover'}, {'function.has_high_level_call_named': 'recover|ecrecover'}, {'function.has_high_level_call_named': 'recover|ecrecover'}, {'function.has_high_level_call_named': 'recover|ecrecover'}, {'function.body_contains_regex': 'ecrecover\\s*\\(.+\\)\\s*==\\s*owner\\s*\\(\\)|ecrecover\\s*\\(.+\\)\\s*==\\s*_owner|owner\\s*\\(\\)\\s*==\\s*ecrecover|_owner\\s*==\\s*ecrecover|signer\\s*=\\s*ecrecover.+;\\s*require\\s*\\(\\s*signer\\s*==\\s*owner'}, {'function.body_not_contains_regex': 'require\\s*\\(\\s*owner\\s*\\(\\s*\\)\\s*!=\\s*address\\s*\\(\\s*0\\s*\\)|require\\s*\\(\\s*_owner\\s*!=\\s*address\\s*\\(\\s*0\\s*\\)|ecrecover.+!=\\s*address\\s*\\(\\s*0'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — glider-verify-signature-signer-as-owner: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
