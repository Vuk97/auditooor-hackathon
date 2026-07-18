"""
glider-ecrecover-no-deadline — generated from reference/patterns.dsl/glider-ecrecover-no-deadline.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py glider-ecrecover-no-deadline.yaml
Source: glider/ecrecover-no-deadline
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class GliderEcrecoverNoDeadline(AbstractDetector):
    ARGUMENT = "glider-ecrecover-no-deadline"
    HELP = "Function uses ecrecover to authenticate a signed message but does not check a deadline / expiry. Signatures are valid forever, enabling long-tail replay across redeploys / reorgs."
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.LOW
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/glider-ecrecover-no-deadline.yaml"
    WIKI_TITLE = "ecrecover-based auth missing deadline/expiration"
    WIKI_DESCRIPTION = "Signed-message auth should bind to a deadline so old signatures cannot be replayed once the intent is stale. Functions that ecrecover `(v,r,s)` over a hash with no expiry never expire the authorisation — a lost/leaked signature remains hot indefinitely."
    WIKI_EXPLOIT_SCENARIO = "User signs `withdraw(amount, nonce)` in 2024. The signature leaks from a compromised front-end cache. Two years later the attacker replays the signature; contract checks ecrecover==user and processes the withdraw — no deadline gate blocks it."
    WIKI_RECOMMENDATION = "Include `uint256 deadline` in the typed-data hash, `require(block.timestamp <= deadline, \"expired\")` before ecrecover."

    _PRECONDITIONS = [{'contract.source_matches_regex': '.*'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.body_contains_regex': 'ecrecover\\s*\\(|ECDSA\\.recover\\s*\\('}, {'function.body_not_contains_regex': 'deadline|expiry|expiresAt|block\\.timestamp\\s*<=?\\s*\\w*[Dd]eadline|require\\s*\\(\\s*block\\.timestamp\\s*<'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}]

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
                info = [f, f" — glider-ecrecover-no-deadline: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
