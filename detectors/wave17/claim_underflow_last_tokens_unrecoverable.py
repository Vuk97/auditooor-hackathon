"""
claim-underflow-last-tokens-unrecoverable — generated from reference/patterns.dsl/claim-underflow-last-tokens-unrecoverable.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py claim-underflow-last-tokens-unrecoverable.yaml
Source: solodit/C0085
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class ClaimUnderflowLastTokensUnrecoverable(AbstractDetector):
    ARGUMENT = "claim-underflow-last-tokens-unrecoverable"
    HELP = "Claim function computes `total - alreadyClaimed` without a saturating guard; rounding or double-accounting makes alreadyClaimed > total, causing permanent panic-revert and stranding the user's residual claimable tokens."
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.LOW
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/claim-underflow-last-tokens-unrecoverable.yaml"
    WIKI_TITLE = "Claim underflow strands last tokens (claimable < claimed)"
    WIKI_DESCRIPTION = "Claim entry points that compute the user's remaining balance via raw subtraction (`total - alreadyClaimed`, `vestedAmount - claimed`, `available - claimed`) will panic-revert on Solidity 0.8 whenever accumulated `alreadyClaimed` exceeds the current `total`. Common triggers: down-rounding in the total computation, double-counting in a partial claim, or admin changes to the allocation. The function "
    WIKI_EXPLOIT_SCENARIO = "User has 100 tokens allocated and has claimed 99 across several calls. A later recomputation rounds `total` down to 98 (truncation in a pro-rata calc or an admin cap reduction). The next `claim()` evaluates `98 - 99`, panics with 0x11, and reverts. Every subsequent call reverts identically. The user's final token is permanently stranded; the claim path is DOS'd for that address. Variant seen in 44"
    WIKI_RECOMMENDATION = "Replace raw subtraction with a saturating floor: `return total >= claimed ? total - claimed : 0;`, or short-circuit `if (claimed >= total) return 0;` before the subtraction. Reject allocation/admin updates that would violate the invariant `total >= claimed`."

    _PRECONDITIONS = [{'contract.source_matches_regex': '.*'}, {'contract.has_state_var_matching': '(claimed|alreadyClaimed|claimable|totalClaimed)'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': '(claim|_claim|claimTokens|claimRewards|getClaim)'}, {'function.body_contains_regex': {'regex': '(total\\w*\\s*-\\s*\\w*claimed|vested\\w*\\s*-\\s*claimed|available\\s*-\\s*\\w*claimed)'}}, {'function.body_not_contains_regex': {'regex': '(unchecked|Math\\.min|Math\\.max|if\\s*\\(.*total\\w*\\s*>=?\\s*claimed|\\?\\s*.*-.*:\\s*0)'}}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — claim-underflow-last-tokens-unrecoverable: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
