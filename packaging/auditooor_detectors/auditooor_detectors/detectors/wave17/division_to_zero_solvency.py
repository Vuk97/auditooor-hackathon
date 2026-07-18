"""
division-to-zero-solvency — generated from reference/patterns.dsl/division-to-zero-solvency.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py division-to-zero-solvency.yaml
Source: kiln-v1 StakingContract
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class DivisionToZeroSolvency(AbstractDetector):
    ARGUMENT = "division-to-zero-solvency"
    HELP = "A function computes a per-user share or asset value via division using a user-controlled or manipulable denominator (totalAssets/totalSupply/totalShares) that is not guarded against zero, causing division-by-zero which reverts and locks withdrawals, or returns zero and enables insolvency via phantom"
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.HIGH
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/division-to-zero-solvency.yaml"
    WIKI_TITLE = "Division-to-zero in staking vault causes withdrawal lock or insolvency"
    WIKI_DESCRIPTION = "A staking vault or share-based contract divides by totalAssets, totalSupply, or totalShares without checking if the denominator is zero. When all assets have been withdrawn (totalAssets == 0) but shares remain (e.g., due to rounding dust or incomplete redemption), any user who tries to compute their entitlement (convertToShares or previewRedeem) will trigger a division-by-zero revert — locking all"
    WIKI_EXPLOIT_SCENARIO = "Vault has 1000 shares and 0 assets (last user withdrew everything but rounding left 1 wei of shares). Attacker calls previewRedeem(1) which does shares * totalAssets / totalSupply = 1 * 0 / 1000 = 0. Attacker receives 0 assets but their shares are not burned (if partial redemption allowed). Or the division reverts, hard-locking the remaining 1 share's worth of assets."
    WIKI_RECOMMENDATION = "Add a require statement at the start of any function that divides by totalAssets, totalSupply, or totalShares: require(denominator > 0, 'division by zero'). Alternatively use SafeMath or rely on the compiler's built-in revert-on-div-by-zero (Solidity 0.8+) but note this still locks funds rather than"

    _PRECONDITIONS = [{'contract.source_matches_regex': '(?i)(staking|vault|share|asset|token|pool|lp)'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.body_contains_regex': '/\\s*(totalAssets|totalSupply|totalShares|reserve|balance)'}, {'function.not_body_contains_regex': 'require\\s*\\(\\s*(totalAssets|totalSupply|totalShares|reserve|balance)\\s*>\\s*0'}, {'function.not_body_contains_regex': 'if\\s*\\(\\s*(totalAssets|totalSupply|totalShares|reserve|balance)\\s*==\\s*0'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — division-to-zero-solvency: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
