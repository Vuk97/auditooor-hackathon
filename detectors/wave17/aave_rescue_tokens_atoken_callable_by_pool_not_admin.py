"""
aave-rescue-tokens-atoken-callable-by-pool-not-admin — generated from reference/patterns.dsl/aave-rescue-tokens-atoken-callable-by-pool-not-admin.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py aave-rescue-tokens-atoken-callable-by-pool-not-admin.yaml
Source: auditooor-R71-fixdiff-mined-aave-v3-core-1a32301881
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class AaveRescueTokensAtokenCallableByPoolNotAdmin(AbstractDetector):
    ARGUMENT = "aave-rescue-tokens-atoken-callable-by-pool-not-admin"
    HELP = "AToken.rescueTokens is guarded only by onlyPool — combined with a Pool.rescueTokensFromAToken wrapper that was also weakly gated, any tx routed through the pool could drain mistakenly-sent tokens from an AToken without pool-admin signoff."
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/aave-rescue-tokens-atoken-callable-by-pool-not-admin.yaml"
    WIKI_TITLE = "AToken rescueTokens gated by onlyPool instead of onlyPoolAdmin opens indirect escalation"
    WIKI_DESCRIPTION = "Aave v3 AToken contract exposes `rescueTokens(token, to, amount)` to recover ERC20s accidentally sent to the aToken address. Pre-fix this was guarded by `onlyPool`, and the Pool contract had a sibling `rescueTokensFromAToken(asset, token, to, amount)` that forwarded the call. The intent was that only the pool admin could reach it, but the Pool-side function's gating was easy to forget/break during"
    WIKI_EXPLOIT_SCENARIO = "A future Pool upgrade adds a helper that forwards arbitrary aToken calls to allow some automation workflow, forgetting to add `_onlyPoolAdmin`. Any user calls this helper with `rescueTokens` calldata; the helper forwards to the aToken which checks `msg.sender == address(POOL)` and allows the drain. Alternatively, a governance mistake listing a malicious Pool implementation in addressesProvider bec"
    WIKI_RECOMMENDATION = "Guard `AToken.rescueTokens` with `onlyPoolAdmin` — resolve the admin via the ACL manager at call time, not by trusting the Pool contract. Remove any Pool-side rescueTokensFromAToken wrapper. Apply the same principle to `stableDebtToken.rescueTokens`, `variableDebtToken.rescueTokens`, and any other t"

    _PRECONDITIONS = [{'contract.has_function_matching': '^(rescueTokens|rescue)$'}, {'contract.source_matches_regex': '(?i)\\b(aToken|POOL|onlyPool|rescueTokensFromAToken)\\b'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': '^(rescueTokens|rescue)$'}, {'function.has_high_level_call_named': 'safeTransfer|transfer'}, {'function.body_contains_regex': '(?i)(IERC20\\s*\\(\\s*token\\s*\\)|IERC20\\s*\\(\\s*asset\\s*\\)|safeTransfer\\s*\\(|transfer\\s*\\()'}, {'function.has_modifier': {'includes': ['onlyPool', 'onlyLendingPool'], 'negate': False}}, {'function.body_not_contains_regex': 'onlyPoolAdmin|POOL_ADMIN|aclManager\\.isPoolAdmin|_onlyPoolAdmin'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — aave-rescue-tokens-atoken-callable-by-pool-not-admin: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
