"""
outer-index-used-for-inner-array-access — generated from reference/patterns.dsl/outer-index-used-for-inner-array-access.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py outer-index-used-for-inner-array-access.yaml
Source: auditooor-R75-c4-yield-2024-04-renzo-28
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class OuterIndexUsedForInnerArrayAccess(AbstractDetector):
    ARGUMENT = "outer-index-used-for-inner-array-access"
    HELP = "Inside a nested i/j loop, the inner body uses tokens[i] instead of tokens[j], sampling the outer array in the inner dimension — breaks TVL and reverts when outer.length > inner.length."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.HIGH
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/outer-index-used-for-inner-array-access.yaml"
    WIKI_TITLE = "TVL loop mixes outer and inner iterators, multi-counting one token and skipping the rest"
    WIKI_DESCRIPTION = "A classic nested-loop indexing bug: the outer loop iterates operator delegators with iterator `i`; the inner loop iterates collateral tokens with `j`; but an inner expression accidentally reads `collateralTokens[i]` instead of `collateralTokens[j]`. When outer_len ≤ inner_len the TVL silently over-counts the first outer_len tokens and ignores the rest. When outer_len > inner_len the function rever"
    WIKI_EXPLOIT_SCENARIO = "Renzo RestakeManager.calculateTVLs: 1 operator delegator, 3 collateral tokens. The inner `totalWithdrawalQueueValue += lookupTokenValue(collateralTokens[i], tokens[j].balanceOf(q))` uses `i` (always 0), so stETH is valued three times and cbETH / wbETH are ignored. TVL is wrong on every block; as soon as a second operator is registered the call reverts for tokens.length < odLength."
    WIKI_RECOMMENDATION = "Enable strict linting (SWC-128) and add unit tests that register asymmetric (O,T) pairs — tests where O>T would have caught the out-of-bounds instantly. When two indexes are in scope, prefer named iterators (`opIdx`, `tokenIdx`) over `i` / `j`."

    _PRECONDITIONS = [{'contract.source_matches_regex': '.*'}]
    _MATCH = [{'function.body_contains_regex': 'for\\s*\\(\\s*(uint\\d*\\s+)?i\\s*=[^;]*;[^}]*\\{\\s*[^}]*for\\s*\\(\\s*(uint\\d*\\s+)?j\\s*=[^;]*;[^}]*\\{'}, {'function.has_high_level_call_named': 'balanceOf'}, {'function.has_high_level_call_named': 'balanceOf'}, {'function.has_high_level_call_named': 'balanceOf'}, {'function.has_high_level_call_named': 'balanceOf'}, {'function.has_high_level_call_named': 'balanceOf'}, {'function.has_high_level_call_named': 'balanceOf'}, {'function.has_high_level_call_named': 'balanceOf'}, {'function.has_high_level_call_named': 'balanceOf'}, {'function.has_high_level_call_named': 'balanceOf'}, {'function.has_high_level_call_named': 'balanceOf'}, {'function.has_high_level_call_named': 'balanceOf'}, {'function.has_high_level_call_named': 'balanceOf'}, {'function.has_high_level_call_named': 'balanceOf'}, {'function.body_contains_regex': '\\[\\s*i\\s*\\][^;]*\\.(balanceOf|totalSupply|price|get\\w+|lookup\\w+)'}, {'function.body_contains_regex': '(?i)(collateralTokens|tokens|assets)\\[\\s*i\\s*\\]'}, {'function.name_matches': '(?i)(calculateTVL|totalAssets|sumValues|_totalValue|recomputeTVL)'}, {'function.not_in_skip_list': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — outer-index-used-for-inner-array-access: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
