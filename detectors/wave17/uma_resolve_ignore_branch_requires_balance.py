"""
uma-resolve-ignore-branch-requires-balance — generated from reference/patterns.dsl/uma-resolve-ignore-branch-requires-balance.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py uma-resolve-ignore-branch-requires-balance.yaml
Source: auditooor-R77-polymarket-UmaCtfAdapter-_resolve
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class UmaResolveIgnoreBranchRequiresBalance(AbstractDetector):
    ARGUMENT = "uma-resolve-ignore-branch-requires-balance"
    HELP = "UMA ignore-price branch opens a new OO request funded from the adapter's balance without checking that the adapter actually holds enough. A prior dispute-reset that consumed the refunded reward leaves adapter empty; ignore-path revert bricks resolve()."
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.HIGH
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/uma-resolve-ignore-branch-requires-balance.yaml"
    WIKI_TITLE = "UMA resolve ignore-price branch reverts when adapter balance is zero, bricking resolution"
    WIKI_DESCRIPTION = "OptimisticOracle returns `int256.min` as an ignore-price sentinel for questions it cannot resolve. Adapter code typically handles this by calling `_reset(address(this), …)` which opens a new OO request funded from the adapter's balance. If a prior dispute-reset already consumed the refunded reward, the adapter holds 0, the new request's internal `transferFrom(currency, adapter, oo, reward)` revert"
    WIKI_EXPLOIT_SCENARIO = "Attacker propose-disputes request-1 triggering first reset. Adapter balance 0. UMA DVM returns ignore for request-2. Any third-party (or the attacker) calls resolve() → ignore-branch → _reset(this) → reverts on empty balance. Question stuck at resolved=false forever; admin must manually recover, paying cost."
    WIKI_RECOMMENDATION = "Guard the ignore branch on adapter balance, OR fall through to a documented 'requires manual resolution' state rather than reverting:\n\n```\nif (price == _ignorePrice()) {\n    if (IERC20(token).balanceOf(address(this)) >= reward) {\n        return _reset(address(this), qID, true, qd);\n    }\n    "

    _PRECONDITIONS = [{'contract.source_matches_regex': '(?i)settleAndGetPrice|ignorePrice|UMA|OptimisticOracle'}]
    _MATCH = [{'function.kind': 'internal_or_external'}, {'function.name_matches': '(?i)_?resolve|_?handleIgnorePrice'}, {'function.body_contains_regex': '(?i)(price\\s*==\\s*_?ignorePrice|price\\s*==\\s*type\\s*\\(\\s*int256\\s*\\)\\s*\\.min)'}, {'function.body_contains_regex': '(?i)_reset\\s*\\(\\s*address\\s*\\(\\s*this\\s*\\)|_requestPrice\\s*\\(\\s*address\\s*\\(\\s*this\\s*\\)'}, {'function.body_not_contains_regex': '(?i)balanceOf\\s*\\(\\s*address\\s*\\(\\s*this\\s*\\)\\s*\\)\\s*>=\\s*\\w*[Rr]eward|balanceOf\\s*\\(\\s*this\\s*\\)\\s*>=\\s*\\w*reward'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — uma-resolve-ignore-branch-requires-balance: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
