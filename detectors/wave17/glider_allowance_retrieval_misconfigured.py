"""
glider-allowance-retrieval-misconfigured — generated from reference/patterns.dsl/glider-allowance-retrieval-misconfigured.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py glider-allowance-retrieval-misconfigured.yaml
Source: glider-query-db/allowance-retrieval-misconfigured-to-return-incorr
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class GliderAllowanceRetrievalMisconfigured(AbstractDetector):
    ARGUMENT = "glider-allowance-retrieval-misconfigured"
    HELP = "`allowance(owner, spender)` returns `type(uint256).max` unconditionally. Spender can pull unlimited funds regardless of owner's intent."
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.LOW
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/glider-allowance-retrieval-misconfigured.yaml"
    WIKI_TITLE = "ERC20 allowance() returns infinite by default"
    WIKI_DESCRIPTION = "A contract that overrides `allowance` to always return `type(uint256).max` effectively grants infinite approval to every spender. Owner's `approve()` calls are silently bypassed."
    WIKI_EXPLOIT_SCENARIO = "User approves Uniswap for 100 USDC. Attacker sees `allowance(user, attacker) == MAX_UINT` and `transferFrom(user, attacker, balance)` drains the whole balance."
    WIKI_RECOMMENDATION = "`allowance` must return the stored approval amount, never a constant max."

    _PRECONDITIONS = [{'contract.source_matches_regex': 'allowance|_allowances'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': '^allowance$'}, {'function.body_contains_regex': 'return\\s+(type\\s*\\(\\s*uint256\\s*\\)\\.max|uint256\\(\\s*-1\\s*\\)|2\\*\\*256\\s*-\\s*1|115792089237316195423570985008687907853269984665640564039457584007913129639935)'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — glider-allowance-retrieval-misconfigured: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
