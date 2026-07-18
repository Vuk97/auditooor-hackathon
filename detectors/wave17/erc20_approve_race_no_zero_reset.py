"""
erc20-approve-race-no-zero-reset — generated from reference/patterns.dsl/erc20-approve-race-no-zero-reset.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py erc20-approve-race-no-zero-reset.yaml
Source: solodit/C0155
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class Erc20ApproveRaceNoZeroReset(AbstractDetector):
    ARGUMENT = "erc20-approve-race-no-zero-reset"
    HELP = "ERC20 approve(spender, amount) called without a prior approve(spender, 0) — reverts on USDT/race-protected tokens; also exposes allowance front-running."
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/erc20-approve-race-no-zero-reset.yaml"
    WIKI_TITLE = "ERC20 approve race: non-zero to non-zero allowance change without zero reset"
    WIKI_DESCRIPTION = "The contract calls token.approve(spender, amount) where spender may already hold a non-zero allowance. Tokens implementing race-protection (USDT, others) revert when transitioning non-zero to non-zero. Even on permissive tokens, a front-running spender can drain the old allowance before the new value takes effect (Approve race condition)."
    WIKI_EXPLOIT_SCENARIO = "Owner grants spender an allowance of 100 tokens. Later, owner wants to reduce it to 50 and calls approve(spender, 50). Spender front-runs by calling transferFrom for the full 100, then the approve(50) confirms and spender can pull another 50 — total 150 instead of 50."
    WIKI_RECOMMENDATION = "Use SafeERC20.forceApprove or safeIncreaseAllowance / safeDecreaseAllowance. If rolling your own, call approve(spender, 0) first, then approve(spender, newAmount)."

    _PRECONDITIONS = [{'contract.source_matches_regex': '.*'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.has_high_level_call_named': 'safeApprove'}, {'function.has_high_level_call_named': 'safeApprove'}, {'function.has_high_level_call_named': 'safeApprove'}, {'function.has_high_level_call_named': 'safeApprove'}, {'function.has_high_level_call_named': 'safeApprove'}, {'function.has_high_level_call_named': 'safeApprove'}, {'function.has_high_level_call_named': 'safeApprove'}, {'function.has_high_level_call_named': 'safeApprove'}, {'function.has_high_level_call_named': 'safeApprove'}, {'function.has_high_level_call_named': 'safeApprove'}, {'function.has_high_level_call_named': 'safeApprove'}, {'function.has_high_level_call_named': 'safeApprove'}, {'function.has_high_level_call_named': 'safeApprove'}, {'function.has_high_level_call_named': 'safeApprove'}, {'function.has_high_level_call_named': 'safeApprove'}, {'function.body_contains_regex': '(?s)^(?=(?:(?!\\.approve\\s*\\(\\s*[a-zA-Z_0-9]+\\s*,\\s*0\\s*\\))(?!forceApprove)(?!safeApprove)(?!safeIncreaseAllowance)(?!SafeERC20).)*$).*\\.approve\\s*\\('}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — erc20-approve-race-no-zero-reset: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
