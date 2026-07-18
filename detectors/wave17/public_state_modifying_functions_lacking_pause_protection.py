"""
public-state-modifying-functions-lacking-pause-protection — generated from reference/patterns.dsl/public-state-modifying-functions-lacking-pause-protection.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py public-state-modifying-functions-lacking-pause-protection.yaml
Source: Hexens Glider query public-state-modifying-functions-lacking-pause-pro
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class PublicStateModifyingFunctionsLackingPauseProtection(AbstractDetector):
    ARGUMENT = "public-state-modifying-functions-lacking-pause-protection"
    HELP = "Public/external user-action function in a pausable contract writes protocol state without whenNotPaused or an equivalent pause check."
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/public-state-modifying-functions-lacking-pause-protection.yaml"
    WIKI_TITLE = "Public state-modifying functions lack pause protection"
    WIKI_DESCRIPTION = "Pausable contracts should stop externally reachable user flows that mutate protocol state during emergencies. This pattern targets user-action entrypoints such as deposit, mint, borrow, repay, swap, or claim that write state without `whenNotPaused` or an inline paused-state check."
    WIKI_EXPLOIT_SCENARIO = "A protocol pauses after detecting an incident, but `deposit(uint256)` lacks the pause guard while withdrawals are guarded. Users can continue changing balances and aggregate accounting during the emergency window, defeating the circuit breaker assumptions used by operators and integrators."
    WIKI_RECOMMENDATION = "Apply `whenNotPaused` or an equivalent pause-state check to externally reachable user-action functions that mutate protocol state. Keep deliberately live emergency functions separate and document them."

    _PRECONDITIONS = [{'contract.source_matches_regex': '(?i)(whenNotPaused|notPaused|ifNotPaused|_pause\\s*\\(|_unpause\\s*\\(|paused\\s*\\(\\s*\\)|contract\\s+\\w+\\s+is\\s+[^{};]*Pausable)'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.is_mutating': True}, {'function.name_matches': '(?i)^(deposit|withdraw|mint|burn|stake|unstake|borrow|repay|liquidate|swap|trade|buy|sell|redeem|claim|collect|enter|exit|join|leave|lock|unlock|wrap|unwrap|supply|removeLiquidity|addLiquidity|create|cancel|execute)\\w*$'}, {'function.has_modifier': {'includes': ['whenNotPaused', 'notPaused', 'ifNotPaused', 'whenUnpaused', 'notWhenPaused'], 'negate': True}}, {'function.body_not_contains_regex': '(?is)\\brequire\\s*\\([^;]*(?:!\\s*_?paused|paused\\s*\\(\\s*\\)\\s*==\\s*false|!?\\s*isPaused)[^;]*\\)|\\bif\\s*\\([^)]*(?:_?paused|paused\\s*\\(\\s*\\)|isPaused)'}, {'function.source_matches_regex': '(?i)\\b(deposit|withdraw|mint|burn|stake|unstake|borrow|repay|liquidate|swap|trade|buy|sell|redeem|claim|collect|enter|exit|join|leave|lock|unlock|wrap|unwrap|supply|removeLiquidity|addLiquidity|create|cancel|execute)\\w*\\b'}, {'function.not_source_matches_regex': '(?i)\\b(onlyOwner|onlyAdmin|onlyGovernance|onlyGovernor|onlyGuardian|onlyManager|onlyOperator|onlyRole|requiresAuth|restricted)\\b'}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)\\b'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}]

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
                info = [f, f" — public-state-modifying-functions-lacking-pause-protection: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
