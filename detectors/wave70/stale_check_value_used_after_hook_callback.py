"""
stale-check-value-used-after-hook-callback - narrow Solidity detector
Source anchor: Task B35 state-change-between-check-and-use lift
"""

import sys
from pathlib import Path as _Path

sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))

from _predicate_engine import eval_function_match, eval_preconditions
from _template_utils import is_leaf_helper, is_vendored_or_test_contract
from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class StaleCheckValueUsedAfterHookCallback(AbstractDetector):
    ARGUMENT = "stale-check-value-used-after-hook-callback"
    HELP = (
        "Function caches a checked balance, credit, or authorization value, "
        "calls an external hook or callback, then commits state or transfers "
        "using the stale cached value without refreshing it."
    )
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/stale-check-value-used-after-hook-callback.yaml"
    WIKI_TITLE = "Stale checked value reused after hook callback"
    WIKI_DESCRIPTION = (
        "A function caches a state-derived balance, claimable amount, credit, "
        "or authorization flag in a local variable, validates that cached "
        "value, then invokes an external hook or callback. Because the hook "
        "can change the underlying state, reusing the cached value after the "
        "callback creates a state-change-between-check-and-use bug."
    )
    WIKI_EXPLOIT_SCENARIO = (
        "A vault reads `cachedBalance = balances[msg.sender]` and requires "
        "`cachedBalance >= amount`, then calls `hook.beforeWithdraw(...)`. "
        "The hook reduces the caller's balance or revokes authorization. The "
        "vault still decrements from `cachedBalance` and transfers funds "
        "without re-reading the live balance."
    )
    WIKI_RECOMMENDATION = (
        "Do not reuse cached checked values across an external callback. "
        "Re-read and re-validate the live state after the hook, or move the "
        "state commit before the callback if the protocol design permits it."
    )

    _PRECONDITIONS = [
        {
            "contract.has_state_var_matching": (
                "(?i)(balance|share|credit|claimable|accrued|allowance|approved|"
                "authorized|whitelist|permission)"
            )
        },
        {"contract.source_matches_regex": "(?i)(hook|callback|before[A-Z]|after[A-Z]|on[A-Z])"},
    ]

    _MATCH = [
        {"function.kind": "external_or_public"},
        {"function.not_in_skip_list": True},
        {
            "function.body_contains_regex": (
                r"(?is)"
                r"(?:uint(?:8|16|32|64|96|128|160|192|224|256)?|"
                r"int(?:8|16|32|64|96|128|160|192|224|256)?|bool)\s+"
                r"([A-Za-z_]\w*)\s*=\s*"
                r"(?:balances?|shares?|credits?|claimable|accrued|allowances?|"
                r"approved|authorized|isAuthorized|whitelist|permissions?)"
                r"\s*(?:\[[^\]]+\])+"
                r"\s*;"
                r"[\s\S]*?"
                r"require\s*\([^;{}]*\1[^;{}]*\)"
                r"[\s\S]*?"
                r"(?:hook|callback|before[A-Z]\w*|after[A-Z]\w*|on[A-Z]\w*)"
                r"\s*\([^;{}]*\)\s*;"
                r"[\s\S]*?"
                r"(?:"
                r"[A-Za-z_]\w*\s*(?:\[[^\]]+\])+\s*=\s*\1\s*[-+]"
                r"|"
                r"(?:payable\s*\([^)]*\)\s*\.\s*transfer"
                r"|[A-Za-z_]\w*\s*\.\s*safeTransfer"
                r"|[A-Za-z_]\w*\s*\.\s*transfer"
                r"|[A-Za-z_]\w*\s*\.\s*safeTransferFrom"
                r"|[A-Za-z_]\w*\s*\.\s*call\s*\{\s*value\s*:)"
                r"[^;{}]*\1"
                r")"
            )
        },
        {
            "function.body_not_contains_regex": (
                r"(?is)"
                r"(?:hook|callback|before[A-Z]\w*|after[A-Z]\w*|on[A-Z]\w*)"
                r"\s*\([^;{}]*\)\s*;"
                r"[\s\S]*?"
                r"(?:uint(?:8|16|32|64|96|128|160|192|224|256)?|"
                r"int(?:8|16|32|64|96|128|160|192|224|256)?|bool)\s+"
                r"[A-Za-z_]\w*\s*=\s*"
                r"(?:balances?|shares?|credits?|claimable|accrued|allowances?|"
                r"approved|authorized|isAuthorized|whitelist|permissions?)"
                r"\s*(?:\[[^\]]+\])+"
                r"\s*;"
                r"[\s\S]*?"
                r"require\s*\([^;{}]*[A-Za-z_]\w*[^;{}]*\)"
            )
        },
    ]

    _INCLUDE_LEAF_HELPERS = False

    def _detect(self):
        results = []
        for contract in self.contracts:
            if is_vendored_or_test_contract(contract):
                continue
            if not eval_preconditions(contract, self._PRECONDITIONS):
                continue
            for function in contract.functions_and_modifiers_declared:
                if not self._INCLUDE_LEAF_HELPERS and is_leaf_helper(function):
                    continue
                if not eval_function_match(function, self._MATCH):
                    continue
                info = [
                    function,
                    " - stale-check-value-used-after-hook-callback: pattern matched. See WIKI for details.",
                ]
                results.append(self.generate_result(info))
        return results
