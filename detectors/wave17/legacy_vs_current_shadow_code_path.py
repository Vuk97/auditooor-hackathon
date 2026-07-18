"""
legacy-vs-current-shadow-code-path — generated from reference/patterns.dsl/legacy-vs-current-shadow-code-path.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py legacy-vs-current-shadow-code-path.yaml
Source: auditooor-PR121-A9-codex-plan-a2d11a06
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class LegacyVsCurrentShadowCodePath(AbstractDetector):
    ARGUMENT = "legacy-vs-current-shadow-code-path"
    HELP = "Advisory: a function whose name signals legacy/deprecated/v1 status writes the same protocol state (payouts, rewards, balances, epoch, status, accruedFees) as a current sibling handler in the same contract, and the body does not unconditionally revert. Likely a parallel/shadow code path with differe"
    IMPACT = DetectorClassification.LOW
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/legacy-vs-current-shadow-code-path.yaml"
    WIKI_TITLE = "Legacy vs current shadow code path (advisory)"
    WIKI_DESCRIPTION = "Contracts that ship a deprecated/legacy/v1 handler alongside the current handler frequently retain the legacy function in the live deployment for migration support. When the legacy path keeps write access to the same storage (payouts[user], rewards[user], epoch counters, status flags) but has weaker or missing epoch/role/state guards, an attacker can bypass the current path's checks by entering th"
    WIKI_EXPLOIT_SCENARIO = "Contract Settlement has settle(uint256 epoch) which require(epoch == currentEpoch) before writing payouts[user]. It also has legacySettle(uint256 epoch) retained from v1, which writes payouts[user] without the epoch check. Bob calls legacySettle(stale_epoch) to credit himself a payout against an old (and now incorrect) price, then withdraws normally. The current path's guard never executed."
    WIKI_RECOMMENDATION = "Either delete the legacy function and any external bindings, or replace its body with `revert('deprecated')`. If the function must remain callable for one-time migration, gate it by a `require(!migrationDone)` check that the migration sets to true on completion, and confirm every guard the current p"

    _PRECONDITIONS = [{'contract.has_function_matching': '^(settle|claim|payout|reward|update|finalize|process|distribute|slash|redeem|execute)[A-Za-z0-9_]*$'}, {'contract.source_matches_regex': '\\b(epoch|currentEpoch|status|payouts|rewards|balances|accruedFees|lastUpdate|version|migrationDone|deprecated)\\b'}]
    _MATCH = [{'function.kind': 'any'}, {'function.name_matches': '^(legacy|deprecated|old|preMigration|preX|oldX)[A-Z][A-Za-z0-9_]*$|^v1[A-Z][A-Za-z0-9_]*$|^legacyV[0-9]+[A-Z][A-Za-z0-9_]*$'}, {'function.body_contains_regex': '\\b(payouts|rewards|balances|epoch|status|accruedFees|lastUpdate|reserves)\\s*\\['}, {'function.body_not_contains_regex': '\\brevert\\s*\\('}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture|harness)'}]

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
                info = [f, f" — legacy-vs-current-shadow-code-path: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
