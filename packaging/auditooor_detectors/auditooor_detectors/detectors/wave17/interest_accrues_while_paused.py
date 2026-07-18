"""
interest-accrues-while-paused — generated from reference/patterns.dsl/interest-accrues-while-paused.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py interest-accrues-while-paused.yaml
Source: solodit/C0373-benddao-pause
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class InterestAccruesWhilePaused(AbstractDetector):
    ARGUMENT = "interest-accrues-while-paused"
    HELP = "Borrow-interest accrual advances `borrowIndex` while the pool is paused. Because repay/liquidate are blocked by the same pause, healthy positions can become liquidatable the instant the pool unpauses — a known mass-liquidation vector (BendDAO, Code4rena M-02)."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/interest-accrues-while-paused.yaml"
    WIKI_TITLE = "Interest accrual runs while pause blocks repay/liquidate — mass-liquidation on unpause"
    WIKI_DESCRIPTION = "A lending pool pauses user-facing actions (`repay`, `liquidate`, `withdraw`) on an emergency switch, but the interest-accrual routine (`accrueInterest`, `updateIndexes`) does NOT check the pause flag. During the pause window, borrow interest continues to compound and `borrowIndex` advances, while borrowers cannot reduce their debt. When the pause is lifted, formerly-healthy positions are underwate"
    WIKI_EXPLOIT_SCENARIO = "Protocol pauses the pool at t0 due to an oracle incident. Borrower B's health factor at pause is 1.05. During the 6-hour pause, `accrueInterest` continues to run from other flows (keeper, upkeep, inherited hooks), advancing `borrowIndex` by 0.08%. On unpause at t1, B's health factor has dropped to 0.97 — liquidatable. Liquidators who were waiting for unpause race to claim the bonus. B loses collat"
    WIKI_RECOMMENDATION = "Gate `accrueInterest` and all interest-index updates behind the same `whenNotPaused` modifier used by `repay`/`liquidate`. When the pool unpauses, carry the stored `lastAccrued` timestamp from the moment of pause (not from the unpause block) to avoid re-introducing the same imbalance. Document the i"

    _PRECONDITIONS = [{'contract.source_matches_regex': '.*'}, {'contract.has_state_var_matching': 'borrowIndex|debtIndex|totalBorrows|borrowRate|_paused|paused'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': '(?i)^(accrue|accrueInterest|updateInterest|_accrueInterest|updateState|updateIndexes|calculateInterest)$'}, {'function.writes_storage_matching': 'borrowIndex|debtIndex|totalBorrows|lastAccrued|lastUpdate'}, {'function.body_not_contains_regex': '(?i)whenNotPaused|notPaused|require\\s*\\(\\s*!?\\s*paused|require\\s*\\(\\s*!?\\s*_paused|if\\s*\\(\\s*paused'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — interest-accrues-while-paused: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
