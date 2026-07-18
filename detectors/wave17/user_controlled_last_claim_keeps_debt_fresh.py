"""
user-controlled-last-claim-keeps-debt-fresh — generated from reference/patterns.dsl/user-controlled-last-claim-keeps-debt-fresh.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py user-controlled-last-claim-keeps-debt-fresh.yaml
Source: solodit/sherlock/union-H3-6387
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class UserControlledLastClaimKeepsDebtFresh(AbstractDetector):
    ARGUMENT = "user-controlled-last-claim-keeps-debt-fresh"
    HELP = "Overdue / staleness check uses `block.number - max(lastRepay, lastWithdrawRewards)`, but `lastWithdrawRewards` is rewritten whenever the user claims rewards. User loops claim-rewards every (threshold-1) blocks to keep their positions 'always fresh' and bypass the bad-debt haircut."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/user-controlled-last-claim-keeps-debt-fresh.yaml"
    WIKI_TITLE = "User-controlled 'last activity' timestamp resets overdue / staleness clock"
    WIKI_DESCRIPTION = "A staleness / overdue / bad-debt calculation uses `block.number - max(protocolCheckpoint, userCheckpoint)` as the age. The user's own actions (claim rewards, poke, refresh) set `userCheckpoint = block.number`. By calling that action periodically, the user perpetually resets the clock — the diff never exceeds the threshold, so the attached penalty / haircut / freeze never triggers. Over time the at"
    WIKI_EXPLOIT_SCENARIO = "Union staker vouches for Borrower B, who never repays. `frozenCoinAge` is only accrued when `overdueBlocks < block.number - max(B.lastRepay, staker.lastWithdrawRewards)`. Staker sets up a bot that calls `withdrawRewards()` every `overdueBlocks - 1` blocks. `lastWithdrawRewards` is rewritten each time, so the diff never exceeds `overdueBlocks`, so B is never counted as frozen. Staker's UNION emissi"
    WIKI_RECOMMENDATION = "Do not take `max(protocol, user)` for staleness math. The staleness should be measured from an immutable protocol event (last repay, last slash, last liquidation) that the user cannot influence. If a user-activity field is needed to prorate rewards, maintain it in a separate accumulator that doesn't"

    _PRECONDITIONS = [{'contract.source_matches_regex': '.*'}]
    _MATCH = [{'function.kind': 'internal_or_external'}, {'function.body_contains_regex': '_?max\\s*\\(\\s*last\\w+,\\s*\\w*lastWithdraw\\w*\\)|_?max\\s*\\(\\s*last\\w*[Rr]epay,\\s*\\w*lastWithdraw'}, {'function.body_contains_regex': 'block\\.(number|timestamp)\\s*-\\s*_?max'}, {'function.body_contains_regex': '(overdueBlocks|overdueThreshold|gracePeriod)\\s*<\\s*\\w+Diff|if\\s*\\(\\s*\\w+Diff\\s*>\\s*(overdueBlocks|grace)'}, {'contract.has_func_body_matching': '(lastWithdrawRewards|lastClaim|lastUpdate)\\s*\\[\\s*(msg\\.sender|stakerAddress)\\s*\\]\\s*=\\s*block\\.(number|timestamp)'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — user-controlled-last-claim-keeps-debt-fresh: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
