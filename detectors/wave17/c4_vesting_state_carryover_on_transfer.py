"""
c4-vesting-state-carryover-on-transfer — generated from reference/patterns.dsl/c4-vesting-state-carryover-on-transfer.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py c4-vesting-state-carryover-on-transfer.yaml
Source: code4arena/slice_ab-SecondSwap
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class C4VestingStateCarryoverOnTransfer(AbstractDetector):
    ARGUMENT = "c4-vesting-state-carryover-on-transfer"
    HELP = "Transferring a vesting schedule to another owner does NOT carry over `stepsClaimed`/`claimed` — new owner sees a fresh schedule and can re-claim the already-paid tokens."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.LOW
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/c4-vesting-state-carryover-on-transfer.yaml"
    WIKI_TITLE = "Vesting transfer leaks claimed-state, enables double-unlock"
    WIKI_DESCRIPTION = "A vesting marketplace that transfers ownership of a schedule must propagate `stepsClaimed` / `claimedAmount` to the new owner. If omitted, the new owner begins with zero claims recorded; they can unlock tokens the original owner already withdrew."
    WIKI_EXPLOIT_SCENARIO = "Alice's vesting: 1M tokens over 10 steps, 5 claimed. Alice lists vesting for sale, Bob buys. `transferVesting` resets stepsClaimed=0 for Bob. Bob claims another 5M (which overlap with Alice's 5), protocol over-pays."
    WIKI_RECOMMENDATION = "Deep-copy `stepsClaimed`, `claimedAmount`, `lastClaimTime` to the destination struct in `transferVesting`."

    _PRECONDITIONS = [{'contract.source_matches_regex': 'vesting|Vesting|stepsClaimed|releaseRate|claimed'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': '^(transferVesting|transferSchedule|splitVesting|transferListing)'}, {'function.body_contains_regex': '(stepsClaimed|claimed|claimedAmount|lastClaim|released)\\s*[^=]*='}, {'function.body_not_contains_regex': '(newVesting|dst|to|recipient)\\.\\w*(stepsClaimed|claimed|claimedAmount|released)\\s*=\\s*(\\w+\\.stepsClaimed|\\w+\\.claimed|\\w+\\.released)'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — c4-vesting-state-carryover-on-transfer: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
