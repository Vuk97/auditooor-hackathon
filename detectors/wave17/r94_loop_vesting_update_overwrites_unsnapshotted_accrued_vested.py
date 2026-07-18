"""
r94-loop-vesting-update-overwrites-unsnapshotted-accrued-vested — generated from reference/patterns.dsl/r94-loop-vesting-update-overwrites-unsnapshotted-accrued-vested.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py r94-loop-vesting-update-overwrites-unsnapshotted-accrued-vested.yaml
Source: solodit-3771-c4-vtvl
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class R94LoopVestingUpdateOverwritesUnsnapshottedAccruedVested(AbstractDetector):
    ARGUMENT = "r94-loop-vesting-update-overwrites-unsnapshotted-accrued-vested"
    HELP = "r94-loop-vesting-update-overwrites-unsnapshotted-accrued-vested"
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.LOW
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/r94-loop-vesting-update-overwrites-unsnapshotted-accrued-vested.yaml"
    WIKI_TITLE = "r94-loop-vesting-update-overwrites-unsnapshotted-accrued-vested"
    WIKI_DESCRIPTION = "r94-loop-vesting-update-overwrites-unsnapshotted-accrued-vested"
    WIKI_EXPLOIT_SCENARIO = "r94-loop-vesting-update-overwrites-unsnapshotted-accrued-vested"
    WIKI_RECOMMENDATION = "See audit report."

    _PRECONDITIONS = [{'contract.source_matches_regex': '(Vesting|Claim|Grant|VTVL|Schedule)'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': '(?i)(updateVesting|modifyVesting|changeVesting|amendGrant|rescheduleVesting)'}, {'function.source_matches_regex': '(claim\\.(amount|released|withdrawn|scheduleStart|scheduleEnd)\\s*=\\s*\\w+|grant\\.(amount|released|withdrawn|releasedAt)\\s*=\\s*\\w+|vesting\\.(amount|released|withdrawn)\\s*=)'}, {'function.not_source_matches_regex': '(snapshotVested|accruedVested\\s*\\+=|payPendingVested|syncReleasedUpToNow|checkpointAccrued)'}]

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
                info = [f, f" — r94-loop-vesting-update-overwrites-unsnapshotted-accrued-vested: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
