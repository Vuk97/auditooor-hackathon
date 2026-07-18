"""
edit-config-check-only-time-not-settlement — generated from reference/patterns.dsl/edit-config-check-only-time-not-settlement.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py edit-config-check-only-time-not-settlement.yaml
Source: auditooor-R75-code4rena-2024-10-coded-estate-4
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class EditConfigCheckOnlyTimeNotSettlement(AbstractDetector):
    ARGUMENT = "edit-config-check-only-time-not-settlement"
    HELP = "edit-guard only checks that the last period ended in the past — not whether funds for that period have been settled. Owner can swap payment denom/price between period-end and finalize."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/edit-config-check-only-time-not-settlement.yaml"
    WIKI_TITLE = "Edit-guard checks only time, not settlement — owner swaps denom post-expiry to drain contract"
    WIKI_DESCRIPTION = "`check_can_edit_short` returns OK if `last_check_out_time < current_time`. It doesn't check whether each rental's payment has been finalized. A malicious landlord configures a listing with low-value `denom = TokenX`, rents to themselves, waits for check-out, then calls `setListForShortTermRental` with `denom = USDC` and `finalizeShortTermRental` — they receive USDC even though the tenant (themselv"
    WIKI_EXPLOIT_SCENARIO = "Landlord sets denom = low-value MEME (1000 MEME ≈ $1). Renter (landlord alt-account) rents for 1000 MEME. Check-out time elapses. Landlord calls setListForShortTermRental changing denom = USDC. Landlord calls finalizeShortTermRental — contract sends 1000 USDC from the pooled-deposits account. Contract is drained of $1000 from other renters' deposits."
    WIKI_RECOMMENDATION = "In `check_can_edit_X`, also iterate rentals and require `item.finalized == true || item.cancelled == true` for every entry. Equivalently, store denom per-rental (not per-listing) at rental creation time, and ignore the listing's current denom at finalize."

    _PRECONDITIONS = [{'contract.source_matches_regex': '.*'}]
    _MATCH = [{'function.kind': 'internal_or_public'}, {'function.name_matches': '(?i)check_can_edit|canEdit|canModify|checkEditable'}, {'function.body_contains_regex': '(?i)renting_period\\s*\\[\\s*1\\s*\\]|last.*period\\[1\\]|endTime|checkOutTime|expiry'}, {'function.reads_block_timestamp': True}, {'function.reads_block_timestamp': True}, {'function.reads_block_timestamp': True}, {'function.reads_block_timestamp': True}, {'function.reads_block_timestamp': True}, {'function.reads_block_timestamp': True}, {'function.reads_block_timestamp': True}, {'function.reads_block_timestamp': True}, {'function.reads_block_timestamp': True}, {'function.reads_block_timestamp': True}, {'function.reads_block_timestamp': True}, {'function.reads_block_timestamp': True}, {'function.reads_block_timestamp': True}, {'function.body_contains_regex': '(?i)<\\s*current_time|<\\s*block\\.timestamp|<\\s*env\\.block\\.time'}, {'function.body_not_contains_regex': '(?i)cancelled|finalized|settled|unpaid|pendingPayment|unpaidRentals|isClosed'}, {'function.not_in_skip_list': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — edit-config-check-only-time-not-settlement: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
