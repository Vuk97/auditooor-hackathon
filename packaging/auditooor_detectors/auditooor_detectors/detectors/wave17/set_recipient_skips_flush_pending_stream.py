"""
set-recipient-skips-flush-pending-stream — generated from reference/patterns.dsl/set-recipient-skips-flush-pending-stream.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py set-recipient-skips-flush-pending-stream.yaml
Source: auditooor-R107-thegraph-Trust-IssuanceAllocator-M-2
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class SetRecipientSkipsFlushPendingStream(AbstractDetector):
    ARGUMENT = "set-recipient-skips-flush-pending-stream"
    HELP = "An admin setter (`setDefaultTarget`, `setFeeRecipient`, `setBeneficiary`, ...) overwrites a stored recipient address without first calling a flush/distribute/claim hook. Any value accrued for the OLD recipient is silently retroactively owed to the NEW recipient — old recipient loses funds they had l"
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.LOW
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/set-recipient-skips-flush-pending-stream.yaml"
    WIKI_TITLE = "Recipient setter does not flush pending stream — accrued value retroactively redirected"
    WIKI_DESCRIPTION = "Contracts that accumulate value over time toward a single recipient slot (treasury fee splits, default-allocation issuance, royalty distributors, sablier streams, charity feeds) must, before changing the recipient, settle the outstanding stream to the OLD recipient. A setter that simply overwrites the storage slot — `defaultTarget = newAddress;` — leaves the accrued-but-undistributed amount in pro"
    WIKI_EXPLOIT_SCENARIO = "An IssuanceAllocator-style contract sets aside 1M tokens of issuance over a pause window for the current default target T0. Governance, planning to switch the default to T1 *next month*, calls `setDefaultTarget(T1)` early to test off-chain pipelines. The setter does not flush the 1M pending tokens; they remain in storage attributed to the (now-unset) default. When `unpause` runs `distribute()`, th"
    WIKI_RECOMMENDATION = "Inside the setter, call the flush helper FIRST: `_distributeIssuance(); defaultTarget = newAddress;` (or `_takeRewards(oldTarget); ...`). Better: factor the recipient-swap into a public function that REQUIRES `pendingIssuance == 0`, forcing the operator to drive distribution to the old target before"

    _PRECONDITIONS = [{'contract.source_matches_regex': '.*'}, {'contract.has_state_var_matching': '(?i)(pendingIssuance|pendingReward|accrued|accumulated|streaming|outstanding|undistributed)'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.is_mutating': True}, {'function.name_matches': '(?i)^_?set(Default|Primary|Master|Recipient|Beneficiary|FeeReceiver|FeeRecipient|Treasury|RewardReceiver|RoyaltyRecipient|AllocationAddress|DefaultTarget|DefaultAllocation|FeeCollector)\\w*$'}, {'function.body_contains_regex': '\\b(?:default\\w*|recipient|beneficiary|feeReceiver|feeRecipient|treasury|target\\w*)\\s*=\\s*(?:_?\\w+|address\\([^)]+\\))\\s*;'}, {'function.body_not_contains_regex': '(?i)\\b(?:_?(?:flush|distribute|settle|claim|sweep|takeRewards|poke|harvest|crystalli[sz]e|disburse))\\w*\\s*\\('}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — set-recipient-skips-flush-pending-stream: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
