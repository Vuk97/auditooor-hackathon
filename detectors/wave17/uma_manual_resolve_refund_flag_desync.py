"""
uma-manual-resolve-refund-flag-desync — generated from reference/patterns.dsl/uma-manual-resolve-refund-flag-desync.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py uma-manual-resolve-refund-flag-desync.yaml
Source: auditooor-R77-polymarket-UmaCtfAdapter-resolveManually
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class UmaManualResolveRefundFlagDesync(AbstractDetector):
    ARGUMENT = "uma-manual-resolve-refund-flag-desync"
    HELP = "A manual-resolution path checks a `refund` flag before returning the creator's reward, but the flag isn't set when a prior dispute-reset consumed the reward. Creator loses funds under the 'safety' pathway."
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.HIGH
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/uma-manual-resolve-refund-flag-desync.yaml"
    WIKI_TITLE = "Admin manual-resolve gates refund on flag that's never set after dispute-reset"
    WIKI_DESCRIPTION = "When an admin manually resolves a question after flagging, the path checks `if (questionData.refund) _refund(creator)`. The `refund` flag is set only in specific callback paths — typically the SECOND dispute's callback. But the FIRST dispute's callback commonly opens a new OO request (`_reset`) that consumes the refunded reward, without setting refund=true. If the admin flag-and-resolveManually se"
    WIKI_EXPLOIT_SCENARIO = "(1) Creator initializes with reward R. (2) Admin flag-queues manual resolution. (3) Attacker (or benign UMA dispute) fires priceDisputed, triggering `_reset(…, resetRefund=false)`. OO refund of R → adapter → consumed by new request. refund flag stays false. (4) Admin calls resolveManually after safety period. questionData.refund==false → refund skipped. Creator's R stranded at OO's request-2, poss"
    WIKI_RECOMMENDATION = "Always set refund=true in the first-reset branch so that downstream resolveManually refunds the creator. Alternatively, have resolveManually always attempt the refund (guarded by reward>0) regardless of the refund flag."

    _PRECONDITIONS = [{'contract.source_matches_regex': '(?i)resolveManually|manualResolution|safetyPeriod'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': '(?i)resolveManually|manualResolve'}, {'function.has_modifier': 'onlyAdmin|onlyOwner'}, {'function.body_contains_regex': '(?i)if\\s*\\(\\s*\\w*[Rr]efund\\s*\\)\\s*_?[Rr]efund'}, {'function.body_not_contains_regex': '(?i)\\w*[Rr]eset\\s*&&\\s*!?\\w*[Rr]efund|always.*refund|_refund\\s*\\(\\s*questionData'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — uma-manual-resolve-refund-flag-desync: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
