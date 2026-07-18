"""
reset-function-called-with-refund-false-from-callback — generated from reference/patterns.dsl/reset-function-called-with-refund-false-from-callback.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py reset-function-called-with-refund-false-from-callback.yaml
Source: polymarket-drafts-1-2
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class ResetFunctionCalledWithRefundFalseFromCallback(AbstractDetector):
    ARGUMENT = "reset-function-called-with-refund-false-from-callback"
    HELP = "Oracle/dispute callback calls internal _reset(..., false, ...) without setting refund=true — multi-hop liveness bug strands creator reward (Polymarket Drafts 1 + 2)."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/reset-function-called-with-refund-false-from-callback.yaml"
    WIKI_TITLE = "Oracle dispute callback calls _reset(..., false, ...) without setting refund flag — multi-hop refund desync"
    WIKI_DESCRIPTION = "An external/public oracle-callback surface (priceDisputed / onDispute / priceSettled / onCallback) invokes an internal `_reset(..., false, ...)` helper whose `resetRefund=false` branch only clears, never sets the refund flag. The callback never compensates by writing `questionData.refund = true;` itself, so the contract's downstream resolve / finalize / settle path — which gates the creator refund"
    WIKI_EXPLOIT_SCENARIO = "Polymarket UmaCtfAdapter.priceDisputed (src/v1/uma/UmaCtfAdapter.sol:163) ends in `_reset(address(this), questionID, false, questionData);`. The `_reset` body (line 390) only sets `questionData.refund = false` when `resetRefund == true`, so the false branch leaves `refund` untouched. Meanwhile the same call path immediately re-invokes `_requestPrice` which pulls the just-refunded reward back out i"
    WIKI_RECOMMENDATION = "After every `_reset(..., false, ...)` call in a permissionless callback, explicitly set `questionData.refund = true;` so the downstream resolve path knows to refund. Or, equivalently, fold the flag-set into `_reset`'s `!resetRefund` branch (`if (!resetRefund) questionData.refund = true;`). Either fi"

    _PRECONDITIONS = [{'contract.source_matches_regex': '(?i)(Adapter|Oracle|Uma|Resolve|Dispute|Request|Optimistic)'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': '^(priceDisputed|onDispute|priceSettled|onPriceSettled|onCallback|callback)$'}, {'function.body_contains_regex': '_reset\\s*\\([^;]*?,\\s*(?:false|0)\\s*[,)]'}, {'function.body_not_contains_regex': '_reset\\s*\\([^;]*?,\\s*(?:false|0)\\s*[,)][\\s\\S]*?(?:questionData\\.|q\\.)?refund\\s*=\\s*true'}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — reset-function-called-with-refund-false-from-callback: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
