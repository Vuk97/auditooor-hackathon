"""
error-handler-cancels-without-feature-validation — generated from reference/patterns.dsl/error-handler-cancels-without-feature-validation.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py error-handler-cancels-without-feature-validation.yaml
Source: lisa-mine-r99-case-02115-sherlock-gmx-2023-02
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class ErrorHandlerCancelsWithoutFeatureValidation(AbstractDetector):
    ARGUMENT = "error-handler-cancels-without-feature-validation"
    HELP = "An internal `_handle*Error` callback (typically the catch-block of a try/catch around an execution path) calls a `cancel*` function without first re-validating the feature-disabled flag. When operators disable a feature for maintenance, queued requests still execute; on revert, the catch path cancel"
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/error-handler-cancels-without-feature-validation.yaml"
    WIKI_TITLE = "Catch-handler cancels request without re-checking feature-disabled flag"
    WIKI_DESCRIPTION = "GMX-style request-handler contracts wrap user-facing executions in `try this._executeX { } catch { _handleXError(...) }` so a single bad price or stale block doesn't brick the contract. The catch path eventually calls `XUtils.cancelX(...)` which refunds the user. The bug shape: when the protocol pauses the X feature mid-flight, the catch path STILL cancels the request — the cancel branch never re-"
    WIKI_EXPLOIT_SCENARIO = "Bob calls createDeposit and prepays 0.01 ETH execution fee. Protocol disables deposits for an upgrade. Keeper calls executeDeposit; the inner _executeDeposit reverts with FeatureDisabled. The catch-block calls _handleDepositError → DepositUtils.cancelDeposit. cancelDeposit deducts the keeper's gas as execution fee from Bob's prepay, refunds the rest, and emits Cancelled. Bob's funds were untouched"
    WIKI_RECOMMENDATION = "In `_handle*Error`, re-call `FeatureUtils.validateFeature(dataStore, Keys.cancelXFeatureDisabledKey(address(this)))` before invoking the cancel utility. If the feature is paused, surface the original revert (or a paused-feature error) instead of cancelling — keepers will retry once the feature is re"

    _PRECONDITIONS = [{'contract.source_matches_regex': '.*'}, {'contract.has_function_matching': '_handle.*Error|_handle.*Failure|_handle.*Revert'}]
    _MATCH = [{'function.kind': 'internal'}, {'function.name_matches': '_handle.*(Error|Failure|Revert)'}, {'function.body_contains_regex': '\\.cancel(Deposit|Withdrawal|Order|Position|Bid)\\s*\\('}, {'function.body_not_contains_regex': 'validateFeature\\s*\\(|FeatureUtils\\.validate|feature(Enabled|Disabled)Key|onlyFeatureEnabled'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — error-handler-cancels-without-feature-validation: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
