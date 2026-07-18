"""
a-malicious-fee-receiver-can-cause-a-denial-of-service — local precision fix
for the wave15 skeleton variant.

The original skeleton overfit to `addReceiver`-style helper functions and
false-fired on the clean extraction fixture. Keep this detector aligned with
the wave17 DSL-backed matcher so the runner behaves consistently regardless of
which wave file is loaded.
"""

import sys
from pathlib import Path as _Path

sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_leaf_helper, is_vendored_or_test_contract
from _predicate_engine import eval_function_match, eval_preconditions

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class AMaliciousFeeReceiverCanCauseADenialOfService(AbstractDetector):
    ARGUMENT = "a-malicious-fee-receiver-can-cause-a-denial-of-service"
    HELP = "A malicious fee receiver can cause a denial of service"
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/a-malicious-fee-receiver-can-cause-a-denial-of-service.yaml"
    WIKI_TITLE = "A malicious fee receiver can cause a denial of service"
    WIKI_DESCRIPTION = "## Difficulty: Low\n\n## Type: Access Controls\n\n## Description\nWhenever a user executes a minting, redeeming, or swapping operation on a vault, a fee is charged to the user and is sent to the `NFXTSimpleFeeDistributor` contract for distribution. The distribution function loops through all fee receiver"
    WIKI_EXPLOIT_SCENARIO = "Per Solodit #18163: ## Difficulty: Low\n\n## Type: Access Controls\n\n## Description\nWhenever a user executes a minting, redeeming, or swapping operation on a vault, a fee is charged to the user and is sent to the `NFXTSimpl"
    WIKI_RECOMMENDATION = "See source audit report for recommended fix."

    _PRECONDITIONS = [{"contract.source_matches_regex": ".*"}]
    _MATCH = [
        {"function.name_matches_regex": r"(?i).*distribute.*"},
        {"function.not_leaf_helper": True},
        {"function.not_in_skip_list": True},
        {"function.is_mutating": True},
        {"function.reads_state_var_matching_regex": r"(?i).*(feeReceivers|feeReceiver|receivers).*"},
        {"function.has_external_call": True},
        {"function.body_contains_regex": r"(?s)for\s*\([^)]*<\s*(feeReceivers|receivers)\.length[^)]*\)"},
        {"function.body_contains_regex": r"(?i)(receiveFee|onFeeReceived|notifyFee|distributeShare)\s*\("},
        {"function.body_not_contains_regex": r"(?i)\btry\b|catch\s*\{|continueOnFailure|ignoreFailure|bestEffort"},
    ]

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
                info = [
                    f,
                    " — a-malicious-fee-receiver-can-cause-a-denial-of-service: loops over fee receivers and makes an unisolated external distribution call.",
                ]
                results.append(self.generate_result(info))
        return results
