"""
rng-source-controller-no-fallback-after-max-failed-attempts — generated from reference/patterns.dsl/rng-source-controller-no-fallback-after-max-failed-attempts.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py rng-source-controller-no-fallback-after-max-failed-attempts.yaml
Source: lisa-mine-r99-case-06949-c4-wenwin-2023-03
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class RngSourceControllerNoFallbackAfterMaxFailedAttempts(AbstractDetector):
    ARGUMENT = "rng-source-controller-no-fallback-after-max-failed-attempts"
    HELP = "RNG source controller (often a Chainlink VRFv2 wrapper) tracks `failedSequentialAttempts` against a `maxFailedAttempts` cap and reverts the retry path once the cap is hit. The contract has NO `setRNSource` / `fallbackSource` / alternate-source path — once the cap is reached, the protocol is permanen"
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/rng-source-controller-no-fallback-after-max-failed-attempts.yaml"
    WIKI_TITLE = "RNG source controller has no fallback path after max failed attempts"
    WIKI_DESCRIPTION = "Pattern fires on `RNSourceController`-style contracts whose retry / request flow is gated by a `failedSequentialAttempts < maxFailedAttempts` counter. When the upstream randomness provider (Chainlink VRF) fails or DoS-griefs the request, the counter increments. Once at the cap, every retry reverts and the controller cannot accept new randomness from the original source — and there is no setter to "
    WIKI_EXPLOIT_SCENARIO = "Wenwin lottery's RNSourceController uses Chainlink VRFv2 Direct Funding. An attacker triggers repeated VRF requests during a period when the LINK funding wallet is depleted; each request fails after the VRF deadline, incrementing `failedSequentialAttempts`. On hitting `maxFailedAttempts`, the controller refuses any further retries — there is no `setRNSource()` setter to replace the broken source. "
    WIKI_RECOMMENDATION = "Expose an admin-callable `setRNSource(address newSource)` (timelocked or DAO-gated) that resets `failedSequentialAttempts` and points the controller at a backup randomness source. Equivalently, allow the controller to fall back to a pre-configured second source after `maxFailedAttempts`. Add an inte"

    _PRECONDITIONS = [{'contract.has_function_matching': 'requestRandom|fulfillRandom|onRandomReceived|retryRng'}, {'contract.source_matches_regex': 'failedSequentialAttempts|maxFailedAttempts|lastRequestFulfilled|RNSourceController|VRFv2RNSource'}, {'contract.has_no_function_body_matching': 'function\\s+(setRNSource|setRandomSource|setFallbackSource|setAlternateSource|swapRNSource|emergencySetRNSource)\\b'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': '^(retry|retryRng|requestRandom|requestNumbers|drawNumbers)$'}, {'function.body_contains_regex': 'failedSequentialAttempts\\s*[+]?=|require\\s*\\([^)]*failedSequentialAttempts'}, {'function.body_not_contains_regex': 'fallbackSource|backupRNSource|swapSource|emergencyRng|alternateSource'}, {'function.not_in_skip_list': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

    _INCLUDE_LEAF_HELPERS = True
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
                info = [f, f" — rng-source-controller-no-fallback-after-max-failed-attempts: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
