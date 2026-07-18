"""
request-confirmation-is-too-low-in-chainlink-vrf-in-polygon

Compatibility detector for the old wave13 queue row. The semantics intentionally
mirror the already-promoted Glider detector
`glider-chainlink-vrf-request-confirmations-too-low`, but keep this scanner id
fixture-backed so scanner burndown does not route through the generated
wave13_broken skeleton.
"""

import sys
from pathlib import Path as _Path

sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _predicate_engine import eval_function_match, eval_preconditions
from _template_utils import is_leaf_helper, is_vendored_or_test_contract

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class RequestConfirmationIsTooLowInChainlinkVrfInPolygon(AbstractDetector):
    ARGUMENT = "request-confirmation-is-too-low-in-chainlink-vrf-in-polygon"
    HELP = "Chainlink VRF requestConfirmations set below 3 on Polygon-style deployments."
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.LOW
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/request-confirmation-is-too-low-in-chainlink-vrf-in-polygon.yaml"
    WIKI_TITLE = "Chainlink VRF requestConfirmations below Polygon-safe threshold"
    WIKI_DESCRIPTION = (
        "Fixture-smoke/source-shape alias for the promoted Glider VRF detector. "
        "It flags requestRandomWords calls that pass 1 or 2 confirmations, which "
        "can make high-value randomness sensitive to short reorgs."
    )
    WIKI_EXPLOIT_SCENARIO = (
        "A randomness consumer requests VRF with requestConfirmations=1 or 2. "
        "If the outcome is valuable enough for a block producer or sequencer-adjacent "
        "actor to bias via a short reorg, the request can be retried on another branch."
    )
    WIKI_RECOMMENDATION = (
        "Use at least the Chainlink-recommended confirmation count for the target "
        "chain and raise it for high-value outcomes; do not hardcode 1 or 2."
    )

    _PRECONDITIONS = [
        {
            "contract.source_matches_regex": (
                r"VRFCoordinator|requestRandomWords|IVRFV2|VRFConsumerBase"
            )
        }
    ]
    _MATCH = [
        {"function.kind": "any"},
        {"function.body_contains_regex": r"requestRandomWords\s*\("},
        {
            "function.body_contains_regex": (
                r"requestConfirmations\s*[=:]\s*(1|2)\b|"
                r"uint16\s*\(\s*(1|2)\s*\)|"
                r",\s*(1|2)\s*,\s*\d+\s*,"
            )
        },
        {"function.not_in_skip_list": True},
        {"function.not_source_matches_regex": r"(?i)\b(mock|test|fixture)"},
    ]

    def _detect(self):
        results = []
        for contract in self.contracts:
            if is_vendored_or_test_contract(contract):
                continue
            if not eval_preconditions(contract, self._PRECONDITIONS):
                continue
            for function in contract.functions_and_modifiers_declared:
                if is_leaf_helper(function):
                    continue
                if not eval_function_match(function, self._MATCH):
                    continue
                info = [
                    function,
                    (
                        " - request-confirmation-is-too-low-in-chainlink-vrf-in-polygon: "
                        "requestRandomWords uses requestConfirmations below 3. "
                        "Alias of glider-chainlink-vrf-request-confirmations-too-low; "
                        "fixture-smoke only, not submit-ready evidence."
                    ),
                ]
                results.append(self.generate_result(info))
        return results
