"""
payable-multicall-can-drain-contracts-that-utilize-msg-value — generated from reference/patterns.dsl/payable-multicall-can-drain-contracts-that-utilize-msg-value.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py payable-multicall-can-drain-contracts-that-utilize-msg-value.yaml
Source: hexens-glider/payable-multicall-msgvalue-reuse-drain-row-local-fixture
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class PayableMulticallCanDrainContractsThatUtilizeMsgValue(AbstractDetector):
    ARGUMENT = "payable-multicall-can-drain-contracts-that-utilize-msg-value"
    HELP = "Payable delegatecall multicall keeps one outer msg.value alive across many sub-calls, and a second payable state-authorizing path consumes that value without visible per-call accounting."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/payable-multicall-can-drain-contracts-that-utilize-msg-value.yaml"
    WIKI_TITLE = "Payable multicall reuses one outer msg.value across multiple delegatecalled effects"
    WIKI_DESCRIPTION = "Fixture-smoke/source-shape proof only: this row proves a payable delegatecall multicall surface plus a payable authorization path that checks msg.value against seatPrice and writes seatBooked without visible consumed-value accounting. NOT_SUBMIT_READY."
    WIKI_EXPLOIT_SCENARIO = "A payable multicall loop delegatecalls each leg against the same contract. The batched function `reserveSeat(uint256)` checks `require(msg.value >= seatPrice)` and writes `seatBooked[seatId] = true`. Because delegatecall preserves the outer msg.value, batching many `reserveSeat(...)` legs can authorize multiple seats for one payment."
    WIKI_RECOMMENDATION = "Reject payable multicall for flows that rely on msg.value, or maintain explicit consumed-value accounting across the outer transaction. Do not promote this row beyond NOT_SUBMIT_READY without real corpus-backed exploit evidence."

    _PRECONDITIONS = [{'contract.source_matches_regex': 'multicall|batch|delegatecall|msg\\.value'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.is_payable': True}, {'function.body_contains_regex': 'require\\s*\\(\\s*msg\\.value\\s*(>=|==)\\s*[A-Za-z_][A-Za-z0-9_\\.]*'}, {'function.body_contains_regex': 'seatBooked\\s*\\[[^\\]]+\\]\\s*=\\s*true|authorized\\s*\\[[^\\]]+\\]\\s*=\\s*true|mint\\s*\\('}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — payable-multicall-can-drain-contracts-that-utilize-msg-value: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
