"""
remove-redundant-code-in-cashin-proof-of-concept-take-a-look-at.

Fixture-smoke detector for a generated audit-text pattern: flag cashIn-like
functions that write balance/amount-style state without a local require/assert
over the same accounting family. This remains detector-fixture coverage only,
not proof of exploitability or severity.
"""

import re
import sys
from pathlib import Path as _Path

sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract

from slither.core.cfg.node import NodeType
from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class RemoveRedundantCodeInCashinProofOfConceptTakeALookAt(AbstractDetector):
    ARGUMENT = "remove-redundant-code-in-cashin-proof-of-concept-take-a-look-at"
    HELP = "cashIn-style function writes accounting state without a local require/assert guard over the accounting variable family"
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/remove-redundant-code-in-cashin-proof-of-concept-take-a-look-at.yaml"
    WIKI_TITLE = "cashIn-like accounting write lacks local guard"
    WIKI_DESCRIPTION = (
        "Generated audit-text pattern for cashIn-style functions that write balance, amount, total, "
        "supply, or reserve state without an adjacent require/assert over the same accounting family."
    )
    WIKI_EXPLOIT_SCENARIO = (
        "A cashIn-like entrypoint updates accounting state directly. This detector only proves the "
        "source-shape and fixture-smoke predicate; a real finding still needs source-specific impact proof."
    )
    WIKI_RECOMMENDATION = "Add an explicit local guard for the amount/accounting invariant before writing state."

    _FN_NAME_REGEX = re.compile(r".*(cashIn|onlyWhiteListed|underlyingToken).*", re.IGNORECASE)
    _WRITE_VAR_REGEX = re.compile(r".*(balance|amount|total|supply|reserve).*", re.IGNORECASE)
    _GUARD_VAR_REGEX = re.compile(r".*(balance|amount|total|supply|reserve).*", re.IGNORECASE)

    def _detect(self):
        results = []
        for contract in self.contracts:
            if is_vendored_or_test_contract(contract):
                continue
            for function in contract.functions_and_modifiers_declared:
                if not self._FN_NAME_REGEX.search(function.name):
                    continue

                if not any(self._WRITE_VAR_REGEX.search(var.name) for var in function.state_variables_written):
                    continue

                has_guard = False
                for node in function.nodes:
                    if node.type not in (NodeType.IF, NodeType.EXPRESSION):
                        continue
                    if not node.contains_require_or_assert():
                        continue
                    expr_text = str(node.expression) if node.expression else ""
                    if self._GUARD_VAR_REGEX.search(expr_text):
                        has_guard = True
                        break

                if has_guard:
                    continue

                info = [
                    function,
                    " - remove-redundant-code-in-cashin-proof-of-concept-take-a-look-at: "
                    "cashIn-like function writes accounting state without a local accounting-family guard. ",
                ]
                results.append(self.generate_result(info))
        return results
