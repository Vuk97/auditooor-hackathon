"""
incorrect-self-referencing-compound-arithmetic

Manual graveyard repair for the Glider row. The generated detector had broken
string quoting and placeholder regexes that did not model the row's source
shape at all.

This repaired detector intentionally stays narrow and honest: it looks only
for a direct compound assignment on a written state variable where the same
slot name also appears on the right-hand side, e.g. `balance += balance +
delta`.

This is fixture-smoke / source-shape evidence only and should remain
`submission_posture: NOT_SUBMIT_READY`.

Spec: detectors/_specs/drafts_glider/incorrect-self-referencing-compound-arithmetic.yaml
"""

import re
import sys
from pathlib import Path as _Path

_DETECTORS_ROOT = _Path(__file__).resolve().parent.parent
if str(_DETECTORS_ROOT) not in sys.path:
    sys.path.insert(0, str(_DETECTORS_ROOT))

from _template_utils import is_vendored_or_test_contract

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class IncorrectSelfReferencingCompoundArithmetic(AbstractDetector):
    ARGUMENT = "incorrect-self-referencing-compound-arithmetic"
    HELP = "State slot uses self-referencing compound arithmetic in the same assignment"
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.LOW
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/bug_patterns_observed.md"
    WIKI_TITLE = "Incorrect Self-Referencing Compound Arithmetic"
    WIKI_DESCRIPTION = (
        "Flags source shapes where a state variable is updated with compound "
        "arithmetic and the same slot name is also reused on the right-hand "
        "side, such as `balance += balance + delta`. This is only a narrow "
        "fixture-smoke approximation of the broader WADJET-style arithmetic bug."
    )
    WIKI_EXPLOIT_SCENARIO = (
        "A protocol intends to add only a delta into a running accumulator, but "
        "the mutating statement also reuses the already-written slot on the "
        "right-hand side. That can double-count balance-like state and push "
        "minting, reward, or accounting paths far away from the intended value."
    )
    WIKI_RECOMMENDATION = (
        "Split the read and write explicitly: compute the intended next value "
        "from stable operands, then assign once. Keep this row "
        "NOT_SUBMIT_READY until there is semantic evidence beyond the owned "
        "fixture pair."
    )

    _SELF_REF_TEMPLATE = r"\b{name}\b\s*(\+=|-=|\*=|/=|%=)\s*[^;{{}}]*\b{name}\b"

    @classmethod
    def _self_ref_pattern(cls, state_var_name: str) -> re.Pattern[str]:
        escaped = re.escape(state_var_name)
        return re.compile(
            cls._SELF_REF_TEMPLATE.format(name=escaped),
            re.MULTILINE | re.DOTALL,
        )

    def _detect(self):
        results = []
        for contract in self.contracts:
            if is_vendored_or_test_contract(contract):
                continue

            for function in contract.functions_and_modifiers_declared:
                if function.is_constructor or (function.name or "").startswith("slitherConstructor"):
                    continue

                body = function.source_mapping.content or ""
                if not body:
                    continue

                for state_var in getattr(function, "state_variables_written", []) or []:
                    match = self._self_ref_pattern(state_var.name).search(body)
                    if not match:
                        continue

                    operator = match.group(1)
                    info = [
                        function,
                        " performs self-referencing compound arithmetic on state variable `",
                        state_var.name,
                        "` via `",
                        operator,
                        "` while the same slot name also appears on the right-hand side. ",
                        "This row is fixture-smoke / source-shape proof only and remains "
                        "NOT_SUBMIT_READY.",
                    ]
                    results.append(self.generate_result(info))
                    break

        return results
