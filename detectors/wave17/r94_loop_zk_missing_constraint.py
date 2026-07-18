"""
r94-loop-zk-missing-constraint — fixture-smoke/source-shape implementation.
Source: loop-cycle-8-solidity-sibling-of-zk-circuit-missing-constraint
"""

from __future__ import annotations

import re
import sys
from pathlib import Path as _Path

sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_leaf_helper, is_vendored_or_test_contract

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


_CONTRACT_RE = re.compile(r"(verify|Verifier|Fiat|Shamir|circuit|Groth|Plonk|STARK|challenge)")
_FN_NAME_RE = re.compile(
    r"(?i)(verify|evalProof|evalOpening|recursiveVerify|observe|fiatShamir|constrain|commitDomain)"
)
_PROVER_VALUE_RE = re.compile(
    r"\b("
    r"proverSupplied\w*|prover_\w+|operand\w*|chipOrdering|quotient\w*|"
    r"logBlowup|permutationChallenges|domainSize"
    r")\b"
)
_SINK_RE = re.compile(r"keccak256\s*\(|abi\.encode|challenge|quotient|domain|alphaPows|[\*\+\-/%]")


class R94LoopZkMissingConstraint(AbstractDetector):
    ARGUMENT = "r94-loop-zk-missing-constraint"
    HELP = (
        "NOT_SUBMIT_READY fixture-smoke/source-shape proof only: verifier-like "
        "functions that incorporate prover-shaped values without any visible "
        "require/assert/constrain on those same values."
    )
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.LOW
    WIKI = (
        "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/"
        "r94-loop-zk-missing-constraint.yaml"
    )
    WIKI_TITLE = "Verifier path uses prover-supplied value without a paired constraint"
    WIKI_DESCRIPTION = (
        "Fixture-smoke/source-shape proof only. NOT_SUBMIT_READY. This row "
        "proves only the owned Solidity shape where a verifier-like function "
        "reads a prover-shaped value such as `proverSupplied*`, `logBlowup`, "
        "`chipOrdering`, or `quotient*` and then uses it in proof-domain logic "
        "without any visible `require(...)`, `assert(...)`, or "
        "`constrain(...)` that mentions the same value."
    )
    WIKI_EXPLOIT_SCENARIO = (
        "A verifier entrypoint accepts a prover-controlled opening or blowup "
        "factor, mixes it into proof arithmetic or hashing, and never applies "
        "a range or equality constraint to that same input. The prover can "
        "choose an unconstrained value and steer the proof relation."
    )
    WIKI_RECOMMENDATION = (
        "Constrain every prover-supplied value before it is used in proof "
        "arithmetic, hashing, or transcript/domain derivation, and keep this "
        "row NOT_SUBMIT_READY until evidence expands beyond the owned fixture "
        "pair."
    )

    SUBMISSION_POSTURE = "NOT_SUBMIT_READY"
    COVERAGE_CLAIM = "detector_fixture_smoke_only"
    PROMOTION_ALLOWED = False

    def _function_source(self, function) -> str:
        try:
            return function.source_mapping.content or ""
        except Exception:
            return ""

    def _contract_source(self, contract) -> str:
        try:
            return contract.source_mapping.content or ""
        except Exception:
            return ""

    def _suspicious_values(self, source: str) -> list[str]:
        values: list[str] = []
        for match in _PROVER_VALUE_RE.finditer(source):
            name = match.group(1)
            if name not in values:
                values.append(name)
        return values

    def _is_live_value(self, source: str, name: str) -> bool:
        if len(re.findall(rf"\b{re.escape(name)}\b", source)) < 2:
            return False
        return _SINK_RE.search(source) is not None

    # The proof stays narrow by requiring the constraint to mention the same
    # prover-shaped value rather than accepting unrelated `require(...)` calls.
    def _has_constraint(self, source: str, name: str) -> bool:
        token = rf"\b{re.escape(name)}\b"
        patterns = (
            rf"require\s*\([^)]*{token}",
            rf"assert\s*\([^)]*{token}",
            rf"_assert(?:Eq|Bool|Range|ValidWord)\s*\([^)]*{token}",
            rf"(?:_constrain\w*|constrain\w*|_requireConstraint)\s*\([^)]*{token}",
            rf"\.constrain\w*\s*\([^)]*{token}",
        )
        return any(re.search(pattern, source) for pattern in patterns)

    def _detect(self):
        results = []

        for contract in self.contracts:
            if is_vendored_or_test_contract(contract):
                continue
            if _CONTRACT_RE.search(self._contract_source(contract)) is None:
                continue

            for function in contract.functions_and_modifiers_declared:
                if is_leaf_helper(function):
                    continue
                if getattr(function, "visibility", "") not in {"external", "public", "internal"}:
                    continue
                if _FN_NAME_RE.search(getattr(function, "name", "") or "") is None:
                    continue

                source = self._function_source(function)
                if not source:
                    continue

                suspicious_values = [
                    name for name in self._suspicious_values(source) if self._is_live_value(source, name)
                ]
                if not suspicious_values:
                    continue

                unconstrained = [name for name in suspicious_values if not self._has_constraint(source, name)]
                if not unconstrained:
                    continue

                preview = ", ".join(unconstrained[:3])
                info = [
                    function,
                    (
                        " — r94-loop-zk-missing-constraint: prover-shaped value(s) "
                        f"{preview} are used without a paired constraint. "
                        "See WIKI for details.\n"
                    ),
                ]
                results.append(self.generate_result(info))

        return results
