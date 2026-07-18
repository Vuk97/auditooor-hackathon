"""
r94-loop-fiat-shamir-missing-observation — generated from
reference/patterns.dsl/r94-loop-fiat-shamir-missing-observation.yaml
DO NOT EDIT BY HAND. Regenerate via:
python3 tools/pattern-compile.py r94-loop-fiat-shamir-missing-observation.yaml
Source: loop-cycle-9-solidity-sibling-of-fiat-shamir-rust
"""

from __future__ import annotations

import re
import sys
from pathlib import Path as _Path

sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_leaf_helper, is_vendored_or_test_contract

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


_FN_NAME_RE = re.compile(r"(?i)(verify|verifier|fiatShamir|challenge|recursive)")
_CHALLENGE_RE = re.compile(
    r"\.challenge\s*\(|\.squeeze\s*\(|\.getChallenge\s*\(|"
    r"fiat_shamir::challenge|transcript\.challenge|derive_challenge"
)
_OBSERVE_RE = re.compile(
    r"\.observe\s*\(|\.absorb\s*\(|\.append\s*\(|\.update\s*\(|"
    r"transcript\.add|fiat_shamir::observe|\.pushToTranscript\s*\("
)


class R94LoopFiatShamirMissingObservation(AbstractDetector):
    ARGUMENT = "r94-loop-fiat-shamir-missing-observation"
    HELP = (
        "Fiat-Shamir verifier derives a challenge without first observing the "
        "protocol-public values it should bind"
    )
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.LOW
    WIKI = (
        "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/"
        "r94-loop-fiat-shamir-missing-observation.yaml"
    )
    WIKI_TITLE = "Fiat-Shamir challenge without prior observation"
    WIKI_DESCRIPTION = (
        "Fixture-smoke/source-shape proof only. The detector flags a verifier "
        "entrypoint that derives a Fiat-Shamir challenge from a transcript "
        "without any visible prior observe/absorb/append step for the protocol "
        "inputs that should have been bound first. NOT_SUBMIT_READY."
    )
    WIKI_EXPLOIT_SCENARIO = (
        "A public verifier path calls `challenge()` before any transcript "
        "observation of the statement, so the prover can derive the same "
        "challenge without committing the public values the proof is meant to "
        "bind."
    )
    WIKI_RECOMMENDATION = (
        "Observe or absorb every protocol-public value before deriving the "
        "challenge, and keep this row NOT_SUBMIT_READY until the fixture-smoke "
        "pair stays the only proof available."
    )

    SUBMISSION_POSTURE = "NOT_SUBMIT_READY"
    COVERAGE_CLAIM = "detector_fixture_smoke_only"
    PROMOTION_ALLOWED = False

    def _function_source(self, function) -> str:
        try:
            return function.source_mapping.content or ""
        except Exception:
            return ""

    def _detect(self):
        results = []

        for contract in self.contracts:
            if is_vendored_or_test_contract(contract):
                continue
            contract_source = getattr(getattr(contract, "source_mapping", None), "content", "") or ""
            if not re.search(r"(Verifier|Transcript|FiatShamir|challenge|recurs)", contract_source):
                continue

            for function in contract.functions_and_modifiers_declared:
                if is_leaf_helper(function):
                    continue
                if getattr(function, "visibility", "") not in {"external", "public", "internal"}:
                    continue
                if not _FN_NAME_RE.search(getattr(function, "name", "") or ""):
                    continue

                source = self._function_source(function)
                if not source:
                    continue

                chal_m = _CHALLENGE_RE.search(source)
                if chal_m is None:
                    continue
                if _OBSERVE_RE.search(source[:chal_m.start()]):
                    continue

                info = [
                    function,
                    " — r94-loop-fiat-shamir-missing-observation: pattern matched. See WIKI for details.\n",
                ]
                results.append(self.generate_result(info))

        return results
