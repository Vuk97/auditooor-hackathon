"""
w69-bridge-state-root-consumed-without-finality-check

Custom Solidity detector for a narrow bridge/finality omission shape taken
from confirmed corpus anchors:

- hyperbridge--hb-optimism-l2oracle-unfinalized-output-HIGH
- hyperbridge--hb-arbitrum-orbit-unconfirmed-node-HIGH

The detector looks for a bridge or consensus verification path that fetches an
output/state root from an external oracle-style source and then consumes or
returns it without an explicit finality/challenge-status guard in the same
function.
"""

from __future__ import annotations

import re
import sys as _sys
from pathlib import Path as _Path

_sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_leaf_helper, is_vendored_or_test_contract

from slither.detectors.abstract_detector import (
    DETECTOR_INFO,
    AbstractDetector,
    DetectorClassification,
)
from slither.utils.output import Output


_BRIDGE_SURFACE_RE = re.compile(
    r"(?i)\b(bridge|cross.?chain|consensus|optimism|arbitrum|outputRoot|stateRoot|proof)\b"
)
_FN_NAME_RE = re.compile(
    r"(?i)(verify|validate|consume|process|check).*(consensus|proof|root|state|commitment|header|output)"
)
_ROOT_FETCH_RE = re.compile(r"(?i)\b(outputRootAt|rootClaim|getL2StateRoot|getStateRoot)\s*\(")
_ROOT_USE_RE = re.compile(
    r"(?i)(return\s+\w*Root\b|return\s+\w*root\b|\b(stateRoot|outputRoot)\s*==|\btrustedRoot\b|\bacceptedRoot\b)"
)
_PROOF_CONTEXT_RE = re.compile(r"(?i)\b(proof|payload|message|height|index|commitment)\b")
_FINALITY_GUARD_RE = re.compile(
    r"(?i)(isFinalized|finalizedAt|finalizationPeriod|gameStatus|verify_not_challenged|"
    r"notChallenged|defenderWins|isConfirmed|confirmedAt|challengeWindow|disputeWindow|"
    r"hasPassedFinality|isOutputFinalized)"
)


def _source_of(obj) -> str:
    try:
        return obj.source_mapping.content or ""
    except Exception:
        return ""


class W69BridgeStateRootConsumedWithoutFinalityCheck(AbstractDetector):
    ARGUMENT = "w69-bridge-state-root-consumed-without-finality-check"
    HELP = "Bridge or consensus verifier consumes an output/state root without an in-function finality check"
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM

    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/fetchable_vuln_corpus.jsonl"
    WIKI_TITLE = "Bridge verifier consumes output root without finality guard"
    WIKI_DESCRIPTION = (
        "A bridge or consensus path reads an output root or state root from an "
        "oracle-style source and immediately consumes or returns that root for "
        "proof validation. If the same function does not enforce finality, "
        "confirmation, or challenge-resolution first, the verifier can accept "
        "unfinalized state."
    )
    WIKI_EXPLOIT_SCENARIO = (
        "A verifier reads `oracle.outputRootAt(index)` and checks a message "
        "proof against that root, but never calls `oracle.isFinalized(index)` "
        "or an equivalent challenge-status guard. An attacker supplies a root "
        "that is still disputable or deletable and gets the bridge to consume "
        "it as trusted state."
    )
    WIKI_RECOMMENDATION = (
        "Require an explicit finality, confirmation, or challenge-status check "
        "in the same verification path before consuming the fetched root."
    )

    SUBMISSION_POSTURE = "NOT_SUBMIT_READY"
    COVERAGE_CLAIM = "detector_fixture_smoke_only"
    PROMOTION_ALLOWED = False

    def _detect(self) -> list[Output]:
        results: list[Output] = []

        for contract in self.contracts:
            if is_vendored_or_test_contract(contract):
                continue

            contract_source = _source_of(contract)
            if not _BRIDGE_SURFACE_RE.search(contract_source):
                continue

            for function in getattr(contract, "functions_and_modifiers_declared", []) or []:
                if is_leaf_helper(function):
                    continue

                name = getattr(function, "name", "") or ""
                if not _FN_NAME_RE.search(name):
                    continue

                source = _source_of(function)
                if not _ROOT_FETCH_RE.search(source):
                    continue
                if not _ROOT_USE_RE.search(source):
                    continue
                if not _PROOF_CONTEXT_RE.search(source):
                    continue
                if _FINALITY_GUARD_RE.search(source):
                    continue

                info: DETECTOR_INFO = [
                    function,
                    " fetches an output/state root and consumes it without an "
                    "explicit finality or challenge-status guard in the same "
                    "verification path.\n",
                ]
                results.append(self.generate_result(info))

        return results
