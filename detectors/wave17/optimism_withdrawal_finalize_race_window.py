"""
optimism-withdrawal-finalize-race-window

Narrow fixture-smoke detector for OP Stack withdrawal wrappers that finalize
through an OptimismPortal-style call after only a legacy timestamp/finalization
period check, without a visible fault-dispute-game status/finality check.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path as _Path

sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_leaf_helper, is_vendored_or_test_contract

from slither.detectors.abstract_detector import (
    DETECTOR_INFO,
    AbstractDetector,
    DetectorClassification,
)
from slither.utils.output import Output


_PORTAL_HINT_RE = re.compile(
    r"\b(OptimismPortal|IOptimismPortal|finalizeWithdrawalTransaction|"
    r"proveWithdrawal|provenWithdrawal|finalizationPeriodSeconds)\b",
    re.IGNORECASE,
)
_FINALIZER_NAME_RE = re.compile(
    r"\b(finalize|claim|relay|process)[A-Za-z0-9_]*(withdraw|message)",
    re.IGNORECASE,
)
_PORTAL_FINALIZE_CALL_RE = re.compile(
    r"\.\s*finalizeWithdrawal(?:Transaction)?\s*\(",
    re.IGNORECASE,
)
_LEGACY_TIMESTAMP_GATE_RE = re.compile(
    r"\bblock\.timestamp\b[^;{}]*(?:>=|>|<=|<)[^;{}]*"
    r"(?:finalizationPeriodSeconds|FINALIZATION_PERIOD|7\s+days|"
    r"provenWithdrawalAt|proofTimestamp|provenAt)|"
    r"(?:finalizationPeriodSeconds|FINALIZATION_PERIOD|7\s+days|"
    r"provenWithdrawalAt|proofTimestamp|provenAt)[^;{}]*(?:>=|>|<=|<)"
    r"[^;{}]*\bblock\.timestamp\b",
    re.IGNORECASE | re.DOTALL,
)
_FAULT_PROOF_FINALITY_GUARD_RE = re.compile(
    r"\b(?:FaultDisputeGame|faultDisputeGame|disputeGameFactory|"
    r"respectedGameType|DEFENDER_WINS|CHALLENGER_WINS|game\.status|"
    r"\.status\s*\(|proofMaturityDelaySeconds|disputeGameFinalityDelaySeconds|"
    r"superchainWithdrawalDelay|DELAY_AFTER_PROVE|additionalWithdrawalDelay)"
    r"\b",
    re.IGNORECASE,
)


def _source_of(obj) -> str:
    try:
        return obj.source_mapping.content or ""
    except Exception:
        return ""


class OptimismWithdrawalFinalizeRaceWindow(AbstractDetector):
    ARGUMENT = "optimism-withdrawal-finalize-race-window"
    HELP = (
        "OP Stack withdrawal wrapper calls OptimismPortal finalization after "
        "only a legacy timestamp/finalization-period gate, with no visible "
        "fault-dispute-game status/finality check"
    )
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = (
        "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/"
        "optimism-withdrawal-finalize-race-window.yaml"
    )
    WIKI_TITLE = "OP Stack withdrawal wrapper finalizes on legacy timestamp only"
    WIKI_DESCRIPTION = (
        "Fixture-smoke/source-shape proof only. The detector flags wrapper "
        "finalizers that call an OptimismPortal-style withdrawal finalization "
        "after checking only a legacy proof timestamp/finalization period. It "
        "does not prove a live portal can be bypassed."
    )
    WIKI_EXPLOIT_SCENARIO = (
        "A wrapper records `provenAt`, waits `finalizationPeriodSeconds`, then "
        "calls `OptimismPortal.finalizeWithdrawalTransaction` without checking "
        "that the referenced fault dispute game resolved with defender wins or "
        "that any post-proof finality delay elapsed."
    )
    WIKI_RECOMMENDATION = (
        "Before forwarding finalization, read the portal's current maturity and "
        "dispute-game finality parameters, verify the referenced dispute game "
        "status/outcome, and apply any Superchain/additional withdrawal delay."
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
            if not _PORTAL_HINT_RE.search(contract_source):
                continue

            for function in contract.functions_and_modifiers_declared:
                if is_leaf_helper(function):
                    continue
                if getattr(function, "visibility", "") not in {"external", "public"}:
                    continue
                if not _FINALIZER_NAME_RE.search(getattr(function, "name", "") or ""):
                    continue

                source = _source_of(function)
                if not source:
                    continue
                if not _PORTAL_FINALIZE_CALL_RE.search(source):
                    continue
                if not _LEGACY_TIMESTAMP_GATE_RE.search(source):
                    continue
                if _FAULT_PROOF_FINALITY_GUARD_RE.search(source):
                    continue

                info: DETECTOR_INFO = [
                    function,
                    " forwards OP withdrawal finalization after only a legacy "
                    "timestamp/finalization-period gate, without a visible "
                    "fault-dispute-game status/finality check.\n",
                ]
                results.append(self.generate_result(info))

        return results
