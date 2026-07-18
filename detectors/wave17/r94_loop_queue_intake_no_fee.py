"""
r94-loop-queue-intake-no-fee — generated from
reference/patterns.dsl/r94-loop-queue-intake-no-fee.yaml
DO NOT EDIT BY HAND. Regenerate via:
python3 tools/pattern-compile.py r94-loop-queue-intake-no-fee.yaml
Source: loop-cycle-4-queue-spam-dos-solidity-sibling
"""

from __future__ import annotations

import re
import sys
from pathlib import Path as _Path

sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_leaf_helper, is_vendored_or_test_contract

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


_QUEUE_FN_RE = re.compile(r"(?i)(submit|request|intake|enqueue|queue|post)")
_QUEUE_APPEND_RE = re.compile(r"\.(push|push_back|enqueue)\s*\(|\bappend\s*\(")
_FEE_GUARD_RE = re.compile(
    r"require\s*\(\s*msg\.value|_chargeFee|payFee|"
    r"\.transferFrom\s*\([^,]*,[^,]*fee|\bintakeFee\b|\bsubmissionFee\b",
    re.IGNORECASE,
)
_RATE_LIMIT_RE = re.compile(
    r"lastCall|cooldown|throttle|rateLimit|blockNumber\s*-\s*\w+Ts|lastSubmit",
    re.IGNORECASE,
)
_USER_CAP_RE = re.compile(
    r"pendingCount|userQuota|requestsBy\[|perUser\[|userSlots",
    re.IGNORECASE,
)


class R94LoopQueueIntakeNoFee(AbstractDetector):
    ARGUMENT = "r94-loop-queue-intake-no-fee"
    HELP = (
        "NOT_SUBMIT_READY detector-fixture-smoke-only: external/public queue "
        "intake appends a processing request with no visible fee, no "
        "rate-limit, and no per-caller cap."
    )
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.LOW
    WIKI = (
        "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/"
        "r94-loop-queue-intake-no-fee.yaml"
    )
    WIKI_TITLE = "Queue intake appends load-bearing work without cost controls"
    WIKI_DESCRIPTION = (
        "Fixture-smoke/source-shape proof only. The detector flags the owned "
        "Solidity shape where an external/public request-intake function "
        "appends to a processing queue without any visible fee, cooldown, or "
        "per-caller pending cap. NOT_SUBMIT_READY."
    )
    WIKI_EXPLOIT_SCENARIO = (
        "A permissionless request intake keeps pushing entries into a queue "
        "that later processing must walk, but the intake path charges no fee, "
        "tracks no last-submit cooldown, and enforces no per-user pending "
        "quota. Attackers can spam cheap entries until processing paths become "
        "storage-heavy or unusable."
    )
    WIKI_RECOMMENDATION = (
        "Charge a meaningful intake fee or enforce explicit per-caller "
        "cooldown and pending-cap controls before queue insertion. Keep this "
        "row NOT_SUBMIT_READY until evidence expands beyond the owned "
        "fixture-smoke pair."
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

    def _detect(self):
        results = []

        for contract in self.contracts:
            if is_vendored_or_test_contract(contract):
                continue
            contract_source = self._contract_source(contract)
            if not re.search(r"(?i)(queue|request|checkpoint|process)", contract_source):
                continue

            for function in contract.functions_and_modifiers_declared:
                if is_leaf_helper(function):
                    continue
                if getattr(function, "visibility", "") not in {"external", "public"}:
                    continue
                if not _QUEUE_FN_RE.search(getattr(function, "name", "") or ""):
                    continue

                source = self._function_source(function)
                if not source:
                    continue
                if not _QUEUE_APPEND_RE.search(source):
                    continue
                if _FEE_GUARD_RE.search(source):
                    continue
                if _RATE_LIMIT_RE.search(source):
                    continue
                if _USER_CAP_RE.search(source):
                    continue

                info = [
                    function,
                    " — r94-loop-queue-intake-no-fee: pattern matched. See WIKI for details.\n",
                ]
                results.append(self.generate_result(info))

        return results
