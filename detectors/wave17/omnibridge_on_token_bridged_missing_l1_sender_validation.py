"""
omnibridge-on-token-bridged-missing-l1-sender-validation

Fixture-smoke/source-shape detector for the owned Omnibridge row where an
`onTokenBridged(..., bytes data)` callback forwards attacker-controlled bridge
payload into local reward / staking processing. The callback can validate the
L2 bridge caller, but it cannot recover the original L1 sender, so data-driven
state changes here are not an authenticated message channel.

Submission posture: NOT_SUBMIT_READY. This row is intentionally narrow and is
backed only by the checked-in fixture pair.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path as _Path

sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_leaf_helper, is_vendored_or_test_contract

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


_CONTEXT_RE = re.compile(
    r"(?i)\b(?:Omnibridge|TargetDispenser|stakingQueueingNonces|stakingTargets|stakingAmounts)\b"
)
_FUNCTION_NAME_RE = re.compile(r"^onTokenBridged$")
_L1_SENDER_MARKERS_RE = re.compile(
    r"(?i)\b(?:messageSender\s*\(|l1Sender\b|rootMessageSender\b|originalCaller\b|"
    r"trustedDispatcher\b|trustedSender\b|bridgeMessenger\.messageSender|"
    r"amb\.messageSender|AMB\.messageSender)\b"
)


def _source(obj) -> str:
    try:
        return obj.source_mapping.content or ""
    except Exception:
        return ""


def _payload_param_name(function) -> str:
    for param in list(function.parameters or []):
        param_type = str(getattr(param, "type", "") or "")
        if "bytes" not in param_type:
            continue
        name = getattr(param, "name", "") or ""
        if name:
            return name
    return ""


def _process_call_regex(payload_name: str) -> re.Pattern[str]:
    return re.compile(
        r"(?is)\b(?:_receiveMessage|_processData|_handleBridgedPayload|_processMessage)"
        rf"\s*\(\s*{re.escape(payload_name)}\s*\)"
    )


class OmnibridgeOnTokenBridgedMissingL1SenderValidation(AbstractDetector):
    ARGUMENT = "omnibridge-on-token-bridged-missing-l1-sender-validation"
    HELP = (
        "Omnibridge `onTokenBridged(..., bytes data)` callback forwards bridge "
        "payload into staking / reward processing, even though the callback "
        "cannot authenticate the original L1 sender."
    )
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = (
        "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/"
        "omnibridge-on-token-bridged-missing-l1-sender-validation.yaml"
    )
    WIKI_TITLE = "Omnibridge callback processes unauthenticated L1 payload"
    WIKI_DESCRIPTION = (
        "Fixture-smoke/source-shape proof only: this row proves only the owned "
        "`onTokenBridged(..., bytes data)` shape where an Omnibridge-style L2 "
        "receiver forwards `data` into `_receiveMessage(data)` / "
        "`_processData(data)` reward logic. The callback can check the L2 bridge "
        "caller, but it cannot recover the original L1 sender. NOT_SUBMIT_READY."
    )
    WIKI_EXPLOIT_SCENARIO = (
        "A staking dispenser exposes `onTokenBridged(address token, uint256 "
        "amount, bytes data)` and calls `_receiveMessage(data)` after only "
        "checking `msg.sender == OMNIBRIDGE`. Any L1 user can relay arbitrary "
        "tokens plus crafted `data`; the L2 callback processes that payload as "
        "reward instructions because no authenticated L1 sender is available."
    )
    WIKI_RECOMMENDATION = (
        "Do not process privileged payload inside `onTokenBridged`. Use the "
        "token bridge only for balance movement, and route data processing "
        "through an authenticated messenger path that exposes the trusted L1 "
        "sender. Do not promote this row from fixture smoke alone."
    )

    def _detect(self):
        results = []
        for contract in self.contracts:
            if is_vendored_or_test_contract(contract):
                continue

            contract_src = _source(contract)
            if not _CONTEXT_RE.search(contract_src):
                continue

            for function in contract.functions_and_modifiers_declared:
                if getattr(function, "visibility", "") not in {"external", "public"}:
                    continue
                if is_leaf_helper(function):
                    continue
                if not _FUNCTION_NAME_RE.search(function.name or ""):
                    continue

                payload_name = _payload_param_name(function)
                if not payload_name:
                    continue

                function_src = _source(function)
                if not function_src:
                    continue
                if _L1_SENDER_MARKERS_RE.search(function_src):
                    continue
                if not _process_call_regex(payload_name).search(function_src):
                    continue

                info = [
                    function,
                    (
                        " — omnibridge-on-token-bridged-missing-l1-sender-validation: "
                        "`onTokenBridged` forwards bridge payload into local "
                        "processing even though the callback cannot authenticate "
                        "the original L1 sender. NOT_SUBMIT_READY: fixture-smoke/"
                        "source-shape proof only."
                    ),
                ]
                results.append(self.generate_result(info))
        return results
