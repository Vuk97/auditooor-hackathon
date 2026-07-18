"""
Fixture-smoke detector for perp-glv-cancel-fee-attributed-to-keeper-not-account.

This row remains NOT_SUBMIT_READY. It proves only the owned source shape where
the USER_INITIATED_CANCEL branch of a GLV cancel flow attributes the execution
fee refund to `msg.sender` instead of the request owner's `.account()`.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path as _Path

sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_leaf_helper, is_vendored_or_test_contract  # noqa: E402

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


def _source_of(obj) -> str:
    try:
        return obj.source_mapping.content or ""
    except Exception:
        return ""


class PerpGlvCancelFeeAttributedToKeeperNotAccount(AbstractDetector):
    ARGUMENT = "perp-glv-cancel-fee-attributed-to-keeper-not-account"
    HELP = (
        "GLV user-initiated cancel forwards the execution-fee refund to "
        "`keeper: msg.sender` instead of the request owner's `.account()`."
    )
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = (
        "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/"
        "perp-glv-cancel-fee-attributed-to-keeper-not-account.yaml"
    )
    WIKI_TITLE = "GLV user cancel refunds execution fee to msg.sender instead of request owner"
    WIKI_DESCRIPTION = (
        "Fixture-smoke/source-shape proof only. This row flags only the owned "
        "GLV cancel shape where a USER_INITIATED_CANCEL branch forwards "
        "`keeper: msg.sender` into the cancel/refund props rather than the "
        "request owner's recorded `.account()`. NOT_SUBMIT_READY."
    )
    WIKI_EXPLOIT_SCENARIO = (
        "A user creates a GLV deposit and later cancels it through a relay or "
        "router. The relay forwards into `cancelGlvDeposit`, where the cancel "
        "util receives `keeper: msg.sender` for USER_INITIATED_CANCEL. The "
        "execution fee refund lands on the relay instead of the user's "
        "account, leaking the refund on every relayed cancel."
    )
    WIKI_RECOMMENDATION = (
        "For USER_INITIATED_CANCEL, bind the refund recipient to the request "
        "owner (`deposit.account()`, `withdrawal.account()`, or equivalent) "
        "rather than `msg.sender`. Keep this row NOT_SUBMIT_READY until "
        "evidence expands beyond the owned fixture pair."
    )

    SUBMISSION_POSTURE = "NOT_SUBMIT_READY"
    COVERAGE_CLAIM = "detector_fixture_smoke_only"
    PROMOTION_ALLOWED = False

    _CONTRACT_GATE_RE = re.compile(
        r"\b(?:GlvHandler|GlvDeposit|GlvWithdrawal|Glv)\b",
        re.IGNORECASE,
    )
    _ENTRY_NAME_RE = re.compile(
        r"^(?:cancelGlvDeposit|cancelGlvWithdrawal|cancelDeposit|cancelWithdrawal)$",
        re.IGNORECASE,
    )
    _USER_CANCEL_RE = re.compile(r"\bUSER_INITIATED_CANCEL\b")
    _KEEPER_MSG_SENDER_RE = re.compile(
        r"\bkeeper\s*:\s*msg\s*\.\s*sender\b",
        re.IGNORECASE,
    )
    _OWNER_ACCOUNT_RE = re.compile(
        r"\b(?:deposit|withdrawal|request|glvDeposit|glvWithdrawal)\s*"
        r"\.\s*account\s*\(\s*\)",
        re.IGNORECASE,
    )
    _REFUND_FLOW_RE = re.compile(
        r"\b(?:executionFee|refund|cancel(?:Glv)?(?:Deposit|Withdrawal)?|keeper)\b",
        re.IGNORECASE,
    )

    @classmethod
    def _has_keeper_refund_misattribution_shape(cls, function) -> bool:
        if getattr(function, "visibility", "") not in {"external", "public", "internal"}:
            return False
        if is_leaf_helper(function):
            return False

        name = getattr(function, "name", "") or ""
        if not cls._ENTRY_NAME_RE.match(name):
            return False

        source = _source_of(function)
        if not source:
            return False
        if not cls._USER_CANCEL_RE.search(source):
            return False
        if not cls._REFUND_FLOW_RE.search(source):
            return False
        if not cls._KEEPER_MSG_SENDER_RE.search(source):
            return False
        if cls._OWNER_ACCOUNT_RE.search(source):
            return False
        return True

    def _detect(self):
        results = []
        for contract in self.contracts:
            if is_vendored_or_test_contract(contract):
                continue

            contract_source = _source_of(contract)
            if not contract_source:
                continue
            if not self._CONTRACT_GATE_RE.search(contract_source):
                continue

            for function in contract.functions_and_modifiers_declared:
                if not self._has_keeper_refund_misattribution_shape(function):
                    continue
                info = [
                    function,
                    " -- perp-glv-cancel-fee-attributed-to-keeper-not-account: "
                    "USER_INITIATED_CANCEL forwards `keeper: msg.sender` "
                    "instead of the request owner account. NOT_SUBMIT_READY: "
                    "fixture-smoke/source-shape proof only.",
                ]
                results.append(self.generate_result(info))
        return results
