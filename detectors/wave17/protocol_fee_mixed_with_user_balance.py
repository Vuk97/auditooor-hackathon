"""
Fixture-smoke detector for protocol-fee-mixed-with-user-balance.

This row remains NOT_SUBMIT_READY. It proves only the owned source shape where
an internal fee helper computes a protocol fee, retains it inside the same ETH
balance used for user reserves, and exposes an owner fee-withdraw path that
reads raw `address(this).balance` instead of a dedicated protocol-fee ledger.
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


class ProtocolFeeMixedWithUserBalance(AbstractDetector):
    ARGUMENT = "protocol-fee-mixed-with-user-balance"
    HELP = (
        "NOT_SUBMIT_READY fixture-smoke/source-shape proof only: flags the "
        "narrow shape where protocol fees stay in the same contract balance as "
        "user reserves and fee withdrawal reads raw `address(this).balance` "
        "without a dedicated accrued-protocol-fee counter."
    )
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = (
        "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/"
        "protocol-fee-mixed-with-user-balance.yaml"
    )
    WIKI_TITLE = "Protocol fees are retained inside the same balance used for user reserves"
    WIKI_DESCRIPTION = (
        "Fixture-smoke/source-shape proof only. This row looks for a narrow "
        "Solidity shape where an internal fee helper computes `protocolFee`, "
        "pays some other fee leg, leaves the protocol fee in the contract, and "
        "the admin fee-withdraw flow later reads raw `address(this).balance` "
        "without a dedicated `accruedProtocolFees` ledger. NOT_SUBMIT_READY."
    )
    WIKI_EXPLOIT_SCENARIO = (
        "Alice buys while `protocolFeePercent` is 5%, then Bob buys after the "
        "owner raises the fee to 10%. The contract keeps protocol fees inside "
        "the same ETH balance that backs user exit liquidity. When the owner "
        "later withdraws fees by reading raw `address(this).balance`, the "
        "contract cannot distinguish accumulated protocol fees from user "
        "reserve ETH."
    )
    WIKI_RECOMMENDATION = (
        "Track protocol fees in a dedicated counter such as "
        "`accruedProtocolFees += protocolFee`, and have the withdraw path read "
        "and zero that counter rather than using raw contract balance. Keep "
        "this row NOT_SUBMIT_READY until evidence expands beyond the owned "
        "fixture pair."
    )

    SUBMISSION_POSTURE = "NOT_SUBMIT_READY"
    COVERAGE_CLAIM = "detector_fixture_smoke_only"
    PROMOTION_ALLOWED = False

    _LEDGER_FIELD_RE = re.compile(
        r"(?ix)"
        r"(?:"
        r"(?:accrued|claimable|collected|pending|unclaimed)\w*"
        r"(?:protocol|treasury|platform)\w*fees?"
        r"|"
        r"(?:protocol|treasury|platform)\w*fees?\w*"
        r"(?:accrued|balance|ledger|vault|collected)"
        r")"
    )
    _LEDGER_WRITE_RE = re.compile(
        r"(?is)\b(?:accruedProtocolFees|protocolFeesAccrued|pendingProtocolFees|"
        r"claimableProtocolFees|protocolFeeBalance)\b\s*(?:\+=|=)"
    )
    _CONTRACT_CONTEXT_RE = re.compile(
        r"(?is)\b(?:protocolFeePercent|protocolFeeBps|setProtocolFee|"
        r"withdrawProtocolFees|buy|sell|reserve)\b"
    )
    _BALANCE_READ_RE = re.compile(r"address\s*\(\s*this\s*\)\s*\.balance", re.IGNORECASE)
    _FEE_HELPER_NAME_RE = re.compile(
        r"^(?:_transferFees|_collectFee|_takeFee|_distributeFees)$",
        re.IGNORECASE,
    )
    _PROTOCOL_FEE_ASSIGN_RE = re.compile(r"(?is)\bprotocolFee\b\s*=\s*[^;]+;")
    _OTHER_FEE_RE = re.compile(
        r"(?is)\b(?:creatorFee|holderFee|subjectFee|referralFee|platformFee)\b"
    )
    _PAYMENT_RE = re.compile(
        r"(?is)(?:\.call\s*\{\s*value\s*:|\.transfer\s*\(|sendValue\s*\()"
    )
    _PROTOCOL_PAYOUT_RE = re.compile(
        r"(?is)(?:\.call\s*\{\s*value\s*:\s*protocolFee\b|"
        r"\.transfer\s*\(\s*protocolFee\b|sendValue\s*\([^,]+,\s*protocolFee\b)"
    )
    _WITHDRAW_NAME_RE = re.compile(
        r"^(?:withdrawProtocolFees|withdrawFees|claimProtocolFees|"
        r"sweepFees|sweepETH|rescueETH)$",
        re.IGNORECASE,
    )
    _ADMIN_GUARD_RE = re.compile(
        r"(?is)\b(?:onlyOwner|onlyAdmin|owner\s*==\s*msg\.sender|"
        r"msg\.sender\s*==\s*owner)\b"
    )

    @classmethod
    def _has_protocol_fee_ledger(cls, contract) -> bool:
        for variable in getattr(contract, "state_variables_declared", []):
            name = getattr(variable, "name", "") or ""
            if cls._LEDGER_FIELD_RE.search(name):
                return True
        return bool(cls._LEDGER_WRITE_RE.search(_source_of(contract)))

    @classmethod
    def _has_raw_balance_fee_withdraw(cls, contract) -> bool:
        for function in contract.functions_and_modifiers_declared:
            if getattr(function, "visibility", "") not in {"external", "public"}:
                continue
            name = getattr(function, "name", "") or ""
            if not cls._WITHDRAW_NAME_RE.match(name):
                continue
            source = _source_of(function)
            if not source:
                continue
            if not cls._BALANCE_READ_RE.search(source):
                continue
            if not cls._ADMIN_GUARD_RE.search(source):
                continue
            if cls._LEDGER_WRITE_RE.search(source):
                continue
            return True
        return False

    @classmethod
    def _has_retained_protocol_fee_shape(cls, function) -> bool:
        if getattr(function, "visibility", "") != "internal":
            return False
        if is_leaf_helper(function):
            return False

        name = getattr(function, "name", "") or ""
        if not cls._FEE_HELPER_NAME_RE.match(name):
            return False

        source = _source_of(function)
        if not source:
            return False
        if not cls._PROTOCOL_FEE_ASSIGN_RE.search(source):
            return False
        if not cls._OTHER_FEE_RE.search(source):
            return False
        if not cls._PAYMENT_RE.search(source):
            return False
        if cls._PROTOCOL_PAYOUT_RE.search(source):
            return False
        if cls._LEDGER_WRITE_RE.search(source):
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
            if not self._CONTRACT_CONTEXT_RE.search(contract_source):
                continue
            if not self._BALANCE_READ_RE.search(contract_source):
                continue
            if self._has_protocol_fee_ledger(contract):
                continue
            if not self._has_raw_balance_fee_withdraw(contract):
                continue

            for function in contract.functions_and_modifiers_declared:
                if not self._has_retained_protocol_fee_shape(function):
                    continue
                info = [
                    function,
                    " -- protocol-fee-mixed-with-user-balance: protocol fee is "
                    "retained in the same contract balance used for reserves, "
                    "and fee withdrawal reads raw `address(this).balance` with "
                    "no dedicated protocol-fee ledger. NOT_SUBMIT_READY: "
                    "fixture-smoke/source-shape proof only.",
                ]
                results.append(self.generate_result(info))
        return results
