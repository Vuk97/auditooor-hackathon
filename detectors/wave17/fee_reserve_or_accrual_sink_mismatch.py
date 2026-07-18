"""
fee-reserve-or-accrual-sink-mismatch

Source-backed fee-redirect detector for three narrow guard-mismatch families:
raw reserve math that includes accrued fee float, fee-rate or fee-charge paths
that skip an existing accrual helper, and protocol fee share views or sinks
that omit zero-receiver or max-share guards.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path as _Path

sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_leaf_helper, is_vendored_or_test_contract

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class FeeReserveOrAccrualSinkMismatch(AbstractDetector):
    ARGUMENT = "fee-reserve-or-accrual-sink-mismatch"
    HELP = (
        "Flags fee-dependent paths that use raw reserves, skip accrual before "
        "fee updates or charges, or trust protocol fee share config without "
        "receiver and max-share guards."
    )
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.LOW
    WIKI = "https://github.com/Vuk97/auditooor"
    WIKI_TITLE = "Fee reserve, accrual, or sink guard mismatch"
    WIKI_DESCRIPTION = (
        "Fee-dependent code must isolate or materialize fee state before "
        "user-facing pricing or fee-share selection. This detector is bounded "
        "to confirmed source fixture families and one sink-generalized "
        "protocol fee redirect shape."
    )
    WIKI_EXPLOIT_SCENARIO = (
        "A burner or swapper captures fee float included in reserve math, a "
        "fee-rate setter silently re-prices pending fees by skipping accrual, "
        "protocolFeeShare returns a misconfigured share, or convertFees sends "
        "fees to a configured receiver without applying the same guards."
    )
    WIKI_RECOMMENDATION = (
        "Subtract fee accumulators before reserve arithmetic, call the accrual "
        "helper before fee changes or charges, and guard fee share config with "
        "zero-receiver and max-share checks."
    )

    _FEE_ACCUMULATOR_RE = re.compile(
        r"\b(?:accruedFee|accruedFees|accumulatedFee|accumulatedFees|"
        r"launchpadFee|protocolFee|treasuryFee)\b",
        re.IGNORECASE,
    )
    _RESERVE_ENTRY_RE = re.compile(r"^(?:mint|burn|swap|_mint|_burn)$")
    _RESERVE_USE_RE = re.compile(
        r"\b(?:reserve0|reserve1|_reserve0|_reserve1)\b|"
        r"\bbalanceOf\s*\(\s*address\s*\(\s*this\s*\)\s*\)",
        re.IGNORECASE,
    )
    _RESERVE_GUARD_RE = re.compile(
        r"\b(?:realReserve|adjustedReserve|netReserve|feeAdjustedReserve|"
        r"subFees|_subtractFee)\b|"
        r"(?:\b(?:reserve0|reserve1|_reserve0|_reserve1|bal\w*)\b|"
        r"\bbalanceOf\s*\(\s*address\s*\(\s*this\s*\)\s*\))"
        r"\s*-\s*\b(?:accruedFee|accruedFees|accumulatedFee|"
        r"accumulatedFees|launchpadFee|protocolFee|treasuryFee)\b",
        re.IGNORECASE,
    )

    _ACCRUAL_HELPER_NAME_RE = re.compile(
        r"^(?:accrueFee|_accrue|updateFee|collectFee|syncFeeAccrual)$",
        re.IGNORECASE,
    )
    _FEE_UPDATE_ENTRY_RE = re.compile(
        r"^(?:setFee|changeFee|setRate|configureFee|chargeFee|collectFees|"
        r"updateFeeRate|setFeePerSecond|setFeePerShare)$",
        re.IGNORECASE,
    )
    _FEE_STATE_WRITE_RE = re.compile(
        r"\b(?:feePerSecond|feeRate|feePerShare|accumulatedFees|"
        r"accruedFees|feesAccrued)\s*(?:=|\+=|-=)",
        re.IGNORECASE,
    )
    _ACCRUAL_CALL_RE = re.compile(
        r"\b(?:accrueFee|_accrue|updateFee|collectFee|syncFeeAccrual)\s*\(",
        re.IGNORECASE,
    )

    _PROTOCOL_SHARE_NAME_RE = re.compile(r"^protocolFeeShare$")
    _PROTOCOL_SINK_ENTRY_RE = re.compile(
        r"^(?:convertFees|distributeFees|claimFees|collectProtocolFees|"
        r"sweepProtocolFees|settleProtocolFees)$",
        re.IGNORECASE,
    )
    _PROTOCOL_CONFIG_RE = re.compile(
        r"\b(?:protocolFeeConfig|protocolShare|protocolFeeShare|feeConfig)\b",
        re.IGNORECASE,
    )
    _ZERO_RECEIVER_GUARD_RE = re.compile(
        r"\b(?:feeReceiver|protocolReceiver|governorReceiver|receiver|"
        r"feeRecipient)\s*==\s*address\s*\(\s*0\s*\)",
        re.IGNORECASE,
    )
    _MAX_SHARE_GUARD_RE = re.compile(
        r"\b(?:protocolShare|protocolFeeShare|share)\s*>\s*"
        r"MAX_PROTOCOL_FEE_SHARE\b|"
        r"\bMAX_PROTOCOL_FEE_SHARE\b\s*<\s*"
        r"\b(?:protocolShare|protocolFeeShare|share)\b",
        re.IGNORECASE,
    )
    _PROTOCOL_SINK_RE = re.compile(
        r"\b(?:safeTransfer|transfer|_mint|mint)\s*\([^;{}]*"
        r"\b(?:feeReceiver|protocolReceiver|governorReceiver|receiver|"
        r"feeRecipient)\b",
        re.IGNORECASE,
    )
    _PROTOCOL_FEE_MATH_RE = re.compile(
        r"\b(?:protocolShare|protocolFeeShare|share)\b\s*(?:\*|/)\s*"
        r"\b\w*(?:fee|amount|asset|share)\w*\b|"
        r"\b\w*(?:fee|amount|asset|share)\w*\b\s*(?:\*|/)\s*"
        r"\b(?:protocolShare|protocolFeeShare|share)\b",
        re.IGNORECASE,
    )

    _INCLUDE_LEAF_HELPERS = False
    _INVERSE_CEI = False

    @staticmethod
    def _source(obj) -> str:
        try:
            return obj.source_mapping.content or ""
        except Exception:
            return ""

    @staticmethod
    def _function_name(function) -> str:
        return str(getattr(function, "name", "") or "")

    @staticmethod
    def _is_public_entry(function) -> bool:
        visibility = str(getattr(function, "visibility", "") or "").lower()
        return visibility in {"external", "public"}

    @classmethod
    def _contract_has_accrual_helper(cls, contract) -> bool:
        try:
            funcs = getattr(contract, "functions_and_modifiers_declared", []) or []
            return any(cls._ACCRUAL_HELPER_NAME_RE.search(cls._function_name(func)) for func in funcs)
        except Exception:
            return False

    @classmethod
    def _raw_reserve_fee_float(cls, contract_source: str, function_name: str, source: str) -> bool:
        if not cls._RESERVE_ENTRY_RE.search(function_name):
            return False
        if not cls._FEE_ACCUMULATOR_RE.search(contract_source):
            return False
        if not cls._RESERVE_USE_RE.search(source):
            return False
        return not cls._RESERVE_GUARD_RE.search(source)

    @classmethod
    def _missing_fee_accrual(cls, contract, function_name: str, source: str) -> bool:
        if not cls._FEE_UPDATE_ENTRY_RE.search(function_name):
            return False
        if not cls._contract_has_accrual_helper(contract):
            return False
        if not cls._FEE_STATE_WRITE_RE.search(source):
            return False
        return not cls._ACCRUAL_CALL_RE.search(source)

    @classmethod
    def _unguarded_protocol_share(cls, function_name: str, source: str) -> bool:
        if not cls._PROTOCOL_SHARE_NAME_RE.search(function_name):
            return False
        if not cls._PROTOCOL_CONFIG_RE.search(source):
            return False
        has_zero_guard = bool(cls._ZERO_RECEIVER_GUARD_RE.search(source))
        has_max_guard = bool(cls._MAX_SHARE_GUARD_RE.search(source))
        return not (has_zero_guard and has_max_guard)

    @classmethod
    def _unguarded_protocol_sink(cls, function_name: str, source: str) -> bool:
        if not cls._PROTOCOL_SINK_ENTRY_RE.search(function_name):
            return False
        if not cls._PROTOCOL_CONFIG_RE.search(source):
            return False
        if not cls._PROTOCOL_SINK_RE.search(source):
            return False
        if not cls._PROTOCOL_FEE_MATH_RE.search(source):
            return False
        has_zero_guard = bool(cls._ZERO_RECEIVER_GUARD_RE.search(source))
        has_max_guard = bool(cls._MAX_SHARE_GUARD_RE.search(source))
        return not (has_zero_guard and has_max_guard)

    @classmethod
    def _reason(cls, contract, function) -> str | None:
        contract_source = cls._source(contract)
        source = cls._source(function)
        function_name = cls._function_name(function)
        if cls._raw_reserve_fee_float(contract_source, function_name, source):
            return "raw reserve or self-balance math is used while fee accumulator state exists"
        if cls._missing_fee_accrual(contract, function_name, source):
            return "fee state is changed or charged without first calling the accrual helper"
        if cls._unguarded_protocol_share(function_name, source):
            return "protocol fee share config is returned without both receiver and max-share guards"
        if cls._unguarded_protocol_sink(function_name, source):
            return "protocol fee sink uses configured receiver or share without both receiver and max-share guards"
        return None

    def _detect(self):
        results = []
        for contract in self.contracts:
            if is_vendored_or_test_contract(contract):
                continue
            for function in contract.functions_and_modifiers_declared:
                if not self._INCLUDE_LEAF_HELPERS and is_leaf_helper(function):
                    continue
                if getattr(function, "is_constructor", False):
                    continue
                if not self._is_public_entry(function):
                    continue
                reason = self._reason(contract, function)
                if reason is None:
                    continue
                info = [
                    function,
                    (
                        " - fee-reserve-or-accrual-sink-mismatch: "
                        f"{reason}."
                    ),
                ]
                results.append(self.generate_result(info))
        return results
