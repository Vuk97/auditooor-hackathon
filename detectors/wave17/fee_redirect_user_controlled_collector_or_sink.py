"""
fee-redirect-user-controlled-collector-or-sink

Flags public fee-sink setter paths that let any caller replace the stored
collector used by a later protocol-fee payout. This is distinct from the
direct user-controlled sink detector, which catches a payout function that
sends a fee amount directly to msg.sender or a caller-supplied recipient.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path as _Path

sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_leaf_helper, is_vendored_or_test_contract

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class FeeRedirectUserControlledCollectorOrSink(AbstractDetector):
    ARGUMENT = "fee-redirect-user-controlled-collector-or-sink"
    HELP = (
        "Flags unguarded public fee collector or fee sink setters whose stored "
        "sink is later used for fee-like token or ETH payouts."
    )
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.LOW
    WIKI = "https://github.com/Vuk97/auditooor"
    WIKI_TITLE = "Caller-controlled stored fee collector redirects protocol fees"
    WIKI_DESCRIPTION = (
        "Protocol fee sinks should be configured by an authenticated role. If a "
        "public setter writes feeCollector, feeRecipient, feeSink, or treasury "
        "from caller-controlled input, later fee payouts to that stored sink can "
        "be redirected."
    )
    WIKI_EXPLOIT_SCENARIO = (
        "An attacker calls setFeeCollector(attacker). The next collectProtocolFees "
        "call transfers accrued protocol fees to feeCollector, which now points "
        "to the attacker."
    )
    WIKI_RECOMMENDATION = (
        "Restrict fee sink configuration to an authenticated role and keep "
        "fee payouts routed to an immutable or allowlisted protocol sink."
    )

    _SETTER_NAME_RE = re.compile(
        r"(?i)\b(?:set|update|change|configure|replace)"
        r".*(?:feecollector|feerecipient|feereceiver|feesink|treasury|protocoltreasury)"
    )
    _SINK_ASSIGN_RE = re.compile(
        r"\b(?P<sink>feeCollector|feeRecipient|feeReceiver|feeSink|protocolTreasury|treasury)"
        r"\s*=\s*(?P<rhs>[^;]+);",
        re.IGNORECASE,
    )
    _AUTH_GUARD_RE = re.compile(
        r"(?is)(?:onlyOwner|onlyRole|onlyAdmin|onlyGovernor|onlyGovernance|"
        r"onlyKeeper|onlyManager|requiresAuth|AccessControl|_checkRole|"
        r"require\s*\(\s*(?:msg\.sender|_msgSender\s*\(\s*\))\s*==\s*"
        r"(?:owner|admin|governor|governance|keeper|manager)|"
        r"require\s*\(\s*(?:owner|admin|governor|governance|keeper|manager)"
        r"\s*==\s*(?:msg\.sender|_msgSender\s*\(\s*\)))"
    )
    _FEE_VALUE_RE = (
        r"(?:protocolFee|platformFee|serviceFee|treasuryFee|royaltyFee|keeperFee|"
        r"callerFee|accruedFee|pendingFee|feeAmount|fee|fees)"
    )

    _INCLUDE_LEAF_HELPERS = False
    _INVERSE_CEI = False

    @staticmethod
    def _function_source(function) -> str:
        try:
            return function.source_mapping.content or ""
        except Exception:
            return ""

    @staticmethod
    def _contract_source(contract) -> str:
        try:
            return contract.source_mapping.content or ""
        except Exception:
            return ""

    @staticmethod
    def _modifier_names(function) -> list[str]:
        names: list[str] = []
        try:
            for modifier in getattr(function, "modifiers", []) or []:
                name = getattr(modifier, "name", None)
                if name:
                    names.append(str(name))
                elif isinstance(modifier, str):
                    names.append(modifier)
        except Exception:
            pass
        return names

    @staticmethod
    def _address_params(function) -> set[str]:
        params: set[str] = set()
        try:
            for param in getattr(function, "parameters", []) or []:
                name = str(getattr(param, "name", "") or "")
                typ = str(getattr(param, "type", "") or "").lower()
                if name and "address" in typ:
                    params.add(name)
        except Exception:
            pass
        return params

    @staticmethod
    def _state_write_names(function) -> set[str]:
        writes: set[str] = set()
        try:
            for state_var in getattr(function, "state_variables_written", []) or []:
                name = str(getattr(state_var, "name", "") or "")
                if name:
                    writes.add(name.lower())
        except Exception:
            pass
        return writes

    @classmethod
    def _has_auth_guard(cls, function, source: str) -> bool:
        if cls._AUTH_GUARD_RE.search(source):
            return True
        return any(cls._AUTH_GUARD_RE.search(name) for name in cls._modifier_names(function))

    @staticmethod
    def _rhs_is_caller_controlled(rhs: str, params: set[str]) -> bool:
        if re.search(r"(?i)\b(?:msg\.sender|_msgSender\s*\(\s*\))\b", rhs):
            return True
        return any(re.search(rf"\b{re.escape(param)}\b", rhs) for param in params)

    @classmethod
    def _contract_routes_fee_to_sink(cls, contract_source: str, sink: str) -> bool:
        sink_rx = re.escape(sink)
        fee = cls._FEE_VALUE_RE
        patterns = [
            rf"(?is)(?:safeTransfer|transfer|sendValue)\s*\(\s*{sink_rx}\s*,\s*{fee}\b",
            rf"(?is)payable\s*\(\s*{sink_rx}\s*\)\s*\.\s*(?:transfer|send)\s*\(\s*{fee}\b",
            rf"(?is)(?:payable\s*\(\s*{sink_rx}\s*\)|{sink_rx})\s*\.\s*call\s*\{{\s*value\s*:\s*{fee}\b",
        ]
        return any(re.search(pattern, contract_source) for pattern in patterns)

    def _detect(self):
        results = []
        for contract in self.contracts:
            if is_vendored_or_test_contract(contract):
                continue
            contract_source = self._contract_source(contract)
            if not re.search(r"(?i)(feeCollector|feeRecipient|feeReceiver|feeSink|protocolTreasury|treasury)", contract_source):
                continue
            for function in contract.functions_and_modifiers_declared:
                if not self._INCLUDE_LEAF_HELPERS and is_leaf_helper(function):
                    continue
                if getattr(function, "is_constructor", False):
                    continue
                if str(getattr(function, "visibility", "") or "").lower() not in {"external", "public"}:
                    continue
                if not self._SETTER_NAME_RE.search(str(getattr(function, "name", "") or "")):
                    continue

                source = self._function_source(function)
                if self._has_auth_guard(function, source):
                    continue

                params = self._address_params(function)
                if not params and not re.search(r"(?i)\b(?:msg\.sender|_msgSender\s*\(\s*\))\b", source):
                    continue
                state_writes = self._state_write_names(function)

                for match in self._SINK_ASSIGN_RE.finditer(source):
                    sink = match.group("sink")
                    rhs = match.group("rhs")
                    if sink.lower() not in state_writes:
                        continue
                    if not self._rhs_is_caller_controlled(rhs, params):
                        continue
                    if not self._contract_routes_fee_to_sink(contract_source, sink):
                        continue

                    info = [
                        function,
                        (
                            " - fee-redirect-user-controlled-collector-or-sink: "
                            f"unguarded setter writes `{sink}` from caller-controlled "
                            "input and the contract later routes fee-like amounts to "
                            "that stored sink."
                        ),
                    ]
                    results.append(self.generate_result(info))
                    break
        return results
