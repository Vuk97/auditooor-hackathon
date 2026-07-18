"""
fee-redirect-caller-supplied-referral-sink

Flags public economic entrypoints that split a protocol fee and route a
referral, affiliate, or rebate fee directly to a caller supplied address
without an allowlist, cap, or protocol-owned fallback sink.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path as _Path

sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_leaf_helper, is_vendored_or_test_contract

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


_ECONOMIC_ENTRY_RE = re.compile(
    r"(?i)^(?:buy|sell|mint|purchase|checkout|swap|trade|deposit|subscribe|"
    r"create|settle|execute|claim|redeem|open|close)"
)
_REFERRAL_PARAM_RE = re.compile(
    r"(?i)^(?:referral|referrer|affiliate|affiliateReceiver|rebateReceiver|"
    r"rewardRecipient|rewardReceiver|feeReferral)$"
)
_FEE_VALUE_RE = (
    r"(?:referralFee|referrerFee|affiliateFee|rebateFee|rewardFee|"
    r"protocolFee|platformFee|serviceFee|treasuryFee|royaltyFee|feeAmount|fee)"
)
_FEE_CONTEXT_RE = re.compile(
    r"(?is)\b(?:protocolFee|platformFee|serviceFee|treasuryFee|royaltyFee|"
    r"referralFee|referrerFee|affiliateFee|rebateFee|BPS|feeBps|feeRate)\b"
)
_AUTH_OR_CONFIG_GUARD_RE = re.compile(
    r"(?is)(?:onlyOwner|onlyRole|onlyAdmin|onlyGovernor|onlyGovernance|"
    r"requiresAuth|AccessControl|_checkRole|"
    r"approvedReferral|allowedReferral|trustedReferral|referralWhitelist|"
    r"referrerWhitelist|affiliateWhitelist|isReferralApproved|"
    r"MAX_REFERRAL|MAX_AFFILIATE|MAX_REBATE|referralVault|referralTreasury|"
    r"configuredReferral|protocolReferral|defaultReferral)"
)


def _source_text(obj) -> str:
    try:
        return obj.source_mapping.content or ""
    except Exception:
        return ""


def _visibility(function) -> str:
    return str(getattr(function, "visibility", "") or "").lower()


def _name(function) -> str:
    return str(getattr(function, "name", "") or "")


def _address_referral_params(function) -> set[str]:
    params: set[str] = set()
    try:
        for param in getattr(function, "parameters", []) or []:
            name = str(getattr(param, "name", "") or "")
            typ = str(getattr(param, "type", "") or "").lower()
            if name and "address" in typ and _REFERRAL_PARAM_RE.search(name):
                params.add(name)
    except Exception:
        pass
    return params


def _routes_fee_to_param(source: str, param: str) -> bool:
    sink = re.escape(param)
    fee = _FEE_VALUE_RE
    patterns = [
        rf"(?is)(?:safeTransfer|transfer|sendValue)\s*\(\s*{sink}\s*,\s*{fee}\b",
        rf"(?is)payable\s*\(\s*{sink}\s*\)\s*\.\s*(?:transfer|send)\s*\(\s*{fee}\b",
        rf"(?is)(?:payable\s*\(\s*{sink}\s*\)|{sink})\s*\.\s*call\s*\{{\s*value\s*:\s*{fee}\b",
    ]
    return any(re.search(pattern, source) for pattern in patterns)


class FeeRedirectCallerSuppliedReferralSink(AbstractDetector):
    ARGUMENT = "fee-redirect-caller-supplied-referral-sink"
    HELP = (
        "Flags public fee-splitting paths that pay protocol-derived referral "
        "or affiliate fees to caller supplied addresses without configured-sink "
        "or bounded-referral guards."
    )
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.LOW
    WIKI = (
        "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/"
        "fee-redirect-caller-supplied-referral-sink.yaml"
    )
    WIKI_TITLE = "Caller supplied referral sink redirects protocol fee share"
    WIKI_DESCRIPTION = (
        "Referral and affiliate fee shares are still protocol fee accounting. "
        "If an economic entrypoint accepts an arbitrary referral address and "
        "transfers protocol-derived fee value to it without a cap or allowlist, "
        "the caller can self-refer and redirect protocol revenue."
    )
    WIKI_EXPLOIT_SCENARIO = (
        "A buy path computes protocolFee and referralFee from the payment amount. "
        "The attacker passes their own address as referral, so the contract pays "
        "part of protocolFee back to the attacker instead of routing it to a "
        "configured treasury or approved partner sink."
    )
    WIKI_RECOMMENDATION = (
        "Route protocol fee shares to configured sinks, or require referral "
        "addresses to be approved and cap the referral share before paying it."
    )

    SUBMISSION_POSTURE = "NOT_SUBMIT_READY"
    COVERAGE_CLAIM = "detector_fixture_smoke_only"
    PROMOTION_ALLOWED = False

    def _detect(self):
        results = []
        for contract in self.contracts:
            if is_vendored_or_test_contract(contract):
                continue

            contract_source = _source_text(contract)
            if not _FEE_CONTEXT_RE.search(contract_source):
                continue

            for function in contract.functions_and_modifiers_declared:
                if is_leaf_helper(function):
                    continue
                if getattr(function, "is_constructor", False):
                    continue
                if _visibility(function) not in {"external", "public"}:
                    continue
                if not _ECONOMIC_ENTRY_RE.search(_name(function)):
                    continue

                source = _source_text(function)
                if not source or not _FEE_CONTEXT_RE.search(source):
                    continue
                if _AUTH_OR_CONFIG_GUARD_RE.search(source):
                    continue

                referral_params = _address_referral_params(function)
                if not referral_params:
                    continue

                routed_param = next(
                    (param for param in sorted(referral_params) if _routes_fee_to_param(source, param)),
                    None,
                )
                if routed_param is None:
                    continue

                info = [
                    function,
                    (
                        " - fee-redirect-caller-supplied-referral-sink: "
                        f"protocol-derived fee value is paid to caller supplied "
                        f"`{routed_param}` without an allowlist, cap, or "
                        "configured fallback sink. NOT_SUBMIT_READY: "
                        "fixture-smoke/source-shape proof only."
                    ),
                ]
                results.append(self.generate_result(info))
        return results
