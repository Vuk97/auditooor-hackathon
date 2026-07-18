"""
fund-loss-arithmetic-fee-or-registration-fire19

Flags Solidity fund-loss arithmetic recall shapes where value is redirected
through caller-controlled fee sinks, duplicate registration, repeat claimable
credit, or unchecked signed-to-unsigned int128 casts.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path as _Path

sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_leaf_helper, is_vendored_or_test_contract

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


_ECONOMIC_ENTRY_RE = re.compile(
    r"(?i)^(?:buy|sell|mint|purchase|swap|trade|deposit|register|claim|"
    r"redeem|withdraw|create|deploy|settle|execute|collect|payout)"
)
_FEE_CONTEXT_RE = re.compile(
    r"(?is)\b(?:fee|fees|protocolFee|platformFee|serviceFee|treasuryFee|"
    r"referralFee|referrerFee|affiliateFee|rebateFee|royaltyFee|BPS|bps|"
    r"feeRate|feeBps)\b"
)
_USER_SINK_PARAM_RE = re.compile(
    r"(?i)^(?:referral|referrer|affiliate|affiliateReceiver|rebateReceiver|"
    r"rewardRecipient|rewardReceiver|feeReferral|feeRecipient|feeReceiver|"
    r"referralSink|referrerSink|affiliateSink|rewardSink|feeSink|collector|"
    r"recipient|receiver|beneficiary|sink|to)$"
)
_FEE_VALUE_RE = (
    r"(?:referralFee|referrerFee|affiliateFee|rebateFee|rewardFee|"
    r"protocolFee|platformFee|serviceFee|treasuryFee|royaltyFee|keeperFee|"
    r"feeAmount|fee|fees)"
)
_AUTH_OR_CONFIG_GUARD_RE = re.compile(
    r"(?is)(?:onlyOwner|onlyRole|onlyAdmin|onlyGovernor|onlyGovernance|"
    r"requiresAuth|AccessControl|_checkRole|approvedReferral|allowedReferral|"
    r"trustedReferral|referralWhitelist|affiliateWhitelist|isReferralApproved|"
    r"MAX_REFERRAL|MAX_AFFILIATE|MAX_REBATE|referralVault|referralTreasury|"
    r"configuredReferral|protocolReferral|defaultReferral|configuredFeeRecipient|"
    r"configuredFeeSink|protocolFeeSink|protocolTreasury)"
)
_DUP_REG_GUARD_RE = re.compile(
    r"(?is)(?:require\s*\(\s*!\s*(?:registered|isRegistered|poolRegistered|"
    r"registeredPool)|if\s*\(\s*!\s*(?:registered|isRegistered|poolRegistered|"
    r"registeredPool)|AlreadyRegistered|PoolAlreadyRegistered|Duplicate|"
    r"_ensureNotRegistered|_checkNotRegistered|contains\s*\(|add\s*\()"
)
_REGISTRATION_CALL_RE = re.compile(
    r"(?is)(?:_registerPoolWithVault|registerPoolWithVault|vault\s*\.\s*registerPool)"
)
_FACTORY_REGISTRATION_CALL_RE = re.compile(
    r"(?is)(?:_registerPoolWithFactory|registerPoolWithFactory|factory\s*\.\s*registerPool)"
)
_REGISTRATION_CREDIT_RE = re.compile(
    r"(?is)\b(?:claimable|credits|shares|balances|registeredCredit|poolCredits)"
    r"\s*\[[^\]]+\]\s*\+=\s*[^;]*(?:amount|value|fee|share|credit|price|rate)"
    r"[^;]*(?:\*|/)"
)
_REGISTRATION_WRITE_RE = re.compile(
    r"(?is)\b(?:registered|isRegistered|poolRegistered|registeredPool)\s*"
    r"\[[^\]]+\]\s*=\s*true"
)
_INT128_DECL_RE = re.compile(
    r"(?is)\bint128\s+(?P<name>[A-Za-z_][A-Za-z0-9_]*)"
)
_UINT128_CAST_RE = re.compile(
    r"(?is)\buint128\s*\(\s*(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*\)"
)


def _source_text(obj) -> str:
    try:
        return obj.source_mapping.content or ""
    except Exception:
        return ""


def _strip_comments(source: str) -> str:
    text = re.sub(r"/\*.*?\*/", "", source, flags=re.DOTALL)
    return re.sub(r"//[^\n\r]*", "", text)


def _visibility(function) -> str:
    return str(getattr(function, "visibility", "") or "").lower()


def _name(function) -> str:
    return str(getattr(function, "name", "") or "")


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


def _has_auth_or_config_guard(function, source: str) -> bool:
    if _AUTH_OR_CONFIG_GUARD_RE.search(source):
        return True
    return any(_AUTH_OR_CONFIG_GUARD_RE.search(name) for name in _modifier_names(function))


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


def _routes_fee_to_user_sink(source: str, param: str) -> bool:
    sink = re.escape(param)
    fee = _FEE_VALUE_RE
    patterns = [
        rf"(?is)(?:safeTransfer|transfer|sendValue)\s*\(\s*{sink}\s*,\s*{fee}\b",
        rf"(?is)payable\s*\(\s*{sink}\s*\)\s*\.\s*(?:transfer|send)\s*\(\s*{fee}\b",
        rf"(?is)(?:payable\s*\(\s*{sink}\s*\)|{sink})\s*\.\s*call\s*\{{\s*value\s*:\s*{fee}\b",
    ]
    return any(re.search(pattern, source) for pattern in patterns)


def _fee_sink_branch(function, source: str) -> str | None:
    if _visibility(function) not in {"external", "public"}:
        return None
    if not _ECONOMIC_ENTRY_RE.search(_name(function)):
        return None
    if not _FEE_CONTEXT_RE.search(source):
        return None
    if _has_auth_or_config_guard(function, source):
        return None

    for param in sorted(_address_params(function)):
        if not _USER_SINK_PARAM_RE.search(param):
            continue
        if _routes_fee_to_user_sink(source, param):
            return f"caller-controlled fee sink `{param}` receives fee-derived value"
    return None


def _duplicate_registration_branch(function, source: str) -> str | None:
    if _visibility(function) not in {"external", "public"}:
        return None
    if not _ECONOMIC_ENTRY_RE.search(_name(function)):
        return None
    if _DUP_REG_GUARD_RE.search(source):
        return None

    if _REGISTRATION_CALL_RE.search(source) and _FACTORY_REGISTRATION_CALL_RE.search(source):
        return "create path calls both vault registration and factory registration"

    if _REGISTRATION_WRITE_RE.search(source) and _REGISTRATION_CREDIT_RE.search(source):
        return "registration path grants arithmetic claimable credit without uniqueness guard"

    return None


def _int128_names(function, source: str) -> set[str]:
    names: set[str] = {match.group("name") for match in _INT128_DECL_RE.finditer(source)}
    try:
        for param in getattr(function, "parameters", []) or []:
            name = str(getattr(param, "name", "") or "")
            typ = str(getattr(param, "type", "") or "")
            if name and re.search(r"\bint128\b", typ):
                names.add(name)
    except Exception:
        pass
    return names


def _has_signed_cast_guard(source: str, name: str) -> bool:
    var = re.escape(name)
    guard_patterns = [
        rf"(?is)\b{var}\s*>=\s*0",
        rf"(?is)0\s*<=\s*{var}\b",
        rf"(?is)\b{var}\s*<\s*0",
        rf"(?is)0\s*>\s*{var}\b",
        r"(?is)\b(?:SafeCast|toUint128|SafeCastOverflow)\b",
        r"(?is)\brevert\b",
    ]
    return any(re.search(pattern, source) for pattern in guard_patterns)


def _unchecked_int128_cast_branch(function, source: str) -> str | None:
    int128_names = _int128_names(function, source)
    if not int128_names:
        return None
    for match in _UINT128_CAST_RE.finditer(source):
        name = match.group("name")
        if name not in int128_names:
            continue
        if _has_signed_cast_guard(source, name):
            continue
        return f"bare uint128 cast of signed int128 `{name}` lacks negativity guard"
    return None


class FundLossArithmeticFeeOrRegistrationFire19(AbstractDetector):
    ARGUMENT = "fund-loss-arithmetic-fee-or-registration-fire19"
    HELP = (
        "Flags fee sink redirection, duplicate registration, repeat arithmetic "
        "credit, and unchecked int128-to-uint128 casts that can redirect value "
        "or overstate claimable balances."
    )
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.LOW
    WIKI = "https://github.com/Vuk97/auditooor"
    WIKI_TITLE = "Fund-loss arithmetic via fee sink or registration accounting"
    WIKI_DESCRIPTION = (
        "Arithmetic-derived fee, registration, and signed-delta accounting must "
        "bind value recipients, enforce registration uniqueness, and guard "
        "signed-to-unsigned casts. Missing one of those controls can redirect "
        "fees, create double credit, or wrap negative deltas into huge unsigned "
        "credits."
    )
    WIKI_EXPLOIT_SCENARIO = (
        "A caller self-selects the referral sink for a protocol-fee share, "
        "registers the same pool twice for duplicate credit, or feeds a "
        "negative int128 delta into a bare uint128 cast that becomes a huge "
        "claimable amount."
    )
    WIKI_RECOMMENDATION = (
        "Use configured or allowlisted sinks, guard registration with explicit "
        "uniqueness checks, and route signed deltas through checked cast helpers."
    )

    SUBMISSION_POSTURE = "NOT_SUBMIT_READY"
    COVERAGE_CLAIM = "detector_fixture_smoke_only"
    PROMOTION_ALLOWED = False

    def _detect(self):
        results = []
        for contract in self.contracts:
            if is_vendored_or_test_contract(contract):
                continue
            contract_source = _strip_comments(_source_text(contract))
            if not re.search(
                r"(?is)(fee|referral|register|pool|vault|claimable|credits|int128|uint128)",
                contract_source,
            ):
                continue

            for function in contract.functions_and_modifiers_declared:
                source = _strip_comments(_source_text(function))
                if not source:
                    continue

                branch = _unchecked_int128_cast_branch(function, source)
                if branch is None:
                    if is_leaf_helper(function):
                        continue
                    branch = _fee_sink_branch(function, source)
                if branch is None:
                    branch = _duplicate_registration_branch(function, source)
                if branch is None:
                    continue

                info = [
                    function,
                    (
                        " - fund-loss-arithmetic-fee-or-registration-fire19: "
                        f"{branch}. NOT_SUBMIT_READY: detector fixture smoke "
                        "evidence only."
                    ),
                ]
                results.append(self.generate_result(info))
        return results
