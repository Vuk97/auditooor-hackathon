"""
fund-loss-arithmetic-fire21

Flags Solidity fund-loss-via-arithmetic recall shapes where computed value is
routed to a caller supplied referral sink, a value-bearing factory path double
registers an asset, or signed int128 value math is cast to uint128 without a
non-negative guard.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path as _Path

sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_leaf_helper, is_vendored_or_test_contract

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


DETECTOR_NAME = "fund-loss-arithmetic-fire21"
DETECTOR_SEVERITY_DEFAULT = "Medium"

_ECONOMIC_ENTRY_RE = re.compile(
    r"(?i)^(?:buy|sell|mint|purchase|swap|trade|deposit|register|claim|"
    r"redeem|withdraw|create|deploy|settle|execute|collect|payout|route)"
)
_VALUE_CONTEXT_RE = re.compile(
    r"(?is)\b(?:fee|fees|referral|referrer|affiliate|rebate|reward|royalty|"
    r"payout|proceeds|claimable|credit|amount|value|share|liquidity|rate|"
    r"price|BPS|bps)\b"
)
_ARITHMETIC_CONTEXT_RE = re.compile(
    r"(?is)\b[A-Za-z_][A-Za-z0-9_]*\s*=\s*[^;]{0,180}(?:\*|/|BPS|bps|rate|price)"
)
_USER_ROUTE_PARAM_RE = re.compile(
    r"(?i)^(?:referral|referrer|affiliate|affiliateReceiver|rebateReceiver|"
    r"rewardRecipient|rewardReceiver|feeReferral|feeRecipient|feeReceiver|"
    r"referralSink|referrerSink|affiliateSink|rewardSink|feeSink|collector|sink)$"
)
_VALUE_NAME_RE = (
    r"(?:referralFee|referrerFee|affiliateFee|rebateFee|rewardFee|feeAmount|"
    r"protocolFee|platformFee|serviceFee|treasuryFee|royaltyFee|keeperFee|"
    r"payout|proceeds|credit|amountOut|valueOut|amount|fee|fees)"
)
_CONFIGURED_ROUTE_GUARD_RE = re.compile(
    r"(?is)(?:onlyOwner|onlyRole|onlyAdmin|onlyGovernor|onlyGovernance|"
    r"approvedReferral|allowedReferral|trustedReferral|referralWhitelist|"
    r"affiliateWhitelist|isReferralApproved|approvedRoute|allowedRoute|"
    r"trustedRoute|configuredRecipient|canonicalRecipient|defaultRecipient|"
    r"configuredSink|canonicalSink|protocolFeeSink|protocolTreasury|"
    r"referralVault|routeRegistry|require\s*\([^;]*(?:approved|allowed|"
    r"trusted|configured|canonical)[^;]*\))"
)
_DUPLICATE_REGISTRATION_GUARD_RE = re.compile(
    r"(?is)(?:require\s*\(\s*!\s*(?:registered|isRegistered|poolRegistered|"
    r"registeredPool)|if\s*\(\s*!\s*(?:registered|isRegistered|poolRegistered|"
    r"registeredPool)|AlreadyRegistered|PoolAlreadyRegistered|Duplicate|"
    r"_ensureNotRegistered|_checkNotRegistered|contains\s*\(|add\s*\()"
)
_VAULT_REGISTRATION_CALL_RE = re.compile(
    r"(?is)(?:_registerPoolWithVault|registerPoolWithVault|vault\s*\.\s*registerPool)"
)
_FACTORY_REGISTRATION_CALL_RE = re.compile(
    r"(?is)(?:_registerPoolWithFactory|registerPoolWithFactory|factory\s*\.\s*registerPool)"
)
_REGISTRATION_WRITE_RE = re.compile(
    r"(?is)\b(?:registered|isRegistered|poolRegistered|registeredPool)\s*"
    r"\[[^\]]+\]\s*=\s*true"
)
_REGISTRATION_CREDIT_RE = re.compile(
    r"(?is)\b(?:claimable|credits|shares|balances|registeredCredit|poolCredits)"
    r"\s*\[[^\]]+\]\s*\+=\s*[^;]*(?:amount|value|fee|share|credit|price|rate|liquidity)"
    r"[^;]*(?:\*|/)"
)
_INT128_DECL_RE = re.compile(r"(?is)\bint128\s+(?P<name>[A-Za-z_][A-Za-z0-9_]*)")
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


def _has_configured_route_guard(function, source: str) -> bool:
    if _CONFIGURED_ROUTE_GUARD_RE.search(source):
        return True
    return any(_CONFIGURED_ROUTE_GUARD_RE.search(name) for name in _modifier_names(function))


def _routes_value_to_param(source: str, param: str) -> bool:
    sink = re.escape(param)
    value = _VALUE_NAME_RE
    patterns = [
        rf"(?is)(?:safeTransfer|transfer|sendValue)\s*\(\s*{sink}\s*,\s*{value}\b",
        rf"(?is)payable\s*\(\s*{sink}\s*\)\s*\.\s*(?:transfer|send)\s*\(\s*{value}\b",
        rf"(?is)(?:payable\s*\(\s*{sink}\s*\)|{sink})\s*\.\s*call\s*\{{\s*value\s*:\s*{value}\b",
    ]
    return any(re.search(pattern, source) for pattern in patterns)


def _caller_supplied_value_route(function, source: str) -> str | None:
    if _visibility(function) not in {"external", "public"}:
        return None
    if not _ECONOMIC_ENTRY_RE.search(_name(function)):
        return None
    if not _VALUE_CONTEXT_RE.search(source):
        return None
    if not _ARITHMETIC_CONTEXT_RE.search(source):
        return None
    if _has_configured_route_guard(function, source):
        return None

    for param in sorted(_address_params(function)):
        if not _USER_ROUTE_PARAM_RE.search(param):
            continue
        if _routes_value_to_param(source, param):
            return f"caller supplied value route `{param}` receives arithmetic value"
    return None


def _duplicate_registration(function, source: str) -> str | None:
    if _visibility(function) not in {"external", "public"}:
        return None
    if not _ECONOMIC_ENTRY_RE.search(_name(function)):
        return None
    if _DUPLICATE_REGISTRATION_GUARD_RE.search(source):
        return None

    if _VAULT_REGISTRATION_CALL_RE.search(source) and _FACTORY_REGISTRATION_CALL_RE.search(source):
        return "factory create path performs both vault and factory registration"

    if _REGISTRATION_WRITE_RE.search(source) and _REGISTRATION_CREDIT_RE.search(source):
        return "registration path grants arithmetic credit without uniqueness guard"

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
        r"(?is)\bSafeCast(?:Overflow)?\b",
        r"(?is)\.\s*toUint128\s*\(",
        r"(?is)\brevert\b",
    ]
    return any(re.search(pattern, source) for pattern in guard_patterns)


def _unsafe_signed_to_unsigned_cast(function, source: str) -> str | None:
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


def _line_for(source: str, offset: int) -> int:
    return source.count("\n", 0, max(offset, 0)) + 1


def _regex_finding(source: str, file_path: str, match: re.Match[str], message: str):
    return {
        "detector": DETECTOR_NAME,
        "severity": DETECTOR_SEVERITY_DEFAULT,
        "file": file_path,
        "line": _line_for(source, match.start()),
        "message": (
            f"{DETECTOR_NAME}: {message}. NOT_SUBMIT_READY: detector "
            "fixture smoke evidence only."
        ),
        "function": None,
    }


def scan(source: str, file_path: str):
    """Regex-runner entrypoint for recall scoreboard integration."""
    text = _strip_comments(source)
    findings = []

    if not _CONFIGURED_ROUTE_GUARD_RE.search(text):
        route_param = (
            r"(?:referral|referrer|affiliate|affiliateReceiver|rebateReceiver|"
            r"rewardRecipient|rewardReceiver|feeReferral|feeRecipient|"
            r"feeReceiver|referralSink|referrerSink|affiliateSink|"
            r"rewardSink|feeSink|collector|sink)"
        )
        route_re = re.compile(
            rf"(?is)\bfunction\s+(?:buy|sell|mint|purchase|swap|trade|deposit|"
            rf"register|claim|redeem|withdraw|create|deploy|settle|execute|"
            rf"collect|payout|route)[A-Za-z0-9_]*\s*\([^)]*address\s+"
            rf"(?P<sink>{route_param})[^)]*\)"
            rf"[^{{;]*\{{(?P<body>[^{{}}]*?(?:\*|/|BPS|bps|rate|price)"
            rf"[^{{}}]*?(?:safeTransfer|transfer|sendValue)\s*\(\s*"
            rf"(?P=sink)\s*,\s*{_VALUE_NAME_RE}\b[^{{}}]*?)\}}"
        )
        for match in route_re.finditer(text):
            findings.append(
                _regex_finding(
                    source,
                    file_path,
                    match,
                    f"caller supplied value route `{match.group('sink')}` receives arithmetic value",
                )
            )

    duplicate_match = None
    if not _DUPLICATE_REGISTRATION_GUARD_RE.search(text):
        if _VAULT_REGISTRATION_CALL_RE.search(text) and _FACTORY_REGISTRATION_CALL_RE.search(text):
            duplicate_match = _VAULT_REGISTRATION_CALL_RE.search(text)
        elif _REGISTRATION_WRITE_RE.search(text) and _REGISTRATION_CREDIT_RE.search(text):
            duplicate_match = _REGISTRATION_CREDIT_RE.search(text)
    if duplicate_match is not None:
        findings.append(
            _regex_finding(
                source,
                file_path,
                duplicate_match,
                "registration path grants arithmetic credit or performs both vault and factory registration without uniqueness guard",
            )
        )

    if not re.search(r"(?is)(SafeCast|safeCast|\.toUint128\s*\(|\b[A-Za-z_][A-Za-z0-9_]*\s*>=\s*0)", text):
        int128_names = {match.group("name") for match in _INT128_DECL_RE.finditer(text)}
        for cast in _UINT128_CAST_RE.finditer(text):
            name = cast.group("name")
            if name in int128_names:
                findings.append(
                    _regex_finding(
                        source,
                        file_path,
                        cast,
                        f"bare uint128 cast of signed int128 `{name}` lacks negativity guard",
                    )
                )
                break

    return findings


class FundLossArithmeticFire21(AbstractDetector):
    ARGUMENT = DETECTOR_NAME
    HELP = (
        "Flags caller supplied referral value routes, duplicate value-bearing "
        "factory registration, and unchecked int128-to-uint128 casts."
    )
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.LOW
    WIKI = "https://github.com/Vuk97/auditooor"
    WIKI_TITLE = "Fund-loss arithmetic via route, registration, or signed cast"
    WIKI_DESCRIPTION = (
        "Arithmetic value must be routed to configured recipients, value-bearing "
        "asset registration must be unique, and signed deltas must reject "
        "negative values before unsigned casts."
    )
    WIKI_EXPLOIT_SCENARIO = (
        "A caller directs a computed referral share to an arbitrary sink, a "
        "factory create path registers the same asset twice, or a negative "
        "int128 delta wraps into a huge uint128 credit."
    )
    WIKI_RECOMMENDATION = (
        "Use configured recipients or allowlists, guard registration uniqueness, "
        "and route signed values through checked cast helpers."
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
                r"(?is)(fee|referral|affiliate|register|pool|vault|claimable|credits|int128|uint128)",
                contract_source,
            ):
                continue

            for function in contract.functions_and_modifiers_declared:
                source = _strip_comments(_source_text(function))
                if not source:
                    continue

                branch = _unsafe_signed_to_unsigned_cast(function, source)
                if branch is None:
                    if is_leaf_helper(function):
                        continue
                    branch = _caller_supplied_value_route(function, source)
                if branch is None:
                    branch = _duplicate_registration(function, source)
                if branch is None:
                    continue

                info = [
                    function,
                    (
                        " - fund-loss-arithmetic-fire21: "
                        f"{branch}. NOT_SUBMIT_READY: detector fixture smoke "
                        "evidence only."
                    ),
                ]
                results.append(self.generate_result(info))
        return results


__all__ = [
    "FundLossArithmeticFire21",
    "DETECTOR_NAME",
    "DETECTOR_SEVERITY_DEFAULT",
    "scan",
]
