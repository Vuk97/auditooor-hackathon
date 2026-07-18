"""
state-check-stale-after-token-or-callback-effect - custom Slither detector.

NOT_SUBMIT_READY: fixture-smoke/source-shape evidence only. Hits require source
review and proof before any filing use.

This is a narrow state-change-between-check-and-use split:
  1. token-effect branch: nominal amountIn is used for value math around a
     token transfer and post-effect balance read without actual-received delta
     derivation;
  2. callback-policy branch: sender, quota, or sponsorship policy is checked,
     an effectful policy callback runs, then the function records spend or
     returns validation success without a post-callback revalidation.

It is intentionally not the Fire6 reentrancy detector. It does not require a
sibling reentry path and a nonReentrant guard is not treated as a full fix for
token delta or post-callback policy staleness.
"""

from __future__ import annotations

import re
import sys as _sys
from pathlib import Path as _Path

_sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_leaf_helper, is_vendored_or_test_contract

from slither.detectors.abstract_detector import (
    AbstractDetector,
    DETECTOR_INFO,
    DetectorClassification,
)
from slither.utils.output import Output


_COMMENT_OR_STRING_RE = re.compile(
    r'"(?:[^"\\]|\\.)*"|'
    r"'(?:[^'\\]|\\.)*'|"
    r"//[^\n\r]*|"
    r"/\*.*?\*/",
    re.DOTALL,
)

_TOKEN_AMOUNT_RE = re.compile(r"(?i)\bamount[01]?In\b")
_TOKEN_TRANSFER_RE = re.compile(
    r"(?i)\b(?:safeTransferFrom|transferFrom|safeTransfer|transfer)\s*\("
)
_SELF_BALANCE_RE = re.compile(
    r"(?i)\bbalanceOf\s*\(\s*address\s*\(\s*this\s*\)\s*\)"
)
_NOMINAL_VALUE_USE_RE = re.compile(
    r"(?is)"
    r"(?:"
    r"\b(?:quotedOut|amount[01]?Out[A-Za-z0-9_]*|amountOut[A-Za-z0-9_]*)\b\s*=\s*[^;]*\bamount[01]?In\b|"
    r"\bamount[01]?In\b\s*[*\/]\s*[^;]*(?:reserve|balance)|"
    r"\bamount[01]?In\b\s*[+\-]\s*[^;]*(?:reserve|balance)|"
    r"\breserve[01]?\b\s*=\s*[^;]*\bnewBal[01]?\b"
    r")"
)
_TOKEN_CHECK_RE = re.compile(
    r"(?is)\b(?:require|if)\s*\([^;]*(?:amount[01]?In|reserve[01]?|balance)[^;]*\)"
)
_TOKEN_FRESH_RE = re.compile(
    r"(?is)"
    r"(?:"
    r"\b(?:actualReceived|receivedDelta|deltaIn|balanceDelta|supportingFeeOnTransfer|feeOnTransfer)\b|"
    r"\bamount[01]?In\b\s*=\s*[^;]*(?:balance|newBal)[A-Za-z0-9_]*\s*-|"
    r"\b(?:received|credited)\b\s*=\s*[^;]*(?:balance|newBal)[A-Za-z0-9_]*\s*-|"
    r"\bbalanceAfter\b"
    r")"
)

_PAYMASTER_NAME_RE = re.compile(r"(?i)\b_?validatePaymasterUserOp\b")
_POLICY_CHECK_RE = re.compile(
    r"(?is)"
    r"\b(?:require|if)\s*\([^;]*"
    r"(?:userOp\.sender|sender|allowedSenders|approvedSenders|sponsored|quota|budget|policy)"
    r"[^;]*\)"
)
_POLICY_CALLBACK_RE = re.compile(
    r"(?is)"
    r"(?:"
    r"\b(?:policy|sponsorPolicy|validator|callback|hook|quotaManager)\s*\."
    r"(?:before|validate|consume|charge|on|check)[A-Za-z0-9_]*\s*\(|"
    r"\bI[A-Za-z0-9_]*(?:Policy|Validator|Callback|Hook|Quota)[A-Za-z0-9_]*"
    r"\s*\([^)]*\)\s*\.[A-Za-z_][A-Za-z0-9_]*\s*\("
    r")"
)
_POLICY_STALE_USE_RE = re.compile(
    r"(?is)"
    r"(?:"
    r"\breturn\s*\([^;]*(?:SIG_VALIDATION_SUCCESS|validationData)|"
    r"\b(?:spent|used|quota|budget|sponsored)\s*\[[^;\]]*(?:userOp\.sender|sender)[^;\]]*\]\s*(?:=|\+=|-=|\+\+|--)|"
    r"\bvalidationData\b"
    r")"
)
_POLICY_FRESH_RE = re.compile(
    r"(?is)"
    r"(?:"
    r"\b(?:quotaAfter|policyAfter|senderAfter|sponsoredAfter|freshPolicy|freshQuota|postEffect|revalidated|validateAfter)\b|"
    r"\brequire\s*\([^;]*(?:quotaAfter|policyAfter|senderAfter|sponsoredAfter|freshPolicy|freshQuota|postEffect|revalidated|validateAfter)[^;]*\)"
    r")"
)


def _source(obj) -> str:
    try:
        return str(getattr(obj.source_mapping, "content", "") or "")
    except Exception:
        return ""


def _source_without_comments_and_strings(source: str) -> str:
    def replace(match: re.Match[str]) -> str:
        text = match.group(0)
        return "\n" * text.count("\n") if "\n" in text else " "

    return _COMMENT_OR_STRING_RE.sub(replace, source or "")


def _first_pos(regex: re.Pattern[str], source: str) -> int:
    match = regex.search(source)
    return match.start() if match else -1


def _has_after(regex: re.Pattern[str], source: str, pos: int) -> bool:
    if pos < 0:
        return False
    return regex.search(source, pos) is not None


def _is_external_public(function) -> bool:
    return getattr(function, "visibility", "") in {"external", "public"}


def _has_effect_or_state(function) -> bool:
    if list(getattr(function, "state_variables_written", []) or []):
        return True
    if list(getattr(function, "high_level_calls", []) or []):
        return True
    if list(getattr(function, "low_level_calls", []) or []):
        return True
    return False


def _token_effect_stales_checked_amount(source: str) -> bool:
    if not _TOKEN_AMOUNT_RE.search(source):
        return False
    if not _TOKEN_TRANSFER_RE.search(source):
        return False
    if not _SELF_BALANCE_RE.search(source):
        return False
    if not _NOMINAL_VALUE_USE_RE.search(source):
        return False
    if _TOKEN_FRESH_RE.search(source):
        return False

    check_pos = _first_pos(_TOKEN_CHECK_RE, source)
    stale_use_pos = _first_pos(_NOMINAL_VALUE_USE_RE, source)
    transfer_pos = _first_pos(_TOKEN_TRANSFER_RE, source)
    balance_pos = _first_pos(_SELF_BALANCE_RE, source)

    if check_pos >= 0 and stale_use_pos > check_pos and transfer_pos >= 0 and balance_pos >= 0:
        return True
    if transfer_pos >= 0 and stale_use_pos > transfer_pos and _has_after(_SELF_BALANCE_RE, source, stale_use_pos):
        return True
    if stale_use_pos >= 0 and transfer_pos > stale_use_pos and _has_after(_SELF_BALANCE_RE, source, transfer_pos):
        return True
    return False


def _callback_effect_stales_policy_check(source: str, function_name: str) -> bool:
    if not (_PAYMASTER_NAME_RE.search(function_name) or "UserOperation" in source or "PackedUserOperation" in source):
        return False
    if _POLICY_FRESH_RE.search(source):
        return False

    check_pos = _first_pos(_POLICY_CHECK_RE, source)
    callback_pos = _first_pos(_POLICY_CALLBACK_RE, source)
    return check_pos >= 0 and callback_pos > check_pos and _has_after(
        _POLICY_STALE_USE_RE,
        source,
        callback_pos,
    )


class StateCheckStaleAfterTokenOrCallbackEffect(AbstractDetector):
    ARGUMENT = "state-check-stale-after-token-or-callback-effect"
    HELP = (
        "Checked token amount or sender policy is used after a token or "
        "callback effect without deriving a fresh delta or revalidating policy."
    )
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.LOW
    WIKI = (
        "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/"
        "state-check-stale-after-token-or-callback-effect.yaml"
    )
    WIKI_TITLE = "State check stale after token or callback effect"
    WIKI_DESCRIPTION = (
        "The detector reports two source-shape branches: nominal token amount "
        "pricing around a token transfer and post-effect balance read without "
        "actual received delta derivation, and paymaster-like policy checks "
        "that cross an effectful callback before success or spend accounting "
        "without post-callback revalidation."
    )
    WIKI_EXPLOIT_SCENARIO = (
        "A fee-on-transfer token credits less than amountIn, but the pool "
        "prices output from amountIn. Or a paymaster checks sender quota, "
        "calls a policy hook that can revoke or consume quota, then still "
        "returns validation success from the stale pre-hook policy result."
    )
    WIKI_RECOMMENDATION = (
        "Use actual received token deltas for value math, and revalidate "
        "sender policy or quota after any effectful callback before returning "
        "success or recording spend."
    )

    def _detect(self) -> list[Output]:
        results: list[Output] = []

        for contract in self.contracts:
            if is_vendored_or_test_contract(contract):
                continue

            for function in contract.functions_and_modifiers_declared:
                if getattr(function, "is_constructor", False):
                    continue
                if not _is_external_public(function):
                    continue
                if getattr(function, "view", False) or getattr(function, "pure", False):
                    continue
                if is_leaf_helper(function):
                    continue
                if not _has_effect_or_state(function):
                    continue

                source = _source_without_comments_and_strings(_source(function))
                function_name = str(getattr(function, "name", "") or "")

                branch = ""
                if _token_effect_stales_checked_amount(source):
                    branch = "token-effect stale amount use"
                elif _callback_effect_stales_policy_check(source, function_name):
                    branch = "callback-effect stale policy use"
                if not branch:
                    continue

                info: DETECTOR_INFO = [
                    function,
                    " crosses a ",
                    branch,
                    " boundary without deriving or revalidating fresh state.\n",
                ]
                results.append(self.generate_result(info))

        return results
