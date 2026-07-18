"""
access-control-third-party-debt-mutation-missing-delegation - custom Slither detector.

Focused W6-8 recall lift for access-control misses around borrow-on-behalf
variants: the caller supplies a third-party borrower/account, debt is increased
for that account, and assets are delivered to msg.sender without a self-borrow
or delegation check.
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


_ACCOUNT_PARAM_RE = re.compile(
    r"^(borrower|onBehalfOf|account|debtor|customer|beneficiary|user)$",
    re.IGNORECASE,
)
_ENTRY_NAME_RE = re.compile(r"(borrow|draw|credit|loan|debt|leverage|advance)", re.IGNORECASE)
_DEBT_STATE_RE = re.compile(
    r"(borrow|debt|loan|credit|principal|liabilit|accountBorrows|borrowBalance)",
    re.IGNORECASE,
)
_ASSET_TO_CALLER_RE = re.compile(
    r"(?:transfer|safeTransfer|mint)\s*\(\s*(?:msg\.sender|_msgSender\(\))\s*,\s*"
    r"(?:amount|assets|principal|borrowAmount|creditAmount)\b",
    re.IGNORECASE | re.DOTALL,
)
_AUTH_HELPER_RE = re.compile(
    r"(borrowAllowance|borrowApproved|isApprovedForBorrow|isAuthorized|delegatedBorrow|"
    r"creditDelegation|borrowDelegation|approvedBorrower|hasBorrowPermission|permitBorrow|"
    r"borrowerAllowance|creditAllowance)\s*(?:\[|\()",
    re.IGNORECASE | re.DOTALL,
)
_GUARD_MODIFIER_RE = re.compile(
    r"(onlyOwner|onlyRole|onlyAdmin|onlyManager|onlyKeeper|onlyOperator|requiresAuth|auth)",
    re.IGNORECASE,
)


def _source(obj) -> str:
    try:
        return obj.source_mapping.content or ""
    except Exception:
        return ""


def _is_external_entry(function) -> bool:
    return (
        getattr(function, "visibility", None) in {"public", "external"}
        and not getattr(function, "is_constructor", False)
        and not getattr(function, "is_receive", False)
        and not getattr(function, "is_fallback", False)
        and not getattr(function, "view", False)
        and not getattr(function, "pure", False)
    )


def _account_params(function) -> list[str]:
    out: list[str] = []
    for param in getattr(function, "parameters", []) or []:
        name = getattr(param, "name", "") or ""
        typ = str(getattr(param, "type", "") or "")
        if "address" in typ and _ACCOUNT_PARAM_RE.search(name):
            out.append(name)
    return out


def _writes_debt_state(function) -> bool:
    for state_var in getattr(function, "state_variables_written", []) or []:
        if _DEBT_STATE_RE.search(getattr(state_var, "name", "") or ""):
            return True
    return False


def _debt_write_keyed_by_param(src: str, param: str) -> bool:
    param_rx = re.escape(param)
    return bool(
        re.search(
            rf"(?:borrow|debt|loan|credit|principal|liabilit|accountBorrows|borrowBalance)\w*"
            rf"\s*\[[^\]]*\b{param_rx}\b[^\]]*\]\s*(?:\+=|=\s*[^;]*\+)",
            src,
            re.IGNORECASE | re.DOTALL,
        )
    )


def _has_self_or_delegation_guard(function, src: str, param: str) -> bool:
    param_rx = re.escape(param)
    if re.search(
        rf"(?:msg\.sender|_msgSender\(\))\s*==\s*\b{param_rx}\b|\b{param_rx}\b\s*==\s*"
        rf"(?:msg\.sender|_msgSender\(\))",
        src,
        re.IGNORECASE | re.DOTALL,
    ):
        return True
    if _AUTH_HELPER_RE.search(src):
        return True
    if re.search(
        rf"(?:allowance|_allowances)\s*(?:\[|\()\s*\b{param_rx}\b[^\]\)]*(?:msg\.sender|_msgSender\(\))",
        src,
        re.IGNORECASE | re.DOTALL,
    ):
        return True
    for modifier in getattr(function, "modifiers", []) or []:
        if _GUARD_MODIFIER_RE.search(getattr(modifier, "name", "") or ""):
            return True
    return False


class AccessControlThirdPartyDebtMutationMissingDelegation(AbstractDetector):
    ARGUMENT = "access-control-third-party-debt-mutation-missing-delegation"
    HELP = (
        "Third-party borrower/account parameter has debt increased while borrowed "
        "assets are sent to msg.sender, without borrower consent or delegation"
    )
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM

    WIKI = (
        "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/"
        "access-control-third-party-debt-mutation-missing-delegation.yaml"
    )
    WIKI_TITLE = "Third-party debt mutation without borrower delegation"
    WIKI_DESCRIPTION = (
        "A lending entry point accepts a borrower/account parameter, writes debt "
        "against that account, and transfers the borrowed asset to the caller. "
        "Without a self-borrow check or explicit borrow-delegation allowance, "
        "any caller can open debt against someone else."
    )
    WIKI_EXPLOIT_SCENARIO = (
        "The caller invokes drawCreditFor(victim, amount); debtOf[victim] "
        "increases while asset.transfer(msg.sender, amount) pays the caller."
    )
    WIKI_RECOMMENDATION = (
        "Require msg.sender == borrower for self-borrow flows, or enforce and "
        "decrement a borrow-delegation allowance keyed by borrower and caller."
    )

    def _detect(self) -> list[Output]:
        results: list[Output] = []

        for contract in self.contracts:
            if is_vendored_or_test_contract(contract):
                continue
            if not _DEBT_STATE_RE.search(_source(contract)):
                continue

            for function in contract.functions_and_modifiers_declared:
                if not _is_external_entry(function):
                    continue
                if is_leaf_helper(function):
                    continue
                if not _ENTRY_NAME_RE.search(getattr(function, "name", "") or ""):
                    continue
                if not _writes_debt_state(function):
                    continue

                src = _source(function)
                if not _ASSET_TO_CALLER_RE.search(src):
                    continue

                for param in _account_params(function):
                    if not _debt_write_keyed_by_param(src, param):
                        continue
                    if _has_self_or_delegation_guard(function, src, param):
                        continue

                    info: DETECTOR_INFO = [
                        function,
                        " increases debt keyed by caller-supplied account parameter `",
                        param,
                        "` and transfers assets to msg.sender without a borrower/delegation guard in ",
                        contract,
                        ".\n",
                    ]
                    results.append(self.generate_result(info))
                    break

        return results
