"""
reentrancy-nonce-or-callback-accounting-fire18

Fixture-smoke/source-shape detector for reentrancy windows where a callback or
external value transfer occurs before nonce consumption, pending map deletion,
token-id finalization, balance updates, or an equivalent accounting write. Also
covers payable fee splitters that make multiple balance-based ETH calls without
a shared reentrancy guard.

Submission posture: NOT_SUBMIT_READY. Detector hits are candidate evidence
only and require source review before filing.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path as _Path

sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_leaf_helper, is_vendored_or_test_contract

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


_ENTRY_NAME_RE = re.compile(
    r"(?i)^_?(?:consume|claim|redeem|finali[sz]e|settle|execute|complete|"
    r"dispatch|distribute|split|payout|sweep|withdraw|refund|mint|safeMint|"
    r"deposit|borrow|repay|liquidate|fill|match|cancel)[A-Za-z0-9_]*$"
)
_CONTROL_TRANSFER_RE = re.compile(
    r"(?is)(?:"
    r"\b_?safeMint\s*\("
    r"|"
    r"\.\s*(?:on[A-Za-z0-9_]*(?:Received|Callback|Hook|FlashLoan)|"
    r"before[A-Za-z0-9_]*|after[A-Za-z0-9_]*)\s*\("
    r"|"
    r"\bI[A-Za-z0-9_]*(?:Callback|Hook|Receiver|Adapter)[A-Za-z0-9_]*"
    r"\s*\([^;\n]*\)\s*\.\s*[A-Za-z_]\w*\s*\("
    r"|"
    r"\.\s*(?:safeTransferFrom|safeTransfer|transferFrom|transfer|sendValue)\s*\("
    r"|"
    r"\.\s*call\s*(?:\{|\(|\.value\s*\()"
    r"|"
    r"\.\s*(?:transfer|send)\s*\("
    r")"
)
_VALUE_CALL_RE = re.compile(r"(?is)\.\s*call\s*\{\s*value\s*:[^}]*\}\s*\(")
_BALANCE_SOURCE_RE = re.compile(
    r"(?is)\b(?:address\s*\(\s*this\s*\)\s*\.\s*balance|msg\s*\.\s*value)\b"
)
_STATE_WRITE_RE = re.compile(
    r"(?is)\b(?P<name>[A-Za-z_]\w*)"
    r"\s*(?:\[[^\]]+\])?(?:\.[A-Za-z_]\w*)?\s*(?:=|\+=|-=|\+\+|--)"
)
_STATE_DELETE_RE = re.compile(
    r"(?is)\bdelete\s+(?P<name>[A-Za-z_]\w*)\s*(?:\[[^\]]+\])?"
)
_FINALIZATION_NAME_RE = re.compile(
    r"(?i)(nonce|commit|pending|consume|used|claim|claimed|mint|minted|"
    r"token|next|supply|balance|share|debt|owed|paid|settle|settled|"
    r"finali[sz]|status|state|position|account|escrow|withdraw|amount)"
)
_REENTRANCY_GUARD_RE = re.compile(
    r"(?i)\b(?:nonReentrant|ReentrancyGuard|noReentrant|noReentry|"
    r"noReentrancy|reentrancyGuard|reentrancyLock|lockReentrancy|"
    r"reentryGuard)\b"
    r"|"
    r"\b(?:_status|status|locked|_locked|entered|_entered|reentrancyLock)"
    r"\s*=\s*(?:true|2|_ENTERED|ENTERED)"
)
_FALSE_POSITIVE_SOURCE_RE = re.compile(
    r"(?i)\b(?:mock|test|fixture|example|notifyOnly|ping|viewOnly)\b"
)


def _source(obj) -> str:
    try:
        return obj.source_mapping.content or ""
    except Exception:
        return ""


def _source_without_comments_and_strings(source: str) -> str:
    token_re = re.compile(
        r'"(?:[^"\\]|\\.)*"|'
        r"'(?:[^'\\]|\\.)*'|"
        r"//[^\n\r]*|"
        r"/\*.*?\*/",
        re.DOTALL,
    )

    def replace_token(match: re.Match[str]) -> str:
        text = match.group(0)
        return "\n" * text.count("\n") if "\n" in text else " "

    return token_re.sub(replace_token, source or "")


def _state_names(values) -> set[str]:
    names: set[str] = set()
    for value in values or []:
        name = getattr(value, "name", None)
        if name:
            names.add(str(name).lower())
    return names


def _has_reentrancy_guard(function) -> bool:
    for modifier in getattr(function, "modifiers", []) or []:
        if _REENTRANCY_GUARD_RE.search(getattr(modifier, "name", "") or ""):
            return True
    return bool(_REENTRANCY_GUARD_RE.search(_source_without_comments_and_strings(_source(function))))


def _post_control_finalization_writes(function) -> set[str]:
    src = _source_without_comments_and_strings(_source(function))
    control = _CONTROL_TRANSFER_RE.search(src)
    if not control:
        return set()

    slither_written = _state_names(getattr(function, "state_variables_written", []) or [])
    if not slither_written:
        return set()

    post_src = src[control.end():]
    names = {
        match.group("name").lower()
        for match in _STATE_WRITE_RE.finditer(post_src)
        if match.group("name") and _FINALIZATION_NAME_RE.search(match.group("name"))
    }
    names.update(
        match.group("name").lower()
        for match in _STATE_DELETE_RE.finditer(post_src)
        if match.group("name") and _FINALIZATION_NAME_RE.search(match.group("name"))
    )
    return names & slither_written


def _has_balance_based_multi_call_gap(function) -> bool:
    src = _source_without_comments_and_strings(_source(function))
    if not _BALANCE_SOURCE_RE.search(src):
        return False
    if len(_VALUE_CALL_RE.findall(src)) < 2:
        return False
    if getattr(function, "payable", False):
        return True
    return bool(re.search(r"(?i)(dispatch|distribute|split|payout|sweep|fee)", getattr(function, "name", "") or ""))


def _has_control_transfer_before_finalization(function) -> bool:
    if not _CONTROL_TRANSFER_RE.search(_source_without_comments_and_strings(_source(function))):
        return False
    return bool(_post_control_finalization_writes(function))


class ReentrancyNonceOrCallbackAccountingFire18(AbstractDetector):
    ARGUMENT = "reentrancy-nonce-or-callback-accounting-fire18"
    HELP = (
        "Callback or external call occurs before nonce consumption, pending map "
        "deletion, token-id/accounting finalization, balance update, or an "
        "equivalent shared reentrancy guard."
    )
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = (
        "https://github.com/Vuk97/auditooor/blob/main/reports/"
        "detector_lift_fire18_20260605/worker_results/worker_jj_results.md"
    )
    WIKI_TITLE = "Reentrancy window before nonce, callback, or accounting finalization"
    WIKI_DESCRIPTION = (
        "The risky shape is an externally callable mutating function that hands "
        "control to a callback, token receiver, value receiver, or another "
        "contract before consuming a nonce, deleting a pending map entry, "
        "finalizing token-id/accounting state, or protecting the sequence with "
        "a shared reentrancy guard."
    )
    WIKI_EXPLOIT_SCENARIO = (
        "An attacker-controlled receiver reenters while a commitment is still "
        "pending, a token-id counter is stale, or a fee dispatcher is midway "
        "through balance-based value calls. The reentrant path can repeat the "
        "consume, spoof accounting, or take over cross-contract state."
    )
    WIKI_RECOMMENDATION = (
        "Consume nonce and pending state, update token-id and balance "
        "accounting, and finalize settlement before any external control "
        "transfer. Where ordering cannot be changed, apply one shared "
        "reentrancy guard across the entrypoint and every sibling callback path."
    )

    def _detect(self):
        results = []
        for contract in self.contracts:
            if is_vendored_or_test_contract(contract):
                continue

            for function in contract.functions_and_modifiers_declared:
                if getattr(function, "visibility", "") not in {"external", "public"}:
                    continue
                if is_leaf_helper(function):
                    continue
                if not _ENTRY_NAME_RE.search(getattr(function, "name", "") or ""):
                    continue
                if _has_reentrancy_guard(function):
                    continue
                if _FALSE_POSITIVE_SOURCE_RE.search(_source(function)):
                    continue

                if not (
                    _has_control_transfer_before_finalization(function)
                    or _has_balance_based_multi_call_gap(function)
                ):
                    continue

                info = [
                    function,
                    (
                        " - reentrancy-nonce-or-callback-accounting-fire18: "
                        "external control transfer precedes nonce/accounting "
                        "finalization or a balance-based multi-call dispatcher "
                        "lacks a shared reentrancy guard."
                    ),
                ]
                results.append(self.generate_result(info))
        return results
