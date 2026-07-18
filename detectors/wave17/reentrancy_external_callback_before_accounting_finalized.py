"""
reentrancy-external-callback-before-accounting-finalized

Fixture-smoke/source-shape detector for external callbacks or cross-contract
calls that occur before debt, balance, settlement, or finalized-state writes.
The detector requires a sibling exit or settlement path that reads the same
state, so ordinary external calls are not enough to produce a hit.

Submission posture: NOT_SUBMIT_READY. This is capability work backed by local
fixtures only.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path as _Path

sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_leaf_helper, is_vendored_or_test_contract

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


_ENTRY_NAME_RE = re.compile(
    r"(?i)^_?(?:deposit|withdraw|redeem|borrow|repay|liquidate|preLiquidate|"
    r"settle|fill|match|execute|buy|purchase|claim|cancel|mint|burn|refund|"
    r"request|queue|exit|close|complete|finali[sz]e)[A-Za-z0-9_]*$"
)
_EXIT_OR_SETTLEMENT_NAME_RE = re.compile(
    r"(?i)^_?(?:exit|settle|withdraw|redeem|claim|close|complete|finali[sz]e|"
    r"cancel|liquidate)[A-Za-z0-9_]*$"
)
_CALLBACK_OR_EXTERNAL_CALL_RE = re.compile(
    r"(?is)(?:"
    r"\bI[A-Za-z0-9_]*(?:Callback|Hook|Receiver|Adapter)[A-Za-z0-9_]*"
    r"\s*\([^;\n]*\)"
    r"\s*\.\s*[A-Za-z_]\w*\s*\("
    r"|"
    r"\.\s*on[A-Za-z0-9_]*(?:Received|Callback|Liquidate|Repay|Settle|Exit|FlashLoan)"
    r"\s*\("
    r"|"
    r"\b[A-Za-z_]\w*\s*\.\s*(?:safeTransferFrom|safeTransfer|transferFrom|transfer|sendValue)"
    r"\s*\("
    r"|"
    r"\.\s*call\s*(?:\{|\(|\.value\s*\()"
    r"|"
    r"\.\s*(?:transfer|send)\s*\("
    r")"
)
_ACCOUNTING_WRITE_RE = re.compile(
    r"(?is)\b(?P<name>[A-Za-z_]\w*)"
    r"\s*(?:\[[^\]]+\])?(?:\.[A-Za-z_]\w*)?\s*(?:=|\+=|-=|\+\+|--)"
)
_DELETE_ACCOUNTING_RE = re.compile(
    r"(?is)\bdelete\s+(?P<name>[A-Za-z_]\w*)\s*(?:\[[^\]]+\])?"
)
_ACCOUNTING_NAME_RE = re.compile(
    r"(?i)(debt|borrow|balanc|share|finali[sz]|settled|status|state|position|"
    r"collateral|remaining|owed|paid|claim|reward|exit|supply|accounting)"
)
_REENTRANCY_GUARD_RE = re.compile(
    r"(?i)\b(?:nonReentrant|ReentrancyGuard|noReentrant|noReentry|"
    r"noReentrancy|reentrancyGuard|reentrancyLock|lockReentrancy)\b"
    r"|"
    r"\b(?:_status|locked|_locked|entered|_entered)\s*=\s*(?:true|2|_ENTERED)"
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
        if "\n" in text:
            return "\n" * text.count("\n")
        return " "

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


def _post_callback_state_writes(function) -> set[str]:
    src = _source_without_comments_and_strings(_source(function))
    callback = _CALLBACK_OR_EXTERNAL_CALL_RE.search(src)
    if not callback:
        return set()

    slither_written = _state_names(getattr(function, "state_variables_written", []) or [])
    if not slither_written:
        return set()

    post_src = src[callback.end():]
    names = {
        match.group("name").lower()
        for match in _ACCOUNTING_WRITE_RE.finditer(post_src)
        if match.group("name") and _ACCOUNTING_NAME_RE.search(match.group("name"))
    }
    names.update(
        match.group("name").lower()
        for match in _DELETE_ACCOUNTING_RE.finditer(post_src)
        if match.group("name") and _ACCOUNTING_NAME_RE.search(match.group("name"))
    )
    return names & slither_written


def _source_reads_any(function, state_names: set[str]) -> bool:
    if not state_names:
        return False
    slither_reads = _state_names(getattr(function, "state_variables_read", []) or [])
    if slither_reads & state_names:
        return True

    src = _source_without_comments_and_strings(_source(function)).lower()
    for name in state_names:
        if re.search(r"\b" + re.escape(name) + r"\s*(?:\[|\.|\b)", src):
            return True
    return False


def _has_sibling_exit_or_settlement_reuse(contract, function, state_names: set[str]) -> bool:
    for candidate in getattr(contract, "functions_and_modifiers_declared", []) or []:
        if candidate is function:
            continue
        if getattr(candidate, "visibility", "") not in {"external", "public"}:
            continue
        if not _EXIT_OR_SETTLEMENT_NAME_RE.search(getattr(candidate, "name", "") or ""):
            continue
        if _source_reads_any(candidate, state_names):
            return True
    return False


class ReentrancyExternalCallbackBeforeAccountingFinalized(AbstractDetector):
    ARGUMENT = "reentrancy-external-callback-before-accounting-finalized"
    HELP = (
        "External callback or cross-contract call occurs before a debt, balance, "
        "settlement, or finalized-state write, and a sibling exit or settlement "
        "path reads that stale state."
    )
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = (
        "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/"
        "callback-external-call-before-accounting-finalized-positive.yaml"
    )
    WIKI_TITLE = "External callback before accounting finalization exposes stale-state exit"
    WIKI_DESCRIPTION = (
        "The risky shape is an externally callable mutating function that hands "
        "control to a callback, hook, token receiver, adapter, or value receiver "
        "before writing debt, balance, settlement status, or finalized state. "
        "A sibling exit or settlement path then reads the same stale state during "
        "reentry."
    )
    WIKI_EXPLOIT_SCENARIO = (
        "A callback fires before balances are decremented or a position is marked "
        "finalized. The receiver reenters a sibling exit or settlement path that "
        "still reads the old balance or unfinalized status and settles again."
    )
    WIKI_RECOMMENDATION = (
        "Finalize all debt, balance, and settlement state before any external "
        "control transfer, or use a shared reentrancy guard plus post-callback "
        "revalidation before committing settlement."
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

                post_write_names = _post_callback_state_writes(function)
                if not post_write_names:
                    continue
                if not _has_sibling_exit_or_settlement_reuse(contract, function, post_write_names):
                    continue

                info = [
                    function,
                    (
                        " - reentrancy-external-callback-before-accounting-finalized: "
                        "external callback precedes accounting finalization, and a "
                        "sibling exit or settlement path reads the same stale state."
                    ),
                ]
                results.append(self.generate_result(info))
        return results
