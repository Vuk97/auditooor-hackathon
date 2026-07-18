"""
reentrancy-state-or-nonce-cleanup-fire20

Same-class recall lift for reentrancy windows where an external call, token
receiver callback, or hook runs before nonce/commitment cleanup, token-id
finalization, accounting updates, or multi-recipient ETH fee dispatch
finalization.

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


DETECTOR_NAME = "reentrancy-state-or-nonce-cleanup-fire20"
DETECTOR_SEVERITY_DEFAULT = "High"

_ENTRYPOINT_RE = re.compile(
    r"(?i)^_?(?:consume|claim|redeem|finali[sz]e|settle|execute|complete|"
    r"dispatch|distribute|split|payout|sweep|withdraw|refund|mint|safeMint|"
    r"deposit|borrow|repay|liquidate|fill|match|cancel|release|collect)"
    r"[A-Za-z0-9_]*$"
)
_EXTERNAL_CONTROL_RE = re.compile(
    r"(?is)(?:"
    r"\b_?safeMint\s*\("
    r"|"
    r"\.\s*(?:on[A-Za-z0-9_]*(?:Received|Callback|Hook|FlashLoan)|"
    r"before[A-Za-z0-9_]*|after[A-Za-z0-9_]*)\s*\("
    r"|"
    r"\bI[A-Za-z0-9_]*(?:Callback|Hook|Receiver|Adapter|Notify|Refund)"
    r"[A-Za-z0-9_]*\s*\([^;\n]*\)\s*\.\s*[A-Za-z_]\w*\s*\("
    r"|"
    r"\.\s*(?:safeTransferFrom|safeTransfer|transferFrom|transfer|sendValue)"
    r"\s*\("
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
    r"finali[sz]|status|state|position|account|escrow|withdraw|amount|fee)"
)
_REENTRANCY_GUARD_RE = re.compile(
    r"(?i)\b(?:nonReentrant|ReentrancyGuard|noReentrant|noReentry|"
    r"noReentrancy|reentrancyGuard|reentrancyLock|lockReentrancy|"
    r"reentryGuard)\b"
    r"|"
    r"\b(?:_status|status|locked|_locked|entered|_entered|reentrancyLock)"
    r"\s*=\s*(?:true|2|_ENTERED|ENTERED)"
)
_NOISY_SOURCE_RE = re.compile(
    r"(?i)\b(?:mock|test|fixture|example|notifyOnly|ping|viewOnly|probeOnly)\b"
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


def _post_control_cleanup_writes(function) -> set[str]:
    src = _source_without_comments_and_strings(_source(function))
    control = _EXTERNAL_CONTROL_RE.search(src)
    if not control:
        return set()

    slither_written = _state_names(getattr(function, "state_variables_written", []) or [])
    if not slither_written:
        return set()

    post_src = src[control.end():]
    written = {
        match.group("name").lower()
        for match in _STATE_WRITE_RE.finditer(post_src)
        if match.group("name") and _FINALIZATION_NAME_RE.search(match.group("name"))
    }
    written.update(
        match.group("name").lower()
        for match in _STATE_DELETE_RE.finditer(post_src)
        if match.group("name") and _FINALIZATION_NAME_RE.search(match.group("name"))
    )
    return written & slither_written


def _has_control_before_cleanup(function) -> bool:
    if not _EXTERNAL_CONTROL_RE.search(_source_without_comments_and_strings(_source(function))):
        return False
    return bool(_post_control_cleanup_writes(function))


def _has_balance_based_splitter_without_guard(function) -> bool:
    src = _source_without_comments_and_strings(_source(function))
    if len(_VALUE_CALL_RE.findall(src)) < 2:
        return False
    if not _BALANCE_SOURCE_RE.search(src):
        return False
    name = getattr(function, "name", "") or ""
    if getattr(function, "payable", False):
        return True
    return bool(re.search(r"(?i)(dispatch|distribute|split|payout|sweep|fee|collect)", name))


def _line_for(source: str, offset: int) -> int:
    return source.count("\n", 0, max(offset, 0)) + 1


def _function_slices(source: str):
    header_re = re.compile(
        r"\bfunction\s+(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*\([^)]*\)"
        r"(?P<header>[^{};]*)\{",
        re.DOTALL,
    )
    for match in header_re.finditer(source):
        depth = 1
        pos = match.end()
        while pos < len(source) and depth:
            if source[pos] == "{":
                depth += 1
            elif source[pos] == "}":
                depth -= 1
            pos += 1
        if depth:
            continue
        yield match.group("name"), match.group("header"), source[match.end():pos - 1], match.start()


def _regex_finding(source: str, file_path: str, offset: int, function: str, message: str):
    return {
        "detector": DETECTOR_NAME,
        "severity": DETECTOR_SEVERITY_DEFAULT,
        "file": file_path,
        "line": _line_for(source, offset),
        "message": f"{DETECTOR_NAME}: {message}",
        "function": function,
    }


def scan(source: str, file_path: str):
    """Regex-runner entrypoint for the real-world recall scoreboard."""
    clean = _source_without_comments_and_strings(source)
    findings = []
    for name, header, body, offset in _function_slices(clean):
        if not re.search(r"\b(?:external|public)\b", header):
            continue
        if not _ENTRYPOINT_RE.search(name):
            continue
        if _REENTRANCY_GUARD_RE.search(header) or _REENTRANCY_GUARD_RE.search(body):
            continue
        if _NOISY_SOURCE_RE.search(name) or _NOISY_SOURCE_RE.search(body):
            continue

        control = _EXTERNAL_CONTROL_RE.search(body)
        if control:
            post = body[control.end():]
            cleanup_after_control = any(
                _FINALIZATION_NAME_RE.search(match.group("name") or "")
                for match in _STATE_WRITE_RE.finditer(post)
            ) or any(
                _FINALIZATION_NAME_RE.search(match.group("name") or "")
                for match in _STATE_DELETE_RE.finditer(post)
            )
            if cleanup_after_control:
                findings.append(
                    _regex_finding(
                        source,
                        file_path,
                        offset,
                        name,
                        "external control transfer precedes nonce/state cleanup or accounting finalization",
                    )
                )
                continue

        if (
            len(_VALUE_CALL_RE.findall(body)) >= 2
            and _BALANCE_SOURCE_RE.search(body)
            and re.search(r"(?i)(dispatch|distribute|split|payout|sweep|fee|collect)", name)
        ):
            findings.append(
                _regex_finding(
                    source,
                    file_path,
                    offset,
                    name,
                    "balance-based multi-call fee splitter lacks one shared reentrancy guard",
                )
            )

    return findings


class ReentrancyStateOrNonceCleanupFire20(AbstractDetector):
    ARGUMENT = DETECTOR_NAME
    HELP = (
        "External control transfer occurs before nonce/commitment cleanup, "
        "token-id/accounting finalization, or multi-recipient fee splitter "
        "state finalization."
    )
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = (
        "https://github.com/Vuk97/auditooor/blob/main/reports/"
        "detector_lift_fire20_20260605/worker_results/worker_ii_results.md"
    )
    WIKI_TITLE = "Reentrancy window before state or nonce cleanup"
    WIKI_DESCRIPTION = (
        "The risky shape is an externally callable mutating function that gives "
        "control to a receiver, hook, callback, or payable fallback before it "
        "cleans a single-use nonce/commitment, increments token-id/accounting "
        "state, or finalizes a multi-recipient ETH fee split."
    )
    WIKI_EXPLOIT_SCENARIO = (
        "An attacker-controlled callback reenters while the outer call has not "
        "deleted a pending commitment, consumed a nonce, incremented the next "
        "token id, or completed balance-based fee dispatch. The reentrant path "
        "can repeat the consume or observe stale partially finalized state."
    )
    WIKI_RECOMMENDATION = (
        "Apply CEI: consume nonce and pending state, update token-id and "
        "accounting state, and finalize settlement before external control "
        "transfer. If ordering cannot change, put one shared reentrancy guard "
        "on the entrypoint and sibling callback paths."
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
                if not _ENTRYPOINT_RE.search(getattr(function, "name", "") or ""):
                    continue
                if _has_reentrancy_guard(function):
                    continue
                if _NOISY_SOURCE_RE.search(_source(function)):
                    continue

                if not (
                    _has_control_before_cleanup(function)
                    or _has_balance_based_splitter_without_guard(function)
                ):
                    continue

                info = [
                    function,
                    (
                        " - reentrancy-state-or-nonce-cleanup-fire20: "
                        "external control transfer precedes nonce/state "
                        "cleanup, token-id/accounting finalization, or a "
                        "balance-based multi-call fee splitter lacks one "
                        "shared guard."
                    ),
                ]
                results.append(self.generate_result(info))
        return results


__all__ = [
    "ReentrancyStateOrNonceCleanupFire20",
    "DETECTOR_NAME",
    "DETECTOR_SEVERITY_DEFAULT",
    "scan",
]
