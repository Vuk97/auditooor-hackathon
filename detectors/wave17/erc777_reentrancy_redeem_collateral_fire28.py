"""
erc777-reentrancy-redeem-collateral-fire28

Solidity recall detector for ERC777-style value-exit reentrancy windows in
redeem, withdraw, reward, and liquidation flows.

Confirmed source refs:
- reference/patterns.dsl.r94_solodit_reentrancy/erc777-reentrancy-during-redeem-charges-more-collateral.yaml
- reference/patterns.dsl.r94_solodit_reentrancy/updateaccountrewards-after-external-call-reentrancy-reward-steal.yaml

Detector hits are candidate evidence only. They require source review,
exploitability proof, and a non-vacuous PoC before filing.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Optional


DETECTOR_NAME = "erc777-reentrancy-redeem-collateral-fire28"
DETECTOR_SEVERITY_DEFAULT = "High"


@dataclass
class Finding:
    detector: str
    file: str
    line: int
    severity: str
    message: str
    function: Optional[str] = None


@dataclass
class FunctionSlice:
    name: str
    header: str
    body: str
    body_line: int


_TOKEN_RE = re.compile(
    r'"(?:[^"\\]|\\.)*"|'
    r"'(?:[^'\\]|\\.)*'|"
    r"//[^\n\r]*|"
    r"/\*.*?\*/",
    re.DOTALL,
)
_FN_HEADER_RE = re.compile(r"\bfunction\s+(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*\(")
_PUBLIC_ENTRY_RE = re.compile(r"\b(?:external|public)\b")
_READ_ONLY_RE = re.compile(r"\b(?:view|pure)\b")
_EXIT_FUNCTION_RE = re.compile(
    r"^_?(?:redeem|withdraw|claim|collect|harvest|getReward|exit|"
    r"settle|release|liquidat|seize|close|unstake|unbond|cashout|"
    r"payout|sweep)[A-Za-z0-9_]*$",
    re.IGNORECASE,
)
_VALUE_EXIT_RE = re.compile(
    r"(?is)(?:"
    r"\.\s*(?:safeTransfer|transfer)\s*\("
    r"|"
    r"\b(?:safeTransfer|transfer)\s*\(\s*"
    r"(?:msg\s*\.\s*sender|_msgSender\s*\(\s*\)|recipient|receiver|"
    r"to|account|user|borrower|owner|payee)"
    r"|"
    r"\.\s*call\s*\{\s*value\s*:"
    r"|"
    r"\bAddress\s*\.\s*sendValue\s*\("
    r")"
)
_ACCOUNTING_NAME_RE = re.compile(
    r"(?i)(account|balance|balances|share|shares|debt|borrow|loan|"
    r"collateral|reward|rewards|claim|claimed|pending|position|"
    r"principal|asset|assets|supply|withdraw|redeem|paid|settled|"
    r"liquidat|seized|allowance|credit|owed|escrow)"
)
_ACCOUNTING_WRITE_RE = re.compile(
    r"(?is)(?:"
    r"\bdelete\s+(?P<delete_name>[A-Za-z_][A-Za-z0-9_]*)"
    r"\s*(?:\[[^\]]+\]\s*)+"
    r"|"
    r"\b(?P<mapping_name>[A-Za-z_][A-Za-z0-9_]*)"
    r"\s*(?:\[[^\]]+\]\s*)+(?:\.[A-Za-z_][A-Za-z0-9_]*)?"
    r"\s*(?:=|\+=|-=|\+\+|--)"
    r"|"
    r"\b(?P<plain_name>totalShares|totalDebt|totalSupply|totalCollateral|"
    r"rewardIndex|accRewardPerShare|debtShares|collateralShares)"
    r"\s*(?:=|\+=|-=|\+\+|--)"
    r"|"
    r"\b_?(?P<settlement_call>updateAccountRewards|checkpointRewards|"
    r"settleRewards|accrueRewards|burn|burnShares|decreaseDebt|"
    r"decreaseBorrow|settleCollateral|finalizeRedeem|finalizeWithdraw|"
    r"settleLiquidation|settleAccount|syncRewards)"
    r"\s*\("
    r")"
)
_REENTRANCY_GUARD_RE = re.compile(
    r"(?i)\b(?:nonReentrant|ReentrancyGuard|noReentrant|noReentry|"
    r"noReentrancy|reentrancyGuard|reentrancyLock|lockReentrancy|"
    r"reentryGuard)\b"
    r"|"
    r"\b(?:_status|locked|_locked|entered|_entered|reentrancyLock)"
    r"\s*=\s*(?:true|2|_ENTERED|ENTERED)"
)
_NOISY_RE = re.compile(r"(?i)\b(?:mock|test|fixture|example|preview|probeOnly)\b")


def _strip_comments_and_strings(source: str) -> str:
    def replace_token(match: re.Match[str]) -> str:
        text = match.group(0)
        return "\n" * text.count("\n") if "\n" in text else " "

    return _TOKEN_RE.sub(replace_token, source or "")


def _find_matching_delimiter(source: str, open_pos: int, open_char: str, close_char: str) -> int:
    if open_pos < 0 or open_pos >= len(source) or source[open_pos] != open_char:
        return -1
    depth = 1
    pos = open_pos + 1
    while pos < len(source) and depth > 0:
        if source[pos] == open_char:
            depth += 1
        elif source[pos] == close_char:
            depth -= 1
        pos += 1
    return pos - 1 if depth == 0 else -1


def _split_functions(source: str) -> list[FunctionSlice]:
    out: list[FunctionSlice] = []
    pos = 0
    while True:
        match = _FN_HEADER_RE.search(source, pos)
        if match is None:
            break
        name = match.group("name")
        open_paren = source.find("(", match.end() - 1)
        close_paren = _find_matching_delimiter(source, open_paren, "(", ")")
        if close_paren < 0:
            pos = match.end()
            continue

        body_start = -1
        scan = close_paren + 1
        while scan < len(source):
            if source[scan] == ";":
                break
            if source[scan] == "{":
                body_start = scan
                break
            scan += 1
        if body_start < 0:
            pos = max(scan, close_paren + 1)
            continue

        body_end = _find_matching_delimiter(source, body_start, "{", "}")
        if body_end < 0:
            pos = body_start + 1
            continue

        header = source[match.start():body_start]
        body = source[body_start + 1:body_end]
        body_line = source.count("\n", 0, body_start + 1) + 1
        out.append(FunctionSlice(name=name, header=header, body=body, body_line=body_line))
        pos = body_end + 1
    return out


def _accounting_write_name(match: re.Match[str]) -> str:
    for group in ("delete_name", "mapping_name", "plain_name", "settlement_call"):
        value = match.groupdict().get(group)
        if value:
            return value
    return ""


def _post_transfer_accounting_write(body: str, transfer_end: int) -> tuple[bool, str]:
    post = body[transfer_end:]
    for match in _ACCOUNTING_WRITE_RE.finditer(post):
        name = _accounting_write_name(match)
        if name and _ACCOUNTING_NAME_RE.search(name):
            return True, name
        if match.groupdict().get("settlement_call"):
            return True, name
    return False, ""


def _has_visible_guard(header: str, body: str) -> bool:
    return bool(_REENTRANCY_GUARD_RE.search(header) or _REENTRANCY_GUARD_RE.search(body))


def _line_for_function(source: str, function_name: str) -> int:
    match = re.search(rf"\bfunction\s+{re.escape(function_name)}\s*\(", source)
    if match is None:
        return 1
    return source.count("\n", 0, match.start()) + 1


def _finding(source: str, file_path: str, function: FunctionSlice, state_name: str) -> Finding:
    return Finding(
        detector=DETECTOR_NAME,
        file=file_path,
        line=_line_for_function(source, function.name),
        severity=DETECTOR_SEVERITY_DEFAULT,
        function=function.name,
        message=(
            f"{DETECTOR_NAME}: callback-capable value transfer before "
            f"{state_name} accounting settlement in {function.name}; "
            "review for ERC777 or receiver-hook reentrancy before filing."
        ),
    )


def scan(source: str, file_path: str) -> list[Finding]:
    clean = _strip_comments_and_strings(source)
    findings: list[Finding] = []
    for function in _split_functions(clean):
        if not _PUBLIC_ENTRY_RE.search(function.header):
            continue
        if _READ_ONLY_RE.search(function.header):
            continue
        if not _EXIT_FUNCTION_RE.search(function.name):
            continue
        if _NOISY_RE.search(function.name):
            continue
        if _has_visible_guard(function.header, function.body):
            continue

        transfer = _VALUE_EXIT_RE.search(function.body)
        if transfer is None:
            continue
        has_write, state_name = _post_transfer_accounting_write(function.body, transfer.end())
        if not has_write:
            continue

        findings.append(_finding(source, file_path, function, state_name))
    return findings


__all__ = [
    "DETECTOR_NAME",
    "DETECTOR_SEVERITY_DEFAULT",
    "Finding",
    "scan",
]
