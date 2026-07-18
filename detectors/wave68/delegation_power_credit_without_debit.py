#!/usr/bin/env python3
"""Detect delegation power credit without a matching old-source debit.

This is a same-class generalization for W68 delegation-power-inflation.
It targets Solidity delegation update functions that credit a delegate or
vote-power ledger, but do not debit or clear the prior delegate/source in the
same function.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import List, Optional


DETECTOR_NAME = "delegation-power-credit-without-debit"
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


_FN_HEADER_RE = re.compile(r"\bfunction\s+(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*\(")
_VISIBILITY_RE = re.compile(r"\b(?:public|external)\b")
_DELEGATION_FN_RE = re.compile(
    r"(?i)(delegate|redelegate|delegation|setDelegate|changeDelegate|"
    r"updateDelegate|assignDelegate|reassignDelegate|moveDelegation)"
)
_POWER_LEDGER = (
    r"(?:delegationPower|delegatePower|delegatedPower|votingPower|"
    r"votePower|delegateVotes|delegatedVotes|votesByDelegate|"
    r"delegateWeight|delegatedWeight|validatorPower)"
)
_DEST_EXPR = (
    r"(?:[^\]]*\b(?:to|newDelegate|newDelegatee|delegatee|delegate|"
    r"representative|validator|operator|recipient)[^\]]*)"
)
_CREDIT_RE = re.compile(
    rf"(?is)\b(?P<ledger>{_POWER_LEDGER})\s*\[\s*(?P<dst>{_DEST_EXPR})\s*\]\s*"
    rf"(?:\+=|=\s*[^;\n]*\+)[^;]*;"
)
_SOURCE_AMOUNT_RE = re.compile(
    r"(?i)\b(balanceOf|balances|stake|stakes|amount|weight|votes|power|shares|units)\b"
)
_OLD_NAME = (
    r"(?:oldDelegate|prevDelegate|previousDelegate|priorDelegate|"
    r"currentDelegate|existingDelegate|fromDelegate|formerDelegate|"
    r"oldValidator|previousValidator|fromValidator|oldRepresentative|"
    r"previousRepresentative)"
)
_DEBIT_TEMPLATE = (
    r"(?is)\b{ledger}\s*\[\s*(?:[^\]]*\b{old}\b[^\]]*)\]\s*"
    r"(?:-=|=\s*[^;\n]*-)[^;]*;"
)
_CLEAR_OR_MOVE_RE = re.compile(
    r"(?is)\b(_moveDelegateVotes|_moveDelegates|_moveVotingPower|"
    r"_transferVotingUnits|moveDelegateVotes|moveDelegationPower|"
    r"debitOldDelegate|debitDelegate|subtractOldDelegate|"
    r"removeDelegation|_removeDelegation|clearOldDelegate|"
    r"clearDelegation|detachDelegate|removeFromOldDelegate|"
    r"swapAndPop)\s*\("
    r"|delete\s+(?:delegateOf|delegates|delegations|delegatedTo|"
    r"delegatedTokenIds|delegatedVotes)\s*\["
    r"|(?:delegateOf|delegates|delegations|delegatedTo)\s*\[[^\]]+\]\s*=\s*address\s*\(\s*0\s*\)"
)


def _strip_comments(source: str) -> str:
    source = re.sub(r"//[^\n]*", "", source)
    source = re.sub(r"/\*.*?\*/", lambda m: "\n" * m.group(0).count("\n"), source, flags=re.S)
    return source


def _extract_balanced_block(source: str, open_brace: int) -> tuple[Optional[str], int]:
    if open_brace < 0 or open_brace >= len(source) or source[open_brace] != "{":
        return None, open_brace
    depth = 1
    i = open_brace + 1
    while i < len(source) and depth > 0:
        char = source[i]
        if char == "{":
            depth += 1
        elif char == "}":
            depth -= 1
        i += 1
    if depth != 0:
        return None, open_brace
    return source[open_brace + 1:i - 1], i


def _split_functions(source: str) -> List[FunctionSlice]:
    out: List[FunctionSlice] = []
    pos = 0
    while True:
        match = _FN_HEADER_RE.search(source, pos)
        if not match:
            break
        name = match.group("name")
        i = match.end()
        depth_paren = 1
        while i < len(source) and depth_paren > 0:
            if source[i] == "(":
                depth_paren += 1
            elif source[i] == ")":
                depth_paren -= 1
            i += 1
        body_start = -1
        j = i
        while j < len(source):
            if source[j] == ";":
                break
            if source[j] == "{":
                body_start = j
                break
            j += 1
        if body_start < 0:
            pos = max(j, i)
            continue
        body, end_pos = _extract_balanced_block(source, body_start)
        if body is None:
            pos = body_start + 1
            continue
        header = source[match.start():body_start]
        body_line = source.count("\n", 0, body_start + 1) + 1
        out.append(FunctionSlice(name=name, header=header, body=body, body_line=body_line))
        pos = end_pos
    return out


def _has_matching_debit_or_clear(body: str, ledger: str) -> bool:
    debit_re = re.compile(
        _DEBIT_TEMPLATE.format(ledger=re.escape(ledger), old=_OLD_NAME)
    )
    return bool(debit_re.search(body) or _CLEAR_OR_MOVE_RE.search(body))


def scan(source: str, file_path: str = "<unknown>") -> List[Finding]:
    clean_source = _strip_comments(source)
    findings: List[Finding] = []
    for fn in _split_functions(clean_source):
        if not _VISIBILITY_RE.search(fn.header):
            continue
        if not _DELEGATION_FN_RE.search(fn.name):
            continue

        for credit in _CREDIT_RE.finditer(fn.body):
            statement = credit.group(0)
            if not _SOURCE_AMOUNT_RE.search(statement):
                continue
            ledger = credit.group("ledger")
            if _has_matching_debit_or_clear(fn.body, ledger):
                continue

            line = fn.body_line + fn.body.count("\n", 0, credit.start())
            findings.append(
                Finding(
                    detector=DETECTOR_NAME,
                    file=file_path,
                    line=line,
                    severity=DETECTOR_SEVERITY_DEFAULT,
                    function=fn.name,
                    message=(
                        f"`{fn.name}` credits `{ledger}` for a new delegate or "
                        "delegate-like destination without debiting or clearing "
                        "the prior delegate/source in the same function. This "
                        "matches delegation-power-inflation."
                    ),
                )
            )
            break
    return findings


__all__ = ["scan", "Finding", "DETECTOR_NAME", "DETECTOR_SEVERITY_DEFAULT"]
