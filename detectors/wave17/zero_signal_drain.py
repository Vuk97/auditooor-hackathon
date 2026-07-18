"""
zero-signal-drain — Graph-style composed migration drain seed (Phase A).

Tight trigger (low-noise seed):
  1) Public/external publish/migrate-like function with curated-target markers.
  2) Function computes a signal/share-like output via floor-prone math
     (division or mulDiv/convert-style expression) and uses that value in a
     mint/signal-write path.
  3) Same function does NOT enforce a strict positive-output guard for that
     computed signal/share output.
  4) Same contract has a public/external burn/redeem-like function that
     rejects zero signal/share AND routes reserve-like value out (transfer/
     redeem/withdraw), indicating mint/burn asymmetry with reserve consequence.

The detector is deliberately narrow and contract-local to suppress noisy
single-symptom matches.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import List, Optional


DETECTOR_NAME = "zero-signal-drain"
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


@dataclass
class ContractSlice:
    name: str
    body: str
    body_line: int


_TEST_PATH_RE = re.compile(r"(?i)\b(mock|test|fixture)\b")
_CONTRACT_HEADER_RE = re.compile(
    r"\b(?:contract|library|abstract\s+contract)\s+"
    r"(?P<name>[A-Za-z_][A-Za-z0-9_]*)\b"
)
_FN_HEADER_RE = re.compile(r"\bfunction\s+(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*\(")
_VISIBILITY_RE = re.compile(r"\b(?:public|external)\b")

_PUBLISH_FN_NAME_RE = re.compile(
    r"(?i)(publish|newVersion|migrate|upgrade|transferFinalization|finalizeMigration)"
)
_BURN_FN_NAME_RE = re.compile(r"(?i)(burn|redeem|withdraw|unpublish)")

_CURATED_MARKER_RE = re.compile(r"(?i)(pre[_-]?curat|curat(?:ed|ion)?|alreadyCurated)")
_TARGET_MARKER_RE = re.compile(r"(?i)(target|deployment|version|pool|subgraph)")

_SIGNAL_ASSIGN_RE = re.compile(
    r"(?i)\b(?P<var>[A-Za-z_][A-Za-z0-9_]*(?:signal|share)[A-Za-z0-9_]*)\s*=\s*"
    r"[^;\n]*(?:/|mulDiv|convert)[^;\n]*;"
)

_BURN_ZERO_REJECT_RE = re.compile(
    r"(?is)"
    r"(require\s*\([^;]*(?:signal|share)[^;]*(?:>\s*0|!=\s*0))|"
    r"(if\s*\([^)]*(?:signal|share)[^)]*==\s*0[^)]*\)\s*\{?[^{};]{0,80}revert)"
)
_RESERVE_PAYOUT_RE = re.compile(
    r"(?is)"
    r"((reserve|poolReserve|curatedReserve|deploymentReserve)[^;]{0,220}"
    r"(transfer|safeTransfer|send|payout|redeem|withdraw))|"
    r"((transfer|safeTransfer|redeem|withdraw)[^;]{0,220}"
    r"(reserve|poolReserve|curatedReserve|deploymentReserve))"
)


def _extract_balanced_block(source: str, open_brace: int) -> tuple[Optional[str], int]:
    if open_brace < 0 or open_brace >= len(source) or source[open_brace] != "{":
        return None, open_brace
    depth = 1
    i = open_brace + 1
    while i < len(source) and depth > 0:
        c = source[i]
        if c == "{":
            depth += 1
        elif c == "}":
            depth -= 1
        i += 1
    if depth != 0:
        return None, open_brace
    return source[open_brace + 1:i - 1], i


def _split_contracts(source: str) -> List[ContractSlice]:
    out: List[ContractSlice] = []
    pos = 0
    while True:
        m = _CONTRACT_HEADER_RE.search(source, pos)
        if not m:
            break
        brace = source.find("{", m.end())
        if brace < 0:
            break
        body, end_pos = _extract_balanced_block(source, brace)
        if body is None:
            pos = brace + 1
            continue
        line = source.count("\n", 0, brace + 1) + 1
        out.append(ContractSlice(name=m.group("name"), body=body, body_line=line))
        pos = end_pos
    return out


def _split_functions(source: str, base_line: int) -> List[FunctionSlice]:
    out: List[FunctionSlice] = []
    pos = 0
    while True:
        m = _FN_HEADER_RE.search(source, pos)
        if not m:
            break
        name = m.group("name")
        i = m.end()
        depth_paren = 1
        while i < len(source) and depth_paren > 0:
            c = source[i]
            if c == "(":
                depth_paren += 1
            elif c == ")":
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
        header = source[m.start():body_start]
        body_line = base_line + source.count("\n", 0, body_start + 1)
        out.append(FunctionSlice(name=name, header=header, body=body, body_line=body_line))
        pos = end_pos
    return out


def _has_positive_output_guard(body: str, var_name: str) -> bool:
    v = re.escape(var_name)
    strict_re = re.compile(
        rf"(?is)(require\s*\(\s*{v}\s*(?:>|!=)\s*0)|"
        rf"(if\s*\(\s*{v}\s*==\s*0\s*\)\s*\{{?[^{{}};]{{0,80}}revert)"
    )
    return bool(strict_re.search(body))


def _uses_var_in_mint_or_signal_write(body: str, var_name: str) -> bool:
    v = re.escape(var_name)
    mint_call_re = re.compile(
        rf"(?is)"
        rf"(?:_?mint|mint\w*|publish\w*|set\w*signal|update\w*signal|add\w*signal)"
        rf"\s*\([^;{{}}]*\b{v}\b"
    )
    state_write_re = re.compile(
        rf"(?is)\b\w+\s*\[[^\]]+\]\s*(?:\+=|=)\s*[^;\n]*\b{v}\b"
    )
    return bool(mint_call_re.search(body) or state_write_re.search(body))


def _find_burn_reserve_function(functions: List[FunctionSlice]) -> Optional[FunctionSlice]:
    for fn in functions:
        if not _VISIBILITY_RE.search(fn.header):
            continue
        if not _BURN_FN_NAME_RE.search(fn.name):
            continue
        if not _BURN_ZERO_REJECT_RE.search(fn.body):
            continue
        if not _RESERVE_PAYOUT_RE.search(fn.body):
            continue
        return fn
    return None


def scan(source: str, file_path: str = "<unknown>") -> List[Finding]:
    if _TEST_PATH_RE.search(file_path):
        return []

    findings: List[Finding] = []
    contracts = _split_contracts(source)
    for contract in contracts:
        functions = _split_functions(contract.body, contract.body_line)
        if not functions:
            continue
        burn_fn = _find_burn_reserve_function(functions)
        if burn_fn is None:
            continue

        for fn in functions:
            if not _VISIBILITY_RE.search(fn.header):
                continue
            if not _PUBLISH_FN_NAME_RE.search(fn.name):
                continue
            if not _CURATED_MARKER_RE.search(fn.body):
                continue
            if not _TARGET_MARKER_RE.search(fn.body):
                continue

            for m in _SIGNAL_ASSIGN_RE.finditer(fn.body):
                var_name = m.group("var")
                if not _uses_var_in_mint_or_signal_write(fn.body, var_name):
                    continue
                if _has_positive_output_guard(fn.body, var_name):
                    continue
                line = fn.body_line + fn.body.count("\n", 0, m.start())
                findings.append(
                    Finding(
                        detector=DETECTOR_NAME,
                        file=file_path,
                        line=line,
                        severity=DETECTOR_SEVERITY_DEFAULT,
                        function=fn.name,
                        message=(
                            f"`{fn.name}` computes `{var_name}` via floor-prone math and "
                            "uses it in a publish/mint-style path for a curated target "
                            "without enforcing positive output; same contract has "
                            f"`{burn_fn.name}` with zero-signal rejection plus reserve "
                            "payout shape. This matches the Graph-style zero-signal-drain "
                            "mint/burn asymmetry seed."
                        ),
                    )
                )
                # One finding per publish/migrate function is enough.
                break
    return findings


__all__ = ["scan", "Finding", "DETECTOR_NAME", "DETECTOR_SEVERITY_DEFAULT"]
