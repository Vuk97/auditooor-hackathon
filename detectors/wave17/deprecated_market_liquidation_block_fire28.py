"""
deprecated-market-liquidation-block-fire28

Detect liquidation, repayment, and bad-debt rescue entrypoints that enforce
paused, deprecated, frozen, or cap checks on the rescue path without a
liquidation-only or debt-reduction exception.

Source refs:
- reference/patterns.dsl.r74_mined_spearbit/borrow-token-caps-may-prevent-repayment-and-liquidations.yaml
- reference/patterns.dsl.r74_mined_cs.PROMOTED/liquidation-revert-due-to-unrelated-paused.yaml
- reference/patterns.dsl.zellic_k2_mined/reserve-cap-bypass-freezes-liquidation.yaml

This is candidate evidence only. It is intentionally scoped to source-shape
matches and must be paired with protocol-specific reachability before any
finding promotion.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Optional


DETECTOR_NAME = "deprecated-market-liquidation-block-fire28"
DETECTOR_SEVERITY_DEFAULT = "Medium"


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
    function_line: int
    body_line: int


_COMMENT_RE = re.compile(r"//[^\n\r]*|/\*.*?\*/", re.DOTALL)
_FN_HEADER_RE = re.compile(r"\bfunction\s+(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*\(")
_CALLABLE_HEADER_RE = re.compile(r"\b(?:external|public|internal)\b")

_RESCUE_NAME_RE = re.compile(
    r"(?i)(liquidat|repay|repayment|rescue|closeout|closeOut|closeBadDebt|"
    r"badDebt|settleBadDebt|writeOff|absorb|seize|deleverage|heal|"
    r"swapCollateral|auction)"
)
_DEBT_CONTEXT_RE = re.compile(
    r"(?i)\b(borrower|account|debt|badDebt|shortfall|insolvent|underwater|"
    r"collateral|healthFactor|repay|liquidat|seize|writeOff|deleverage)\b"
)
_ADMIN_MAINTENANCE_NAME_RE = re.compile(
    r"(?i)^(set|pause|unpause|configure|update|list|delist|deprecate|freeze|"
    r"cap|set[A-Z]|mark|toggle)"
)
_ADMIN_ONLY_RE = re.compile(
    r"(?i)\b(onlyOwner|onlyAdmin|onlyGovernance|onlyGov|onlyGuardian|"
    r"onlyConfigurator|onlyRiskAdmin|onlyMarketAdmin|onlyPoolAdmin|"
    r"onlyRole\s*\([^)]*(ADMIN|PAUSER|GUARDIAN|GOVERNANCE|CONFIGURATOR|"
    r"RISK|MANAGER)[^)]*\)|requiresAuth|auth)\b"
)

_GUARD_MODIFIER_RE = re.compile(
    r"(?i)\b(whenNotPaused|notPaused|marketNotPaused|reserveNotPaused|"
    r"whenMarketActive|onlyActiveMarket|notDeprecated|notFrozen|notBorrowPaused|"
    r"notRepayPaused|notLiquidationPaused|underCap|capNotExceeded|withinCap)\b"
)
_GUARD_EXPR_RE = re.compile(
    r"(?is)\b(?:require|if)\s*\((?P<expr>[^;{}]*(?:paused|pause|deprecated|"
    r"deprecat|frozen|freeze|cap|borrowCap|supplyCap|reserveCap|collateralCap|"
    r"debtCeiling|MAX_USER_RESERVES|countActiveReserves)[^;{}]*)\)"
)
_GUARD_CALL_RE = re.compile(
    r"(?i)\b(?:_?check|_?validate|_?require|_?assert|enforce)"
    r"[A-Za-z0-9_]*(?:Pause|Paused|Unpaused|Deprecated|Frozen|Freeze|Cap|"
    r"Ceiling|ActiveMarket|MarketActive)[A-Za-z0-9_]*\s*\("
)
_EXPLICIT_EXCEPTION_RE = re.compile(
    r"(?i)(skip(?:ped)?(?:Pause|Paused|Cap|Frozen|Deprecated)|"
    r"ignore(?:s|d)?(?:Pause|Paused|Cap|Frozen|Deprecated)|"
    r"bypass(?:Pause|Paused|Cap|Frozen|Deprecated)|"
    r"allow(?:ed)?Liquidat|liquidationExempt|"
    r"exempt(?:From)?(?:Pause|Paused|Cap|Frozen|Deprecated)|"
    r"debtReduction(?:Exempt|Bypass|Mode)|"
    r"reduceDebt(?:Bypass|WithoutCap)|closeoutException)"
)
_GUARD_LEVEL_EXCEPTION_RE = re.compile(
    r"(?i)(\|\||&&)[^;\n)]*(liquidat|repay|debtReduction|closeout|badDebt|"
    r"writeOff|shortfall|insolvent|keeper|auction)"
)


def _strip_comments(source: str) -> str:
    def replace(match: re.Match[str]) -> str:
        text = match.group(0)
        return "\n" * text.count("\n") if "\n" in text else " "

    return _COMMENT_RE.sub(replace, source or "")


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


def _split_functions(source: str) -> list[FunctionSlice]:
    out: list[FunctionSlice] = []
    pos = 0
    while True:
        match = _FN_HEADER_RE.search(source, pos)
        if not match:
            break
        name = match.group("name")
        i = match.end()
        depth_paren = 1
        while i < len(source) and depth_paren > 0:
            char = source[i]
            if char == "(":
                depth_paren += 1
            elif char == ")":
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
        out.append(
            FunctionSlice(
                name=name,
                header=header,
                body=body,
                function_line=source.count("\n", 0, match.start()) + 1,
                body_line=source.count("\n", 0, body_start + 1) + 1,
            )
        )
        pos = end_pos
    return out


def _line_for(fn: FunctionSlice, match: re.Match[str]) -> int:
    return fn.body_line + fn.body.count("\n", 0, match.start())


def _is_admin_maintenance(fn: FunctionSlice) -> bool:
    if not _ADMIN_ONLY_RE.search(fn.header):
        return False
    if _ADMIN_MAINTENANCE_NAME_RE.search(fn.name):
        return True
    return not _DEBT_CONTEXT_RE.search(fn.header + "\n" + fn.body)


def _has_explicit_rescue_exception(text: str) -> bool:
    if _EXPLICIT_EXCEPTION_RE.search(text):
        return True
    return any(_GUARD_LEVEL_EXCEPTION_RE.search(match.group("expr")) for match in _GUARD_EXPR_RE.finditer(text))


def _guard_evidence(fn: FunctionSlice) -> tuple[Optional[str], int]:
    pieces: list[str] = []
    line = 0

    modifier_match = _GUARD_MODIFIER_RE.search(fn.header)
    if modifier_match:
        pieces.append(f"modifier `{modifier_match.group(0)}` applies a market availability or cap guard")
        line = fn.function_line

    for match in _GUARD_EXPR_RE.finditer(fn.body):
        expr = re.sub(r"\s+", " ", match.group("expr")).strip()
        if _GUARD_LEVEL_EXCEPTION_RE.search(expr):
            continue
        if line == 0:
            line = _line_for(fn, match)
        pieces.append(f"guard expression `{expr[:120]}` blocks a rescue path")

    for call_match in _GUARD_CALL_RE.finditer(fn.body):
        if line == 0:
            line = _line_for(fn, call_match)
        pieces.append(f"guard call `{call_match.group(0).strip()}` blocks a rescue path")

    if not pieces:
        return None, 0
    return "; ".join(pieces[:4]), line


def _is_rescue_path(fn: FunctionSlice) -> bool:
    if not _CALLABLE_HEADER_RE.search(fn.header):
        return False
    text = fn.name + "\n" + fn.header + "\n" + fn.body
    if not _RESCUE_NAME_RE.search(text):
        return False
    return bool(_DEBT_CONTEXT_RE.search(text))


def scan(source: str, file_path: str) -> list[Finding]:
    text = _strip_comments(source)
    findings: list[Finding] = []
    for fn in _split_functions(text):
        if not _is_rescue_path(fn):
            continue
        if _is_admin_maintenance(fn):
            continue
        context = fn.header + "\n" + fn.body
        if _has_explicit_rescue_exception(context):
            continue

        evidence, line = _guard_evidence(fn)
        if evidence is None:
            continue

        findings.append(
            Finding(
                detector=DETECTOR_NAME,
                file=file_path,
                line=line,
                severity=DETECTOR_SEVERITY_DEFAULT,
                function=fn.name,
                message=(
                    "Liquidation, repayment, or bad-debt rescue path enforces "
                    "pause/deprecated/frozen/cap state without an explicit "
                    f"liquidation-only bypass or debt-reduction exception: {evidence}."
                ),
            )
        )
    return findings
