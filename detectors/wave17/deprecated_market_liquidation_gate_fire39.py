"""
deprecated-market-liquidation-gate-fire39

verification_tier: tier-3-synthetic-taxonomy-anchored
attack_class: emergency-bypass
context_pack_id: auditooor.vault_context_pack.v1:resume:cbdd9eeb5255863c
context_pack_hash: cbdd9eeb5255863c4870d83e88642e9c4a3eef8e7cdfb8b5fb9a8ee7ac5a25d8
MCP receipt: .auditooor/memory_context_receipt.json
NOT_SUBMIT_READY

Fire39 Solidity detector for emergency-bypass misses where an admin
deprecates, closes, disables, or freezes a market while the liquidation,
repayment, or bad-debt closeout entrypoint still enforces that same market
status without a liquidation-only exception or deprecated-market rescue path.

Seed refs inspected:
* reports/detector_lift_fire38_20260605/post_priorities_solidity.md
* detectors/wave17/emergency_pending_claim_bypass_fire38.py
* reference/patterns.dsl/a-market-could-be-deprecated-but-still-prevent-liquidators-to-li.yaml
* reference/patterns.dsl/admin-sweep-blocks-pending-user-claims.yaml

R40/R76/R80 caveat: detector hits are source-review candidates only, not
proof. They are NOT_SUBMIT_READY and must not be used as exploit evidence
without real entrypoint execution, source-existence validation, and honest
harness evidence.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Optional


DETECTOR_NAME = "deprecated-market-liquidation-gate-fire39"
DETECTOR_SEVERITY_DEFAULT = "Medium"
PROMOTION_ALLOWED = False


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
    start_line: int


@dataclass
class ContractSlice:
    source: str
    start_line: int
    name: str


_TOKEN_RE = re.compile(
    r'"(?:[^"\\]|\\.)*"|'
    r"'(?:[^'\\]|\\.)*'|"
    r"//[^\n\r]*|"
    r"/\*.*?\*/",
    re.DOTALL,
)
_CONTRACT_HEADER_RE = re.compile(
    r"\b(?:abstract\s+)?(?:contract|library)\s+(?P<name>[A-Za-z_][A-Za-z0-9_]*)\b"
)
_FN_HEADER_RE = re.compile(r"\bfunction\s+(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*\(")
_CALLABLE_RE = re.compile(r"\b(?:external|public|internal)\b", re.IGNORECASE)
_PUBLIC_RE = re.compile(r"\b(?:external|public)\b", re.IGNORECASE)
_VIEW_OR_PURE_RE = re.compile(r"\b(?:view|pure)\b", re.IGNORECASE)
_SKIP_RE = re.compile(r"\b(?:mock|test|fixture|harness|example|demo)\b", re.IGNORECASE)

_FAST_CONTEXT_RE = re.compile(
    r"\b(?:deprecat|disable|disabled|close|closed|freeze|frozen|pause|"
    r"paused|liquidat|repay|badDebt|shortfall|insolvent|marketStatus|"
    r"isLiquidateBorrowPaused|liquidationsPaused|isDeprecated|"
    r"marketDeprecated)\b",
    re.IGNORECASE,
)
_ADMIN_AUTH_RE = re.compile(
    r"\b(?:onlyOwner|onlyAdmin|onlyGovernor|onlyGovernance|onlyGov|"
    r"onlyGuardian|onlyEmergencyAdmin|onlyPauser|onlyRole|onlyRoles|"
    r"requiresAuth|requiresAuthorization|restricted|auth|hasRole|"
    r"_checkRole|EMERGENCY_ADMIN|GUARDIAN_ROLE|PAUSER_ROLE|ADMIN_ROLE|"
    r"RISK_ADMIN|CONFIGURATOR_ROLE)\b|"
    r"\b(?:msg\.sender|_msgSender\s*\(\s*\))\s*(?:==|!=)\s*"
    r"(?:owner|admin|governance|governor|guardian|emergencyAdmin|"
    r"pauser|controller|manager|configurator|riskAdmin)",
    re.IGNORECASE,
)
_ADMIN_DEPRECATE_NAME_RE = re.compile(
    r"(?:deprecat|disable|delist|close|freeze|shutdown|sunset|retire|"
    r"mark.*(?:Deprecated|Closed|Disabled|Frozen)|"
    r"set.*(?:Deprecated|Status|Closed|Disabled|Frozen)|"
    r"update.*(?:Deprecated|Status|Closed|Disabled|Frozen))",
    re.IGNORECASE,
)
_DEPRECATION_WRITE_RE = re.compile(
    r"\b(?:isDeprecated|marketDeprecated|deprecatedMarkets?|disabledMarkets?|"
    r"closedMarkets?|frozenMarkets?|marketStatus|statusOf)"
    r"(?:\s*\[[^\]]+\]\s*){0,3}\s*=\s*"
    r"(?:true|1|[A-Za-z_][A-Za-z0-9_]*\.(?:Deprecated|Closed|Disabled|Frozen|Paused))\b|"
    r"\bmarkets?\s*(?:\[[^\]]+\]\s*){1,3}\.\s*"
    r"(?:isDeprecated|deprecated|disabled|closed|frozen|status)\s*=\s*"
    r"(?:true|1|[A-Za-z_][A-Za-z0-9_]*\.(?:Deprecated|Closed|Disabled|Frozen|Paused))\b|"
    r"\b[A-Za-z_][A-Za-z0-9_]*\.\s*"
    r"(?:isDeprecated|deprecated|disabled|closed|frozen|status)\s*=\s*"
    r"(?:true|1|[A-Za-z_][A-Za-z0-9_]*\.(?:Deprecated|Closed|Disabled|Frozen|Paused))\b",
    re.IGNORECASE | re.DOTALL,
)
_LIQUIDATION_PAUSE_DEP_RE = re.compile(
    r"\b(?:isLiquidateBorrowPaused|liquidateBorrowPaused|liquidationsPaused|"
    r"liquidationPaused|marketPaused|borrowPaused|repayPaused)\b",
    re.IGNORECASE,
)
_LIQUIDATION_PAUSE_TRUE_RE = re.compile(
    r"\b(?:isLiquidateBorrowPaused|liquidateBorrowPaused|liquidationsPaused|"
    r"liquidationPaused|marketPaused)"
    r"(?:\s*\[[^\]]+\]\s*){0,3}\s*=\s*(?:true|1)\b|"
    r"\bmarkets?\s*(?:\[[^\]]+\]\s*){1,3}\.\s*"
    r"(?:liquidationPaused|liquidateBorrowPaused|paused)\s*=\s*(?:true|1)\b",
    re.IGNORECASE | re.DOTALL,
)
_LIQUIDATION_RELEASE_RE = re.compile(
    r"\b(?:isLiquidateBorrowPaused|liquidateBorrowPaused|liquidationsPaused|"
    r"liquidationPaused|marketPaused)"
    r"(?:\s*\[[^\]]+\]\s*){0,3}\s*=\s*(?:false|0)\b|"
    r"\bmarkets?\s*(?:\[[^\]]+\]\s*){1,3}\.\s*"
    r"(?:liquidationPaused|liquidateBorrowPaused|paused)\s*=\s*(?:false|0)\b|"
    r"\b(?:allowLiquidation|liquidationExempt|debtReductionMode|"
    r"repayDeprecated|liquidateDeprecated|closeoutException|"
    r"ignorePauseForDebt|allowBadDebtCloseout)"
    r"(?:\s*\[[^\]]+\]\s*){0,3}\s*=\s*(?:true|1)\b",
    re.IGNORECASE | re.DOTALL,
)
_LIQUIDATION_NAME_RE = re.compile(
    r"(?:liquidat|repay|repayment|closeBadDebt|settleBadDebt|writeOff|"
    r"absorb|seize|deleverage|auction|badDebt|closeout|heal)",
    re.IGNORECASE,
)
_DEBT_CONTEXT_RE = re.compile(
    r"\b(?:borrower|account|debt|badDebt|shortfall|insolvent|underwater|"
    r"collateral|healthFactor|repay|liquidat|seize|writeOff|absorb|"
    r"deleverage|auction)\b",
    re.IGNORECASE,
)
_BLOCKING_GUARD_RE = re.compile(
    r"\b(?:require|if)\s*\((?P<expr>[^;{}]*(?:isDeprecated|marketDeprecated|"
    r"deprecated|disabled|closed|frozen|paused|pause|marketStatus|"
    r"isLiquidateBorrowPaused|liquidateBorrowPaused|liquidationsPaused|"
    r"liquidationPaused|marketPaused)[^;{}]*)\)|"
    r"\b(?:_?check|_?validate|_?require|_?assert|enforce)"
    r"[A-Za-z0-9_]*(?:Deprecated|ActiveMarket|MarketActive|Pause|Paused|"
    r"Closed|Disabled|Frozen|LiquidationPaused)[A-Za-z0-9_]*\s*\(",
    re.IGNORECASE | re.DOTALL,
)
_EXCEPTION_RE = re.compile(
    r"\b(?:liquidationKeeper|keeper|liquidator|allowLiquidation|"
    r"liquidationExempt|debtReductionMode|repayDeprecated|"
    r"liquidateDeprecated|closeoutException|badDebtCloseout|"
    r"ignorePauseForDebt|ignoreDeprecatedForDebt|bypassDeprecated|"
    r"bypassPause|skipDeprecated|skipPause|allowBadDebtCloseout|"
    r"deprecatedMarketCanLiquidate)\b",
    re.IGNORECASE,
)
_RESCUE_SURFACE_RE = re.compile(
    r"\bfunction\s+(?:liquidateDeprecatedMarket|repayDeprecatedMarket|"
    r"closeDeprecatedMarketDebt|closeBadDebtDeprecated|absorbDeprecated|"
    r"settleBadDebtDeprecated|writeOffDeprecatedMarket|"
    r"forceLiquidateDeprecatedMarket|rescueDeprecatedMarketDebt|"
    r"debtReductionForDeprecatedMarket)\b",
    re.IGNORECASE,
)
_PENDING_CLAIM_ONLY_RE = re.compile(
    r"\b(?:pendingClaims?|queuedClaims?|claimable|unclaimed|"
    r"pendingWithdrawals?|queuedWithdrawals?|sweepClaims?|"
    r"rescuePendingClaims?)\b",
    re.IGNORECASE,
)


def _strip_comments_and_strings(source: str) -> str:
    def replace(match: re.Match[str]) -> str:
        text = match.group(0)
        return "\n" * text.count("\n") if "\n" in text else " "

    return _TOKEN_RE.sub(replace, source or "")


def _find_matching_delimiter(source: str, open_pos: int, open_char: str, close_char: str) -> int:
    if open_pos < 0 or open_pos >= len(source) or source[open_pos] != open_char:
        return -1
    depth = 1
    i = open_pos + 1
    while i < len(source) and depth > 0:
        char = source[i]
        if char == open_char:
            depth += 1
        elif char == close_char:
            depth -= 1
        i += 1
    return i - 1 if depth == 0 else -1


def _extract_balanced_block(source: str, open_brace: int) -> tuple[Optional[str], int]:
    close = _find_matching_delimiter(source, open_brace, "{", "}")
    if close < 0:
        return None, open_brace
    return source[open_brace + 1:close], close + 1


def _split_contracts(source: str) -> list[ContractSlice]:
    out: list[ContractSlice] = []
    pos = 0
    while True:
        match = _CONTRACT_HEADER_RE.search(source, pos)
        if not match:
            break
        open_brace = source.find("{", match.end())
        if open_brace < 0:
            pos = match.end()
            continue
        body, end_pos = _extract_balanced_block(source, open_brace)
        if body is None:
            pos = open_brace + 1
            continue
        out.append(
            ContractSlice(
                source=body,
                start_line=source.count("\n", 0, open_brace + 1) + 1,
                name=match.group("name"),
            )
        )
        pos = end_pos
    return out


def _split_functions(source: str, base_line: int = 1) -> list[FunctionSlice]:
    out: list[FunctionSlice] = []
    pos = 0
    while True:
        match = _FN_HEADER_RE.search(source, pos)
        if not match:
            break

        name = match.group("name")
        open_paren = source.find("(", match.end() - 1)
        close_paren = _find_matching_delimiter(source, open_paren, "(", ")")
        if close_paren < 0:
            pos = match.end()
            continue

        body_start = -1
        i = close_paren + 1
        while i < len(source):
            if source[i] == ";":
                break
            if source[i] == "{":
                body_start = i
                break
            i += 1
        if body_start < 0:
            pos = max(i, close_paren + 1)
            continue

        body, end_pos = _extract_balanced_block(source, body_start)
        if body is None:
            pos = body_start + 1
            continue

        out.append(
            FunctionSlice(
                name=name,
                header=source[match.start():body_start],
                body=body,
                start_line=base_line + source.count("\n", 0, match.start()),
            )
        )
        pos = end_pos
    return out


def _is_public_or_external(fn: FunctionSlice) -> bool:
    return bool(_PUBLIC_RE.search(fn.header))


def _is_callable(fn: FunctionSlice) -> bool:
    return bool(_CALLABLE_RE.search(fn.header))


def _is_skipped(fn: FunctionSlice, file_path: str) -> bool:
    return bool(_SKIP_RE.search(file_path) or _SKIP_RE.search(fn.name))


def _has_admin_deprecation_context(fn: FunctionSlice) -> bool:
    text = fn.name + "\n" + fn.header + "\n" + fn.body
    if not (_ADMIN_AUTH_RE.search(text) or _ADMIN_DEPRECATE_NAME_RE.search(fn.name)):
        return False
    return bool(_DEPRECATION_WRITE_RE.search(fn.body))


def _admin_releases_liquidation(fn: FunctionSlice) -> bool:
    return bool(_LIQUIDATION_RELEASE_RE.search(fn.body))


def _admin_depends_on_liquidation_pause(fn: FunctionSlice) -> bool:
    text = fn.name + "\n" + fn.header + "\n" + fn.body
    return bool(_LIQUIDATION_PAUSE_DEP_RE.search(text) or _LIQUIDATION_PAUSE_TRUE_RE.search(fn.body))


def _is_liquidation_rescue(fn: FunctionSlice) -> bool:
    text = fn.name + "\n" + fn.header + "\n" + fn.body
    return bool(_RESCUE_SURFACE_RE.search(text))


def _is_liquidation_surface(fn: FunctionSlice) -> bool:
    if not _is_callable(fn):
        return False
    text = fn.name + "\n" + fn.header + "\n" + fn.body
    return bool(_LIQUIDATION_NAME_RE.search(text) and _DEBT_CONTEXT_RE.search(text))


def _blocking_guard_evidence(fn: FunctionSlice) -> tuple[Optional[str], int]:
    text = fn.header + "\n" + fn.body
    if _EXCEPTION_RE.search(text):
        return None, 0

    pieces: list[str] = []
    line = fn.start_line
    for match in _BLOCKING_GUARD_RE.finditer(text):
        expr = match.groupdict().get("expr")
        evidence = expr if expr is not None else match.group(0)
        if _EXCEPTION_RE.search(evidence):
            continue
        if line == fn.start_line:
            relative = text.count("\n", 0, match.start())
            line = fn.start_line + relative
        evidence = re.sub(r"\s+", " ", evidence).strip()
        pieces.append(evidence[:120])

    if not pieces:
        return None, 0
    return "; ".join(pieces[:3]), line


def _has_pending_claim_only_context(contract: ContractSlice, functions: list[FunctionSlice]) -> bool:
    if any(_is_liquidation_surface(fn) for fn in functions):
        return False
    return bool(_PENDING_CLAIM_ONLY_RE.search(contract.source))


def _contract_has_rescue_surface(functions: list[FunctionSlice]) -> bool:
    return any(_is_liquidation_rescue(fn) for fn in functions)


def scan(source: str, file_path: str = "<unknown>") -> list[Finding]:
    clean = _strip_comments_and_strings(source)
    if not _FAST_CONTEXT_RE.search(clean):
        return []

    findings: list[Finding] = []
    contracts = _split_contracts(clean) or [ContractSlice(clean, 1, "<file>")]
    for contract in contracts:
        functions = _split_functions(contract.source, contract.start_line)
        if _has_pending_claim_only_context(contract, functions):
            continue
        if _contract_has_rescue_surface(functions):
            continue

        liquidation_blockers: list[tuple[FunctionSlice, str, int]] = []
        for fn in functions:
            if _is_skipped(fn, file_path):
                continue
            if not _is_liquidation_surface(fn):
                continue
            evidence, line = _blocking_guard_evidence(fn)
            if evidence is not None:
                liquidation_blockers.append((fn, evidence, line))

        if not liquidation_blockers:
            continue

        for fn in functions:
            if not _is_public_or_external(fn):
                continue
            if _VIEW_OR_PURE_RE.search(fn.header):
                continue
            if _is_skipped(fn, file_path):
                continue
            if not _has_admin_deprecation_context(fn):
                continue
            if not _admin_depends_on_liquidation_pause(fn):
                continue
            if _admin_releases_liquidation(fn):
                continue

            blocker_names = ", ".join(sorted({item[0].name for item in liquidation_blockers}))
            blocker_evidence = "; ".join(item[1] for item in liquidation_blockers[:2])
            findings.append(
                Finding(
                    detector=DETECTOR_NAME,
                    file=file_path,
                    line=fn.start_line,
                    severity=DETECTOR_SEVERITY_DEFAULT,
                    function=fn.name,
                    message=(
                        f"{DETECTOR_NAME}: admin market deprecation path leaves "
                        f"liquidation or debt-reduction entrypoints gated "
                        f"({blocker_names}) by deprecated or pause state without "
                        f"a liquidation-only exception. Blocking guard evidence: "
                        f"{blocker_evidence}. NOT_SUBMIT_READY."
                    ),
                )
            )
    return findings


__all__ = [
    "DETECTOR_NAME",
    "DETECTOR_SEVERITY_DEFAULT",
    "PROMOTION_ALLOWED",
    "Finding",
    "scan",
]
