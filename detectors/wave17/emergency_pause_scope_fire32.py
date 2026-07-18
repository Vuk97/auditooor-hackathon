"""
emergency-pause-scope-fire32

Fire32 Solidity detector for emergency-bypass misses where a protocol declares
global or scoped pause state, but an exit, claim, route, or settlement path
moves assets after checking the wrong scope or no pause scope.

Source records:
* reports/detector_lift_fire31_20260605/post_priorities_all.md
* detectors/wave17/emergency_asset_scope_bypass_fire31.py
* reference/patterns.dsl/reentrancy-during-pause.yaml
* reference/patterns.dsl.zellic_k2_mined/emergency-admin-can-unpause-reserves-breaking-pause-asymmetry.yaml

Detector hits are candidate evidence only. They are NOT_SUBMIT_READY and must
not be used as exploit proof without R40/R76/R80 evidence.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Optional


DETECTOR_NAME = "emergency-pause-scope-fire32"
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
    has_global_pause_state: bool
    has_scoped_pause_state: bool


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
_PUBLIC_HEADER_RE = re.compile(r"\b(?:external|public)\b", re.IGNORECASE)
_VIEW_OR_PURE_RE = re.compile(r"\b(?:view|pure)\b", re.IGNORECASE)
_SKIP_RE = re.compile(r"\b(?:mock|test|fixture|harness|example|demo)\b", re.IGNORECASE)

_GLOBAL_PAUSE_STATE_RE = re.compile(
    r"\b(?:bool|uint(?:8|16|32|64|128|256)?|bytes32)?\s*"
    r"(?:public|private|internal|external)?\s*"
    r"(?:globalPaused|protocolPaused|systemPaused|emergencyPaused|paused|"
    r"_paused|isPaused|halted|stopped|shutdown|emergencyMode)\b|"
    r"\bPausable\b",
    re.IGNORECASE,
)
_SCOPED_PAUSE_STATE_RE = re.compile(
    r"\b(?:mapping\s*\([^;]+\)|bool|uint(?:8|16|32|64|128|256)?|bytes32)"
    r"[^;{}]*(?:asset|token|reserve|market|vault|pool|route|adapter|bridge|chain)"
    r"\w*(?:Paused|Frozen|Disabled|Halted|Deprecated|Closed|Status|Emergency)|"
    r"\b(?:asset|token|reserve|market|vault|pool|route|adapter|bridge|chain)"
    r"\w*(?:Paused|Frozen|Disabled|Halted|Deprecated|Closed|Status|Emergency)\b|"
    r"\b(?:is|are)?(?:Asset|Token|Reserve|Market|Vault|Pool|Route|Adapter|Bridge|Chain)"
    r"\w*(?:Paused|Frozen|Disabled|Halted|Deprecated|Closed|Live|Active|Enabled)\b",
    re.IGNORECASE,
)
_CONTEXT_HINT_RE = re.compile(
    r"\b(?:pause|paused|Pausable|freeze|frozen|emergency|halted|disabled|"
    r"deprecated|closed|withdraw|redeem|claim|settle|route|bridge|adapter|"
    r"reserve|market|asset|token|vault)\b",
    re.IGNORECASE,
)

_EXIT_NAME_RE = re.compile(
    r"(?:withdraw|redeem|claim|collect|harvest|settle|settlement|route|"
    r"bridge|relay|dispatch|release|finalize|completeWithdrawal|processExit|"
    r"executeExit|executeRoute|executeSettlement)",
    re.IGNORECASE,
)
_ADMIN_STATE_SETTER_RE = re.compile(
    r"^(?:set|update|configure|pause|unpause|freeze|unfreeze|disable|enable|"
    r"close|open)(?:Global|Protocol|System|Asset|Token|Reserve|Market|Vault|"
    r"Pool|Route|Adapter|Bridge|Chain)?"
    r"(?:Pause|Paused|Frozen|Freeze|Disabled|Halted|Deprecated|Closed|Status|Emergency)?$",
    re.IGNORECASE,
)
_ALLOW_DURING_PAUSE_RE = re.compile(
    r"\b(?:whenPaused|onlyPaused|whenEmergency|onlyEmergencyMode|"
    r"allowWhilePaused|allowedDuringPause|ignorePause|bypassPause|"
    r"pauseExempt|emergencyExitAllowed|breakGlass)\b",
    re.IGNORECASE,
)
_GLOBAL_GUARD_RE = re.compile(
    r"\b(?:whenNotPaused|onlyWhenNotPaused|notPaused|whenGlobalNotPaused|"
    r"globalNotPaused|_requireNotPaused|requireNotPaused|notEmergency|"
    r"whenProtocolActive|protocolActive|notHalted|notShutdown)\b|"
    r"\brequire\s*\([^;{}]*(?:!\s*(?:globalPaused|protocolPaused|systemPaused|"
    r"emergencyPaused|paused|_paused|isPaused|halted|stopped|shutdown)|"
    r"(?:globalPaused|protocolPaused|systemPaused|emergencyPaused|paused|_paused|"
    r"isPaused|halted|stopped|shutdown)\s*==\s*false|"
    r"(?:globalStatus|protocolStatus|systemStatus)[^;{}]*(?:Active|Live|Enabled|Open))"
    r"[^;{}]*\)",
    re.IGNORECASE | re.DOTALL,
)
_SCOPED_GUARD_ANY_RE = re.compile(
    r"\b(?:whenAsset\w*|whenToken\w*|whenReserve\w*|whenMarket\w*|"
    r"whenVault\w*|whenPool\w*|whenRoute\w*|whenAdapter\w*|whenBridge\w*|"
    r"whenChain\w*|assetNotPaused|tokenNotPaused|reserveNotPaused|"
    r"marketNotPaused|vaultNotPaused|poolNotPaused|routeNotPaused|"
    r"adapterNotPaused|bridgeNotPaused|assetNotFrozen|reserveNotFrozen|"
    r"notFrozen|notDisabled|notDeprecated|notClosed|validateAsset\w*|"
    r"validateToken\w*|validateReserve\w*|validateMarket\w*|validateRoute\w*|"
    r"checkAsset\w*|checkReserve\w*|checkMarket\w*|checkRoute\w*|"
    r"ensureAsset\w*|ensureReserve\w*|ensureMarket\w*|ensureRoute\w*|"
    r"_validateAsset\w*|_validateReserve\w*|_validateMarket\w*|"
    r"_validateRoute\w*|_requireAsset\w*|_requireReserve\w*|"
    r"_requireMarket\w*|_requireRoute\w*)\b|"
    r"\brequire\s*\([^;{}]*(?:Paused|Frozen|Disabled|Halted|Deprecated|Closed|Status)"
    r"[^;{}]*\[[^\]]+\][^;{}]*\)",
    re.IGNORECASE | re.DOTALL,
)
_VALUE_OR_ACCOUNTING_RE = re.compile(
    r"\b(?:safeTransferFrom|safeTransfer|transferFrom|transfer|sendValue|send|"
    r"mint|burn|deposit|withdraw|redeem|claim|release|settle|bridge|relay|"
    r"dispatch|_withdraw|_redeem|_claim|_settle|_release|_bridge|_burn|_mint)"
    r"\s*\(|"
    r"\.call\s*\{\s*value\s*:|"
    r"\b(?:balances?|shares?|deposits?|reserves?|credits?|claims?|pendingClaims|"
    r"claimable|escrow|settlements?|routes?|liabilities|collateral|inventory|"
    r"totalAssets|totalSupply|assetBalance|bridgeBalance|settled)"
    r"(?:\s*\[[^\]]+\]\s*){0,3}"
    r"(?:\.\s*[A-Za-z_][A-Za-z0-9_]*\s*)?"
    r"\s*(?:[+\-*/]?=|\+\+|--)",
    re.IGNORECASE,
)
_PARAM_LIST_RE = re.compile(r"\((?P<params>[^)]*)\)", re.DOTALL)
_PARAM_DECL_RE = re.compile(
    r"\b(?:address|bytes32|string|uint(?:8|16|32|64|128|256)?|"
    r"int(?:8|16|32|64|128|256)?|[A-Za-z_][A-Za-z0-9_]*)"
    r"(?:\s*\[\s*\])?\s+"
    r"(?:calldata\s+|memory\s+|storage\s+)?"
    r"(?P<name>[A-Za-z_][A-Za-z0-9_]*)\b",
    re.IGNORECASE,
)
_SCOPE_PARAM_NAME_RE = re.compile(
    r"(?:asset|token|underlying|collateral|reserve|market|vault|pool|route|"
    r"path|adapter|bridge|srcChain|dstChain|chainId|sourceChain|destinationChain|"
    r"settlement)",
    re.IGNORECASE,
)
_IGNORED_PARAM_RE = re.compile(
    r"^(?:amount|value|shares|assets|balance|receiver|recipient|to|from|owner|"
    r"spender|operator|account|user|caller|borrower|payer|deadline|nonce|"
    r"signature|data|proof|payload|index|id)$",
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
                has_global_pause_state=bool(_GLOBAL_PAUSE_STATE_RE.search(body)),
                has_scoped_pause_state=bool(_SCOPED_PAUSE_STATE_RE.search(body)),
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

        header = source[match.start():body_start]
        out.append(
            FunctionSlice(
                name=name,
                header=header,
                body=body,
                start_line=base_line + source.count("\n", 0, match.start()),
            )
        )
        pos = end_pos
    return out


def _is_public(fn: FunctionSlice) -> bool:
    return bool(_PUBLIC_HEADER_RE.search(fn.header))


def _is_skipped(fn: FunctionSlice, file_path: str) -> bool:
    return bool(_SKIP_RE.search(file_path) or _SKIP_RE.search(fn.name))


def _is_exit_path(fn: FunctionSlice) -> bool:
    return bool(_EXIT_NAME_RE.search(fn.name))


def _is_admin_state_setter(fn: FunctionSlice) -> bool:
    return bool(_ADMIN_STATE_SETTER_RE.search(fn.name))


def _has_global_guard(fn: FunctionSlice) -> bool:
    return bool(_GLOBAL_GUARD_RE.search(fn.header + "\n" + fn.body))


def _has_scoped_guard(fn: FunctionSlice) -> bool:
    return bool(_SCOPED_GUARD_ANY_RE.search(fn.header + "\n" + fn.body))


def _moves_value_or_accounting(fn: FunctionSlice) -> bool:
    return bool(_VALUE_OR_ACCOUNTING_RE.search(fn.name + "\n" + fn.body))


def _scoped_params(fn: FunctionSlice) -> list[str]:
    params = _PARAM_LIST_RE.search(fn.header)
    if not params:
        return []
    out: list[str] = []
    text = fn.name + "\n" + fn.body
    for match in _PARAM_DECL_RE.finditer(params.group("params")):
        name = match.group("name")
        if _IGNORED_PARAM_RE.search(name):
            continue
        if not _SCOPE_PARAM_NAME_RE.search(name):
            continue
        if not re.search(rf"\b{re.escape(name)}\b", text):
            continue
        if name not in out:
            out.append(name)
    return out


def _guard_covers_param(fn: FunctionSlice, param: str) -> bool:
    text = fn.header + "\n" + fn.body
    name = re.escape(param)
    patterns = [
        rf"\b(?:when|only|not|validate|check|ensure|require)[A-Za-z0-9_]*"
        rf"(?:Active|Live|Open|Enabled|NotPaused|NotFrozen|NotDisabled|"
        rf"NotDeprecated|NotClosed|Paused|Frozen|Disabled|Deprecated|Closed)"
        rf"[A-Za-z0-9_]*\s*\(\s*{name}\s*\)",
        rf"\b_?(?:require|validate|check|ensure)[A-Za-z0-9_]*\s*\(\s*{name}\s*\)",
        rf"\brequire\s*\([^;{{}}]*(?:!\s*[A-Za-z0-9_\.]*"
        rf"(?:Paused|paused|Frozen|frozen|Disabled|disabled|Deprecated|deprecated|"
        rf"Halted|halted|Closed|closed)\s*\[\s*{name}\s*\]|"
        rf"[A-Za-z0-9_\.]*(?:Paused|paused|Frozen|frozen|Disabled|disabled|"
        rf"Deprecated|deprecated|Halted|halted|Closed|closed)\s*\[\s*{name}\s*\]"
        rf"\s*==\s*false|"
        rf"!\s*[A-Za-z0-9_\.]+\s*\[\s*{name}\s*\]\s*\.\s*"
        rf"(?:paused|frozen|disabled|deprecated|halted|closed)|"
        rf"[A-Za-z0-9_\.]+\s*\[\s*{name}\s*\]\s*\.\s*"
        rf"(?:paused|frozen|disabled|deprecated|halted|closed)\s*==\s*false|"
        rf"[A-Za-z0-9_\.]*(?:Status|status)\s*\[\s*{name}\s*\]"
        rf"[^;{{}}]*(?:Active|Live|Open|Enabled))[^;{{}}]*\)",
    ]
    return any(re.search(pattern, text, re.IGNORECASE | re.DOTALL) for pattern in patterns)


def _candidate_branch(fn: FunctionSlice, contract: ContractSlice) -> str | None:
    if not (contract.has_global_pause_state or contract.has_scoped_pause_state):
        return None
    if not _is_exit_path(fn):
        return None
    if _is_admin_state_setter(fn):
        return None
    if _VIEW_OR_PURE_RE.search(fn.header):
        return None
    if _ALLOW_DURING_PAUSE_RE.search(fn.header + "\n" + fn.body):
        return None
    if not _moves_value_or_accounting(fn):
        return None

    scoped_params = _scoped_params(fn)
    has_global_guard = _has_global_guard(fn)
    has_scoped_guard = _has_scoped_guard(fn)
    uncovered = [param for param in scoped_params if not _guard_covers_param(fn, param)]

    if contract.has_scoped_pause_state and scoped_params and uncovered:
        if has_scoped_guard and len(uncovered) < len(scoped_params):
            return "exit-path-wrong-scoped-pause-check"
        if has_global_guard:
            return "exit-path-global-pause-only"
        return "exit-path-no-pause-scope"

    if contract.has_global_pause_state and not has_global_guard and not has_scoped_guard:
        return "exit-path-no-pause-scope"

    return None


def scan(source: str, file_path: str = "<unknown>") -> list[Finding]:
    clean = _strip_comments_and_strings(source)
    if not _CONTEXT_HINT_RE.search(clean):
        return []

    findings: list[Finding] = []
    contracts = _split_contracts(clean) or [
        ContractSlice(
            clean,
            1,
            bool(_GLOBAL_PAUSE_STATE_RE.search(clean)),
            bool(_SCOPED_PAUSE_STATE_RE.search(clean)),
        )
    ]
    for contract in contracts:
        if not (contract.has_global_pause_state or contract.has_scoped_pause_state):
            continue
        for fn in _split_functions(contract.source, contract.start_line):
            if not _is_public(fn):
                continue
            if _is_skipped(fn, file_path):
                continue
            branch = _candidate_branch(fn, contract)
            if branch is None:
                continue
            findings.append(
                Finding(
                    detector=DETECTOR_NAME,
                    file=file_path,
                    line=fn.start_line,
                    severity=DETECTOR_SEVERITY_DEFAULT,
                    function=fn.name,
                    message=(
                        f"{DETECTOR_NAME}: branch {branch}: exit, claim, route, "
                        "or settlement path moves assets while declared global or "
                        "scoped pause state is unchecked or checked against the "
                        "wrong scope. NOT_SUBMIT_READY."
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
