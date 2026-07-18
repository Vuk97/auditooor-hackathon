"""
emergency-asset-scope-bypass-fire31

Fire31 Solidity detector for emergency-bypass misses where a global pause,
freeze, or emergency gate is checked, but the asset, reserve, adapter, bridge,
or route-specific emergency state remains unchecked on a value-moving path.

Source records:
* reports/detector_lift_fire30_20260605/post_priorities_all.md
* detectors/wave17/emergency_unpause_bypass_fire29.py
* reference/patterns.dsl/reentrancy-during-pause.yaml
* reference/patterns.dsl.zellic_k2_mined/collateral-can-be-enabled-despite-pause-freeze-or-invalid-pricing.yaml
* reference/patterns.dsl.r94_kelp_rseth_deep/destination-adapter-does-not-pause-on-source-side-pause-event.yaml

Detector hits are candidate evidence only. They are NOT_SUBMIT_READY and must
not be used as exploit proof without R40/R76/R80 evidence.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Optional


DETECTOR_NAME = "emergency-asset-scope-bypass-fire31"
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
_SKIP_RE = re.compile(r"\b(?:mock|test|fixture|harness|example|demo)\b", re.IGNORECASE)

_CONTEXT_HINT_RE = re.compile(
    r"\b(?:pause|paused|Pausable|freeze|frozen|emergency|halted|disabled|"
    r"asset|token|reserve|market|adapter|bridge|route|collateral)\b",
    re.IGNORECASE,
)
_SCOPED_STATE_RE = re.compile(
    r"\b(?:asset|token|reserve|market|collateral|adapter|bridge|route|chain)"
    r"\w*(?:Paused|Frozen|Disabled|Halted|Deprecated|Emergency|Status)|"
    r"\b(?:is|are)?(?:Asset|Token|Reserve|Market|Collateral|Adapter|Bridge|Route|Chain)"
    r"\w*(?:Paused|Frozen|Disabled|Halted|Deprecated|Live|Active|Enabled)|"
    r"\bmapping\s*\([^;]+\)[^;]*(?:asset|token|reserve|market|collateral|adapter|bridge|route|chain)"
    r"[^;]*(?:paused|frozen|disabled|halted|deprecated|status|emergency)",
    re.IGNORECASE,
)
_GLOBAL_GUARD_RE = re.compile(
    r"\b(?:whenNotPaused|onlyWhenNotPaused|notPaused|whenGlobalNotPaused|"
    r"globalNotPaused|_requireNotPaused|requireNotPaused|notEmergency|"
    r"whenProtocolActive|protocolActive|notHalted)\b|"
    r"\brequire\s*\([^;{}]*(?:!\s*(?:globalPaused|protocolPaused|systemPaused|"
    r"paused|emergencyPaused|halted)|(?:globalPaused|protocolPaused|systemPaused|"
    r"paused|emergencyPaused|halted)\s*==\s*false|(?:globalStatus|protocolStatus)"
    r"[^;{}]*(?:Active|Live|Enabled))[^;{}]*\)",
    re.IGNORECASE | re.DOTALL,
)
_SCOPED_GUARD_RE = re.compile(
    r"\b(?:whenAssetLive|whenAssetActive|whenReserveLive|whenReserveActive|"
    r"whenMarketLive|whenMarketActive|whenAdapterLive|whenAdapterActive|"
    r"whenBridgeLive|whenRouteLive|assetNotPaused|reserveNotPaused|"
    r"marketNotPaused|adapterNotPaused|bridgeNotPaused|routeNotPaused|"
    r"assetNotFrozen|reserveNotFrozen|notFrozen|notDisabled|notDeprecated|"
    r"validateAsset\w*|validateReserve\w*|validateMarket\w*|"
    r"validateAdapter\w*|validateBridge\w*|validateRoute\w*|"
    r"checkAsset\w*|checkReserve\w*|checkMarket\w*|checkAdapter\w*|"
    r"checkBridge\w*|checkRoute\w*|ensureAsset\w*|ensureReserve\w*|"
    r"ensureMarket\w*|ensureAdapter\w*|ensureRoute\w*|_checkAsset\w*|"
    r"_checkReserve\w*|_validateAsset\w*|_validateReserve\w*|"
    r"_requireAsset\w*|_requireReserve\w*)\b|"
    r"\brequire\s*\([^;{}]*(?:!\s*(?:asset|token|reserve|market|collateral|"
    r"adapter|bridge|route|chain)\w*(?:Paused|Frozen|Disabled|Halted|Deprecated)"
    r"\s*\[[^\]]+\]|(?:asset|token|reserve|market|collateral|adapter|bridge|route|chain)"
    r"\w*(?:Paused|Frozen|Disabled|Halted|Deprecated)\s*\[[^\]]+\]\s*==\s*false|"
    r"(?:asset|token|reserve|market|collateral|adapter|bridge|route|chain)"
    r"\w*Status\s*\[[^\]]+\][^;{}]*(?:Active|Live|Enabled)|"
    r"price[^;{}]*(?:valid|fresh)|oracle[^;{}]*(?:valid|fresh))[^;{}]*\)",
    re.IGNORECASE | re.DOTALL,
)
_SCOPED_PARAM_RE = re.compile(
    r"\((?P<params>[^)]*)\)",
    re.DOTALL,
)
_SCOPED_PARAM_NAME_RE = re.compile(
    r"\b(?:address|uint(?:8|16|32|64|128|256)?|bytes32|string)\s+"
    r"(?:calldata\s+|memory\s+|storage\s+)?"
    r"(?:asset|token|reserve|market|collateral|adapter|bridge|route|srcChain|"
    r"dstChain|chainId|sourceChain|destinationChain)\w*\b",
    re.IGNORECASE,
)
_SCOPED_BODY_RE = re.compile(
    r"\b(?:asset|token|reserve|market|collateral|adapter|bridge|route|"
    r"sourceChain|destinationChain|chainId)\w*\b",
    re.IGNORECASE,
)
_VALUE_OR_ACCOUNTING_RE = re.compile(
    r"\b(?:safeTransferFrom|safeTransfer|transferFrom|transfer|sendValue|send|"
    r"mint|burn|deposit|withdraw|redeem|bridge|sendMessage|release|creditTo|"
    r"_creditTo|debitFrom|_debitFrom|lock|unlock)\s*\(|"
    r"\.call\s*\{\s*value\s*:|"
    r"\b(?:balances?|shares?|deposits?|reserves?|credits?|debts?|liabilities|"
    r"collateral|inventory|totalAssets|totalSupply|adapterBalance|bridgeBalance)"
    r"(?:\s*\[[^\]]+\]\s*)?\s*(?:[+\-*/]?=|\+\+|--)",
    re.IGNORECASE,
)
_COLLATERAL_ENABLE_RE = re.compile(
    r"\b(?:enableCollateral|setUseReserveAsCollateral|setUserUseReserveAsCollateral|"
    r"useReserveAsCollateral|activateCollateral|enableAsset|enableReserve)\b|"
    r"\b(?:collateralEnabled|useAsCollateral|isCollateral|userConfig|"
    r"userConfiguration|assetEnabled|reserveEnabled)"
    r"(?:\s*\[[^\]]+\]\s*){1,2}(?:\.\s*[A-Za-z_][A-Za-z0-9_]*\s*)?"
    r"\s*=\s*(?:true|enabled)",
    re.IGNORECASE,
)
_BRIDGE_ADAPTER_NAME_RE = re.compile(
    r"(?:bridge|adapter|route|lzReceive|receiveMessage|processInbound|"
    r"handleInbound|release|creditTo|sendTo|sendMessage|dispatch|relay)",
    re.IGNORECASE,
)
_ADMIN_STATE_SETTER_RE = re.compile(
    r"^(?:set|update|configure|pause|unpause|freeze|unfreeze|disable|enable)"
    r"(?:Asset|Token|Reserve|Market|Adapter|Bridge|Route|Chain)?"
    r"(?:Pause|Paused|Frozen|Freeze|Disabled|Halted|Deprecated|Status|Emergency)$",
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


def _has_scoped_param(fn: FunctionSlice) -> bool:
    params = _SCOPED_PARAM_RE.search(fn.header)
    return bool(params and _SCOPED_PARAM_NAME_RE.search(params.group("params")))


def _has_global_guard(fn: FunctionSlice) -> bool:
    return bool(_GLOBAL_GUARD_RE.search(fn.header + "\n" + fn.body))


def _has_scoped_guard(fn: FunctionSlice) -> bool:
    return bool(_SCOPED_GUARD_RE.search(fn.header + "\n" + fn.body))


def _touches_scoped_surface(fn: FunctionSlice) -> bool:
    return _has_scoped_param(fn) and bool(_SCOPED_BODY_RE.search(fn.name + "\n" + fn.body))


def _moves_value_or_accounting(fn: FunctionSlice) -> bool:
    return bool(_VALUE_OR_ACCOUNTING_RE.search(fn.name + "\n" + fn.body))


def _collateral_enable_branch(fn: FunctionSlice) -> str | None:
    if not _COLLATERAL_ENABLE_RE.search(fn.name + "\n" + fn.body):
        return None
    if not _touches_scoped_surface(fn):
        return None
    return "collateral-or-asset-enable-global-only"


def _bridge_adapter_branch(fn: FunctionSlice) -> str | None:
    text = fn.name + "\n" + fn.header + "\n" + fn.body
    if not _BRIDGE_ADAPTER_NAME_RE.search(text):
        return None
    if not _touches_scoped_surface(fn):
        return None
    if not _moves_value_or_accounting(fn):
        return None
    return "bridge-or-adapter-global-pause-only"


def _asset_motion_branch(fn: FunctionSlice) -> str | None:
    if _ADMIN_STATE_SETTER_RE.search(fn.name):
        return None
    if not _touches_scoped_surface(fn):
        return None
    if not _moves_value_or_accounting(fn):
        return None
    return "asset-or-reserve-value-path-global-only"


def _candidate_branch(fn: FunctionSlice) -> str | None:
    if not _has_global_guard(fn):
        return None
    if _has_scoped_guard(fn):
        return None

    for branch_fn in (
        _bridge_adapter_branch,
        _collateral_enable_branch,
        _asset_motion_branch,
    ):
        branch = branch_fn(fn)
        if branch is not None:
            return branch
    return None


def scan(source: str, file_path: str = "<unknown>") -> list[Finding]:
    clean = _strip_comments_and_strings(source)
    if not _CONTEXT_HINT_RE.search(clean):
        return []

    findings: list[Finding] = []
    contracts = _split_contracts(clean) or [ContractSlice(clean, 1)]
    for contract in contracts:
        if not _SCOPED_STATE_RE.search(contract.source):
            continue
        for fn in _split_functions(contract.source, contract.start_line):
            if not _is_public(fn):
                continue
            if _is_skipped(fn, file_path):
                continue
            branch = _candidate_branch(fn)
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
                        f"{DETECTOR_NAME}: branch {branch}: function checks "
                        "only a global pause, freeze, or emergency gate while "
                        "asset, reserve, adapter, bridge, or route-specific "
                        "emergency state remains unchecked. NOT_SUBMIT_READY."
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
