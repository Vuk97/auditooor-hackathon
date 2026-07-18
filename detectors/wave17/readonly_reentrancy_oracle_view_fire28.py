"""
readonly-reentrancy-oracle-view-fire28

Solidity regex API detector for price, oracle, getRate, and virtualPrice style
view functions that read live external pool or vault state while lacking a
read-only reentrancy mitigation. The lifted shape is a view oracle reading
Balancer Vault pool tokens, Curve virtual price or balances, pair reserves, or
vault rates that may be observable during a pool or vault callback.

Provenance:
- context_pack_id: auditooor.vault_context_pack.v1:resume:86c2076101171056
- context_pack_hash: 86c2076101171056d88e0073a7354a1cf2324d92f13627249a1c5ece0c70b722
- source ref: reference/patterns.dsl.r94_solodit_reentrancy/balancerpairoracle-read-only-reentrancy-no-vault-guard.yaml
- source ref: reference/patterns.dsl.r94_solodit_reentrancy/wsteth-eth-curve-lp-price-manipulable-via-readonly-reentrancy.yaml
- attack_class: reentrancy-cross-contract

Hits are candidate evidence only. NOT_SUBMIT_READY.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Optional


DETECTOR_NAME = "readonly-reentrancy-oracle-view-fire28"
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
    line: int


_COMMENT_OR_STRING_RE = re.compile(
    r'"(?:[^"\\]|\\.)*"|'
    r"'(?:[^'\\]|\\.)*'|"
    r"//[^\n\r]*|"
    r"/\*.*?\*/",
    re.DOTALL,
)
_FN_HEADER_RE = re.compile(r"\bfunction\s+(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*\(")
_CALLABLE_VIEW_RE = re.compile(
    r"(?is)\b(?:external|public)\b(?=[^{};]*\bview\b)|\bview\b(?=[^{};]*\b(?:external|public)\b)"
)
_PURE_RE = re.compile(r"\bpure\b")
_PRICING_NAME_RE = re.compile(
    r"(?i)(?:price|oracle|quote|rate|virtual|valuation|value|health|"
    r"collateral|liquidat|lp)"
)
_PRICING_BODY_RE = re.compile(
    r"(?is)\b(?:price|oracle|quote|rate|virtual|valuation|value|health|"
    r"collateral|liquidat|lp|reserve|pool|vault|curve|balancer)\b"
)
_POOLISH_RECEIVER_RE = re.compile(
    r"(?i)(?:pool|vault|pair|curve|balancer|amm|reserve|market|lp|stable|rateProvider)"
)
_RAW_POOL_READ_RE = re.compile(
    r"(?is)\b(?P<receiver>[A-Za-z_][A-Za-z0-9_]*)\s*\.\s*"
    r"(?P<call>"
    r"getPoolTokens|"
    r"get_virtual_price|"
    r"getVirtualPrice|"
    r"virtualPrice|"
    r"price_oracle|"
    r"get_dy|"
    r"balances|"
    r"getReserves|"
    r"reserve0|"
    r"reserve1|"
    r"getRate|"
    r"exchangeRate|"
    r"getExchangeRate|"
    r"storedRate|"
    r"totalAssets|"
    r"convertToAssets|"
    r"convertToShares|"
    r"previewRedeem|"
    r"previewWithdraw|"
    r"previewDeposit|"
    r"previewMint"
    r")\s*\("
)
_HIGH_SIGNAL_READ_RE = re.compile(
    r"(?is)\.\s*(?:getPoolTokens|get_virtual_price|getVirtualPrice|"
    r"price_oracle|get_dy|balances|getReserves)\s*\("
)
_READ_ONLY_REENTRANCY_GUARD_RE = re.compile(
    r"(?is)"
    r"\b(?:nonReentrant|noReentrant|noReentry|noReentrancy|"
    r"reentrancyGuard|reentrancyLock|vaultReentrancyGuard|"
    r"checkReentrancy|check_reentrancy_lock|checkReadOnlyReentrancy|"
    r"checkVaultReentrancy|ensureNotInVaultContext|assertNotInVaultContext|"
    r"ensureNotReentrant|_checkVaultReentrancy|_ensureNotInVaultContext)\b"
    r"|"
    r"\b(?:remove_liquidity|removeLiquidity)\s*\(\s*0\s*,"
    r"|"
    r"\bclaim_admin_fees\s*\("
    r"|"
    r"\bmanageUserBalance\s*\("
)
_CACHE_BLOCK_RE = re.compile(
    r"(?is)\bblock\s*\.\s*number\b[\s\S]{0,240}"
    r"\b(?:cached|cache|last|stored)[A-Za-z0-9_]*(?:Price|Rate|Value|Block|Update)\b"
    r"|"
    r"\b(?:cached|cache|last|stored)[A-Za-z0-9_]*(?:Price|Rate|Value|Block|Update)\b"
    r"[\s\S]{0,240}\bblock\s*\.\s*number\b"
)
_TWAP_SAFE_RE = re.compile(
    r"(?is)\b(?:twap|timeWeighted|timeWeightedAverage|movingAverage|"
    r"observe\s*\(|consult\s*\(|priceCumulative|cumulativePrice|"
    r"cumulativeTick|secondsAgo|OracleLibrary|weightedAverage)\b"
)
_OBVIOUS_TEST_PATH_RE = re.compile(r"(?i)(?:^|/)(?:test|tests|mock|mocks|fixtures?)(?:/|$)")


def _strip_comments_and_strings(source: str) -> str:
    def replace(match: re.Match[str]) -> str:
        text = match.group(0)
        return "\n" * text.count("\n") if "\n" in text else " "

    return _COMMENT_OR_STRING_RE.sub(replace, source or "")


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
        if match is None:
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
            pos = max(i, j)
            continue

        body, end_pos = _extract_balanced_block(source, body_start)
        if body is None:
            pos = body_start + 1
            continue

        header = source[match.start():body_start]
        line = source.count("\n", 0, match.start()) + 1
        out.append(FunctionSlice(name=name, header=header, body=body, line=line))
        pos = end_pos
    return out


def _is_public_or_external_view(fn: FunctionSlice) -> bool:
    if _PURE_RE.search(fn.header):
        return False
    return bool(_CALLABLE_VIEW_RE.search(fn.header))


def _has_pricing_context(fn: FunctionSlice) -> bool:
    return bool(_PRICING_NAME_RE.search(fn.name) or _PRICING_BODY_RE.search(fn.body))


def _has_read_only_reentrancy_mitigation(fn: FunctionSlice) -> bool:
    text = f"{fn.header}\n{fn.body}"
    if _READ_ONLY_REENTRANCY_GUARD_RE.search(text):
        return True
    if _CACHE_BLOCK_RE.search(text):
        return True
    return bool(_TWAP_SAFE_RE.search(text))


def _is_relevant_raw_read(match: re.Match[str], body: str) -> bool:
    call = match.group("call")
    receiver = match.group("receiver")
    if _HIGH_SIGNAL_READ_RE.search(match.group(0)):
        return True
    if _POOLISH_RECEIVER_RE.search(receiver):
        return True
    if call in {"getRate", "exchangeRate", "getExchangeRate", "storedRate"}:
        return bool(_POOLISH_RECEIVER_RE.search(body))
    return False


def _first_raw_pool_read(fn: FunctionSlice) -> tuple[int, str] | None:
    for match in _RAW_POOL_READ_RE.finditer(fn.body):
        if not _is_relevant_raw_read(match, fn.body):
            continue
        line = fn.line + fn.body.count("\n", 0, match.start())
        return line, f"{match.group('receiver')}.{match.group('call')}()"
    return None


def _match_function(fn: FunctionSlice) -> tuple[int, str] | None:
    if not _is_public_or_external_view(fn):
        return None
    if not _has_pricing_context(fn):
        return None
    if _has_read_only_reentrancy_mitigation(fn):
        return None
    return _first_raw_pool_read(fn)


def scan(source: str, file_path: str = "<unknown>") -> list[Finding]:
    findings: list[Finding] = []
    if _OBVIOUS_TEST_PATH_RE.search(file_path):
        return findings
    if not re.search(r"(?is)(?:price|oracle|rate|virtual|pool|vault|reserve|curve|balancer)", source or ""):
        return findings

    clean_source = _strip_comments_and_strings(source)
    functions = _split_functions(clean_source)

    for fn in functions:
        matched = _match_function(fn)
        if matched is None:
            continue
        line, read_call = matched
        findings.append(
            Finding(
                detector=DETECTOR_NAME,
                file=file_path,
                line=line,
                severity=DETECTOR_SEVERITY_DEFAULT,
                function=fn.name,
                message=(
                    f"`{fn.name}` is a pricing view that reads live external "
                    f"pool or vault state via `{read_call}` without a read-only "
                    "reentrancy mitigation. Add a vault or pool reentrancy "
                    "probe, use a same-block cache, or price through a "
                    "non-manipulable TWAP or cumulative oracle path."
                ),
            )
        )
    return findings


__all__ = ["scan", "Finding", "DETECTOR_NAME", "DETECTOR_SEVERITY_DEFAULT"]
