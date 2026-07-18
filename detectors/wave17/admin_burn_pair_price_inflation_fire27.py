"""
admin-burn-pair-price-inflation-fire27

Solidity recall-lift detector for admin-controlled token burns or balance
reductions that target AMM pair, pool, or reserve addresses. The dangerous
shape lets a privileged path shrink the pair-held token reserve and inflate
spot price or reserve accounting without binding the target to an authorized
router, pair, factory, or pool-domain allowlist.

Provenance:
- context_pack_id: auditooor.vault_context_pack.v1:resume:5a4dc5fcabec4193
- context_pack_hash: 5a4dc5fcabec419385f40cc3f83d3a24f63a01e0d5c301ab1ef08763094a3fe5
- source ref: burn-on-transfer-to-pair-inflates-price
- source ref: abi-encode-packed-hash-collision
- source ref: ccip-receiver-and-chain-unvalidated
- attack_class: admin-bypass

Hits are candidate evidence only. NOT_SUBMIT_READY.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Optional


DETECTOR_NAME = "admin-burn-pair-price-inflation-fire27"
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
_CALLABLE_HEADER_RE = re.compile(r"\b(?:external|public|internal|private)\b")
_VIEW_HEADER_RE = re.compile(r"\b(?:view|pure)\b")

_PAIR_WORD = (
    r"(?:pair|lpPair|ammPair|pool|ammPool|dexPool|reserve|reserveAddress|"
    r"uniswapV2Pair|pancakePair|sushiPair|camelotPair|curvePool)"
)
_PAIR_CONTEXT_RE = re.compile(
    rf"(?is)\b(?:{_PAIR_WORD}|router|factory|getPair|pairFor|getReserves|"
    rf"sync|skim|token0|token1|IUniswapV2Pair|IPair|IPool|IReserve)\b"
)
_PAIR_PARAM_RE = re.compile(
    rf"(?is)\baddress(?:\s+payable)?\s+(?P<name>[A-Za-z_]*{_PAIR_WORD}[A-Za-z0-9_]*)\b"
)
_PAIR_IDENTIFIER_RE = re.compile(rf"(?is)\b[A-Za-z_]*{_PAIR_WORD}[A-Za-z0-9_]*\b")

_PRIVILEGED_CONTEXT_RE = re.compile(
    r"(?is)(?:"
    r"\b(?:onlyOwner|onlyAdmin|onlyRole|onlyRoles|onlyGovernance|onlyGovernor|"
    r"onlyOperator|onlyManager|onlyController|onlyKeeper|requiresAuth|"
    r"requireAuth|restricted|auth)\b|"
    r"\b(?:_checkRole|_checkOwner|isOwner|isAdmin|hasRole)\s*\(|"
    r"\brequire\s*\([^;{}]*(?:msg\.sender|_msgSender\s*\(\s*\))"
    r"[^;{}]*(?:owner|admin|governance|governor|controller|manager|operator|keeper)|"
    r"\brequire\s*\([^;{}]*(?:owner|admin|governance|governor|controller|manager|operator|keeper)"
    r"[^;{}]*(?:msg\.sender|_msgSender\s*\(\s*\))|"
    r"\b(?:owner|admin|governance|governor|controller|manager|operator|keeper)"
    r"[A-Za-z0-9_]*\b"
    r")"
)
_ADMIN_FUNCTION_NAME_RE = re.compile(
    r"(?i)(admin|owner|govern|manager|operator|controller|keeper)"
)

_PAIR_BURN_PATTERNS = [
    re.compile(rf"(?is)\b_burn\s*\(\s*(?P<target>[A-Za-z_]*{_PAIR_WORD}[A-Za-z0-9_]*)\s*,"),
    re.compile(rf"(?is)\bburnFrom\s*\(\s*(?P<target>[A-Za-z_]*{_PAIR_WORD}[A-Za-z0-9_]*)\s*,"),
    re.compile(rf"(?is)\bburn\s*\(\s*(?P<target>[A-Za-z_]*{_PAIR_WORD}[A-Za-z0-9_]*)\s*,"),
    re.compile(
        rf"(?is)\b(?:_balances|balances|balanceOf)\s*\[\s*"
        rf"(?P<target>[A-Za-z_]*{_PAIR_WORD}[A-Za-z0-9_]*)\s*\]\s*(?:-=|=)"
    ),
    re.compile(
        rf"(?is)\b(?:reduceBalance|slashBalance|decreaseBalance|confiscateBalance)"
        rf"\s*\(\s*(?P<target>[A-Za-z_]*{_PAIR_WORD}[A-Za-z0-9_]*)\s*,"
    ),
]
_TRANSFER_TO_PAIR_BURN_RE = re.compile(
    rf"(?is)\b(?:to|recipient|receiver)\s*==\s*(?:[A-Za-z_]*{_PAIR_WORD}[A-Za-z0-9_]*)"
    rf"[^{{}};]*(?:_burn|burn|deadAddress|address\s*\(\s*0\s*\)|"
    rf"(?:_balances|balances|balanceOf)\s*\[\s*(?:to|recipient|receiver)\s*\]\s*(?:-=|=))"
)
_SUPPLY_OR_SYNC_EFFECT_RE = re.compile(
    r"(?is)(?:"
    r"\b(?:totalSupply|_totalSupply)\s*(?:-=|=)|"
    r"\b(?:sync|skim)\s*\(|"
    r"\bI[A-Za-z0-9_]*(?:Pair|Pool)\s*\([^;{}]+\)\s*\.\s*(?:sync|skim)\s*\("
    r")"
)
_STATE_DECREASE_RE = re.compile(r"(?is)(?:-=|-\s*amount|-\s*burnAmount|-\s*burned|-\s*delta)")

_POOL_DOMAIN_GUARD_RE = re.compile(
    rf"(?is)(?:"
    rf"\brequire\s*\([^;{{}}]*(?:approved|allowed|trusted|registered|known|valid|enabled|is)"
    rf"[A-Za-z0-9_]*(?:Pairs?|Pools?|Reserves?)\s*\[\s*(?:[A-Za-z_]*{_PAIR_WORD}[A-Za-z0-9_]*)\s*\]|"
    rf"\brequire\s*\([^;{{}}]*(?:[A-Za-z_]*{_PAIR_WORD}[A-Za-z0-9_]*)"
    rf"[^;{{}}]*(?:==|!=)[^;{{}}]*(?:factory|getPair|pairFor|poolFor|trustedPair|trustedPool|canonicalPair|canonicalPool)|"
    rf"\brequire\s*\([^;{{}}]*(?:factory|getPair|pairFor|poolFor|trustedPair|trustedPool|canonicalPair|canonicalPool)"
    rf"[^;{{}}]*(?:==|!=)[^;{{}}]*(?:[A-Za-z_]*{_PAIR_WORD}[A-Za-z0-9_]*)|"
    rf"\brequire\s*\([^;{{}}]*(?:token0|token1)\s*\(\s*\)[^;{{}}]*address\s*\(\s*this\s*\)|"
    rf"\brequire\s*\([^;{{}}]*address\s*\(\s*this\s*\)[^;{{}}]*(?:token0|token1)\s*\(\s*\)|"
    rf"\brequire\s*\([^;{{}}]*(?:msg\.sender|_msgSender\s*\(\s*\))"
    rf"[^;{{}}]*(?:router|pair|pool|ammPair|lpPair)|"
    rf"\brequire\s*\([^;{{}}]*(?:router|pair|pool|ammPair|lpPair)"
    rf"[^;{{}}]*(?:msg\.sender|_msgSender\s*\(\s*\))|"
    rf"\b(?:onlyRouter|onlyPair|onlyPool|onlyAmm|onlyAMM|onlyPairManager|onlyPoolManager)\b|"
    rf"\b(?:_validatePair|validatePair|_validatePool|validatePool|_checkPair|_checkPool)"
    rf"\s*\(\s*(?:[A-Za-z_]*{_PAIR_WORD}[A-Za-z0-9_]*)\s*\)"
    rf")"
)
_BENIGN_SELF_BURN_RE = re.compile(
    r"(?is)(?:_burn\s*\(\s*(?:msg\.sender|_msgSender\s*\(\s*\)|from|account)\s*,|"
    r"(?:_balances|balances|balanceOf)\s*\[\s*(?:msg\.sender|_msgSender\s*\(\s*\)|from|account)\s*\]\s*(?:-=|=))"
)


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
        if source[i] == "{":
            depth += 1
        elif source[i] == "}":
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


def _is_callable_mutator(fn: FunctionSlice) -> bool:
    return bool(_CALLABLE_HEADER_RE.search(fn.header)) and not _VIEW_HEADER_RE.search(fn.header)


def _is_privileged_context(fn: FunctionSlice) -> bool:
    text = f"{fn.name}\n{fn.header}\n{fn.body}"
    return bool(_PRIVILEGED_CONTEXT_RE.search(text) or _ADMIN_FUNCTION_NAME_RE.search(fn.name))


def _pair_param_names(header: str) -> set[str]:
    return {match.group("name") for match in _PAIR_PARAM_RE.finditer(header)}


def _has_pair_targeted_burn(fn: FunctionSlice) -> bool:
    body = fn.body
    for pattern in _PAIR_BURN_PATTERNS:
        match = pattern.search(body)
        if match is None:
            continue
        target = match.groupdict().get("target") or ""
        if target and _PAIR_IDENTIFIER_RE.search(target) and _STATE_DECREASE_RE.search(match.group(0)):
            return True
        if target and _PAIR_IDENTIFIER_RE.search(target):
            return True
    if _TRANSFER_TO_PAIR_BURN_RE.search(body):
        return True
    return False


def _has_unbound_pair_domain(fn: FunctionSlice) -> bool:
    text = f"{fn.header}\n{fn.body}"
    if _POOL_DOMAIN_GUARD_RE.search(text):
        return False
    return True


def _admin_burn_pair_gap(fn: FunctionSlice) -> bool:
    text = f"{fn.name}\n{fn.header}\n{fn.body}"
    if not _is_callable_mutator(fn):
        return False
    if not _PAIR_CONTEXT_RE.search(text):
        return False
    if not _is_privileged_context(fn):
        return False
    if not _has_pair_targeted_burn(fn):
        return False
    if not _SUPPLY_OR_SYNC_EFFECT_RE.search(fn.body):
        return False
    if _BENIGN_SELF_BURN_RE.search(fn.body) and not _PAIR_IDENTIFIER_RE.search(fn.body):
        return False
    if not _has_unbound_pair_domain(fn):
        return False
    return bool(_pair_param_names(fn.header) or _PAIR_IDENTIFIER_RE.search(fn.body))


def _finding(file_path: str, fn: FunctionSlice) -> Finding:
    return Finding(
        detector=DETECTOR_NAME,
        file=file_path,
        line=fn.line,
        severity=DETECTOR_SEVERITY_DEFAULT,
        function=fn.name,
        message=(
            "admin-controlled pair or pool burn can shrink AMM reserve balance "
            "and inflate spot price or reserve accounting without router, pair, "
            "factory, or pool-domain authorization. NOT_SUBMIT_READY: detector "
            "fixture smoke evidence only."
        ),
    )


def scan(source: str, file_path: str = "<memory>") -> list[Finding]:
    code = _strip_comments_and_strings(source)
    findings: list[Finding] = []
    for fn in _split_functions(code):
        if _admin_burn_pair_gap(fn):
            findings.append(_finding(file_path, fn))
    return findings


__all__ = ["scan", "Finding", "DETECTOR_NAME", "DETECTOR_SEVERITY_DEFAULT"]
