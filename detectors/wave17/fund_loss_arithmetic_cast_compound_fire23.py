"""
fund-loss-arithmetic-cast-compound-fire23

Fire23 Solidity lift for same-class fund-loss-via-arithmetic misses. It
stays narrower than generic overflow, generic unsafe cast, and generic
randomness detectors by requiring value-bearing math that can change user
balances, reserves, claim amounts, or settlement amounts.

Branches:
- arithmetic local narrowed through a bare uintN cast before value accounting
- direct self-referencing denominator or rate update consumed by value math
- blockhash-derived stale entropy used directly in amount or price math

This is detector fixture smoke evidence only. It is NOT_SUBMIT_READY and must
not be cited as proof of exploitability without a real in-scope PoC.
"""

from __future__ import annotations

import re
import sys
from dataclasses import dataclass
from pathlib import Path as _Path
from typing import Iterable

sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_leaf_helper, is_vendored_or_test_contract

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


DETECTOR_NAME = "fund-loss-arithmetic-cast-compound-fire23"
DETECTOR_SEVERITY_DEFAULT = "Medium"

_ECONOMIC_ENTRY_RE = re.compile(
    r"(?i)^(?:deposit|withdraw|redeem|mint|burn|claim|settle|payout|"
    r"collect|liquidate|borrow|repay|swap|trade|buy|sell|quote|preview|"
    r"convert|request|queue|process|finalize|draw|resolve|accrue|update)"
)
_SKIP_NAME_RE = re.compile(r"(?i)(?:test|mock|fixture|harness|setup|helper)")
_VISIBILITY_RE = re.compile(r"(?i)\b(?:external|public)\b")
_VALUE_CONTEXT_RE = re.compile(
    r"(?is)(?:balance|balances|balanceOf|asset|assets|share|shares|"
    r"reserve|reserves|settlement|settle|payout|claimable|reward|fee|"
    r"liquidity|debt|collateral|amount|amountOut|value|price|rate|index|"
    r"denominator|supply|totalSupply|totalAssets|credit|principal)"
)
_VALUE_EFFECT_RE = re.compile(
    r"(?is)(?:\b[A-Za-z_][A-Za-z0-9_]*(?:balance|balances|reserve|reserves|"
    r"settlement|payout|claimable|reward|debt|collateral|credit|principal|"
    r"assets|supply|amount)[A-Za-z0-9_]*\s*(?:\[[^\]]+\]\s*)?(?:=|\+=|-=)|"
    r"\.(?:transfer|safeTransfer|sendValue)\s*\(|\.call\s*\{\s*value\s*:)"
)
_ARITHMETIC_RE = re.compile(r"(?s)(?:\+|-|\*|/|%)")
_FUNCTION_START_RE = re.compile(
    r"(?is)\bfunction\s+(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*"
    r"\([^)]*\)(?P<trailer>[^{;]*)\{"
)
_STATE_DECL_RE = re.compile(
    r"(?m)^\s*(?:mapping\s*\([^;\n]+\)|u?int(?:\d+)?|int(?:\d+)?)\s+"
    r"(?:(?:public|private|internal|constant|immutable|override)\s+)*"
    r"(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*(?:=|;|\[)"
)
_VALUE_SLOT_RE = re.compile(
    r"(?i)(?:balance|balances|balanceOf|asset|assets|share|shares|reserve|"
    r"reserves|settlement|payout|claimable|reward|fee|liquidity|debt|"
    r"collateral|amount|value|price|rate|index|denom|denominator|supply|"
    r"totalSupply|totalAssets|credit|principal|accumulator|factor|scale)"
)
_ARITH_LOCAL_RE = re.compile(
    r"(?is)\b(?:u?int(?:\d+)?|int(?:\d+)?)\s+"
    r"(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*=\s*"
    r"(?P<expr>[^;]*(?:\+|-|\*|/|%)[^;]*)\s*;"
)
_UINT_CAST_RE = re.compile(
    r"(?is)\b(?P<target>uint(?P<bits>8|16|24|32|40|48|56|64|72|80|88|96|"
    r"104|112|120|128|136|144|152|160|168|176|184|192|200|208|216|224))"
    r"\s*\(\s*(?P<arg>[A-Za-z_][A-Za-z0-9_]*)\s*\)"
)
_BLOCKHASH_VALUE_RE = re.compile(
    r"(?is)\b(?P<name>assets|shares|amount|amountOut|payout|settlementAmount|"
    r"settlement|price|rate|reward|claimable|debt|collateral|value)\s*=\s*"
    r"[^;]*\bblockhash\s*\([^;]*(?:\*|/|%)[^;]*;"
)
_BLOCKHASH_VAR_RE = re.compile(
    r"(?is)\b(?:bytes32|uint(?:\d+)?)\s+"
    r"(?P<var>[A-Za-z_][A-Za-z0-9_]*)\s*=\s*[^;]*\bblockhash\s*\([^;]*;"
)
_BLOCKHASH_GUARD_RE = re.compile(
    r"(?is)(?:block\.number\s*-\s*[A-Za-z_][A-Za-z0-9_\[\]\.]*\s*"
    r"(?:<=|<)\s*(?:255|256)|(?:BlockhashTooOld|staleBlock|freshBlock)|"
    r"require\s*\([^;]*(?:<=|<)\s*(?:255|256)[^;]*block)"
)
_SAFE_CAST_RE = re.compile(
    r"(?is)(?:SafeCast|\.toUint(?:8|16|32|64|96|112|128|160|192|224)\s*\(|"
    r"safeCast|cast overflow|CastOverflow)"
)


@dataclass(frozen=True)
class _FunctionSource:
    name: str
    trailer: str
    start: int
    end: int
    text: str


@dataclass(frozen=True)
class _BranchFinding:
    branch: str
    offset: int
    detail: str


def _source_text(obj) -> str:
    try:
        return obj.source_mapping.content or ""
    except Exception:
        return ""


def _blank_match(match: re.Match[str]) -> str:
    return re.sub(r"[^\r\n]", " ", match.group(0))


def _strip_comments(source: str) -> str:
    text = re.sub(r"/\*.*?\*/", _blank_match, source, flags=re.DOTALL)
    return re.sub(r"//[^\n\r]*", _blank_match, text)


def _line_for(source: str, offset: int) -> int:
    return source.count("\n", 0, max(offset, 0)) + 1


def _find_matching_brace(source: str, open_brace: int) -> int | None:
    depth = 0
    for index in range(open_brace, len(source)):
        char = source[index]
        if char == "{":
            depth += 1
        elif char == "}":
            depth -= 1
            if depth == 0:
                return index + 1
    return None


def _iter_functions(source: str) -> Iterable[_FunctionSource]:
    for match in _FUNCTION_START_RE.finditer(source):
        open_brace = source.find("{", match.start())
        if open_brace == -1:
            continue
        end = _find_matching_brace(source, open_brace)
        if end is None:
            continue
        yield _FunctionSource(
            name=match.group("name"),
            trailer=match.group("trailer") or "",
            start=match.start(),
            end=end,
            text=source[match.start():end],
        )


def _mask_ranges(source: str, ranges: Iterable[tuple[int, int]]) -> str:
    chars = list(source)
    for start, end in ranges:
        for index in range(max(start, 0), min(end, len(chars))):
            if chars[index] not in "\r\n":
                chars[index] = " "
    return "".join(chars)


def _state_value_slots(source: str) -> set[str]:
    functions = list(_iter_functions(source))
    masked = _mask_ranges(source, ((fn.start, fn.end) for fn in functions))
    return {
        match.group("name")
        for match in _STATE_DECL_RE.finditer(masked)
        if _VALUE_SLOT_RE.search(match.group("name"))
    }


def _state_variables_written(function) -> set[str]:
    names: set[str] = set()
    try:
        for state_var in getattr(function, "state_variables_written", []) or []:
            name = str(getattr(state_var, "name", "") or "")
            if name and _VALUE_SLOT_RE.search(name):
                names.add(name)
    except Exception:
        pass
    return names


def _is_public_economic(name: str, trailer: str, source: str) -> bool:
    if not _VISIBILITY_RE.search(trailer):
        return False
    if _SKIP_NAME_RE.search(name):
        return False
    if _ECONOMIC_ENTRY_RE.search(name):
        return True
    return bool(_VALUE_CONTEXT_RE.search(source) and _VALUE_EFFECT_RE.search(source))


def _is_candidate_function(function, source: str) -> bool:
    visibility = str(getattr(function, "visibility", "") or "").lower()
    name = str(getattr(function, "name", "") or "")
    if visibility not in {"external", "public"}:
        return False
    if _SKIP_NAME_RE.search(name):
        return False
    if _ECONOMIC_ENTRY_RE.search(name):
        return True
    return bool(_VALUE_CONTEXT_RE.search(source) and _VALUE_EFFECT_RE.search(source))


def _has_value_math(source: str) -> bool:
    return bool(
        _VALUE_CONTEXT_RE.search(source)
        and _VALUE_EFFECT_RE.search(source)
        and _ARITHMETIC_RE.search(source)
    )


def _arithmetic_locals(source: str) -> set[str]:
    names: set[str] = set()
    for match in _ARITH_LOCAL_RE.finditer(source):
        expr = match.group("expr") or ""
        if _VALUE_CONTEXT_RE.search(expr) or _VALUE_CONTEXT_RE.search(source):
            names.add(match.group("name"))
    return names


def _has_cast_guard(source: str, name: str, target: str, bits: str) -> bool:
    if _SAFE_CAST_RE.search(source):
        return True
    escaped = re.escape(name)
    target_escaped = re.escape(target)
    guard_patterns = [
        rf"(?is)\brequire\s*\([^;]*\b{escaped}\b\s*<=\s*type\s*\(\s*{target_escaped}\s*\)\.max",
        rf"(?is)\bif\s*\([^;]*\b{escaped}\b\s*>\s*type\s*\(\s*{target_escaped}\s*\)\.max[^;{{]*revert",
        rf"(?is)\brequire\s*\([^;]*\b{escaped}\b\s*<\s*2\s*\*\*\s*{re.escape(bits)}\b",
        rf"(?is)\b{escaped}\b\s*<=\s*type\s*\(\s*{target_escaped}\s*\)\.max",
    ]
    return any(re.search(pattern, source) for pattern in guard_patterns)


def _find_cast_after_arithmetic(source: str) -> list[_BranchFinding]:
    if not _has_value_math(source):
        return []
    locals_from_arithmetic = _arithmetic_locals(source)
    if not locals_from_arithmetic:
        return []

    findings: list[_BranchFinding] = []
    for match in _UINT_CAST_RE.finditer(source):
        arg = match.group("arg")
        if arg not in locals_from_arithmetic:
            continue
        target = match.group("target")
        bits = match.group("bits")
        if _has_cast_guard(source, arg, target, bits):
            continue
        findings.append(
            _BranchFinding(
                branch="cast-after-arithmetic",
                offset=match.start(),
                detail=(
                    f"arithmetic local `{arg}` is narrowed through bare `{target}` "
                    "before value accounting"
                ),
            )
        )
        break
    return findings


def _self_ref_denominator_pattern(slot: str) -> re.Pattern[str]:
    escaped = re.escape(slot)
    return re.compile(
        rf"(?is)\b{escaped}\b\s*=\s*[^;{{}}]*\b{escaped}\b"
        rf"[^;{{}}]*(?:/|\*)[^;{{}}]*\b{escaped}\b[^;{{}}]*;"
    )


def _find_self_ref_denominator(source: str, slots: Iterable[str]) -> list[_BranchFinding]:
    if not _has_value_math(source):
        return []
    findings: list[_BranchFinding] = []
    for slot in sorted(set(slots)):
        if not _VALUE_SLOT_RE.search(slot):
            continue
        pattern = _self_ref_denominator_pattern(slot)
        for match in pattern.finditer(source):
            findings.append(
                _BranchFinding(
                    branch="self-referencing-denominator",
                    offset=match.start(),
                    detail=(
                        f"value-bearing denominator or rate `{slot}` is assigned "
                        "from an expression that divides or multiplies by itself"
                    ),
                )
            )
            return findings
    return findings


def _find_blockhash_value_math(source: str) -> list[_BranchFinding]:
    if "blockhash" not in source:
        return []
    if not _has_value_math(source):
        return []
    if _BLOCKHASH_GUARD_RE.search(source):
        return []

    direct = _BLOCKHASH_VALUE_RE.search(source)
    if direct:
        return [
            _BranchFinding(
                branch="stale-blockhash-value-math",
                offset=direct.start(),
                detail="blockhash-derived stale entropy is used directly in amount or price math",
            )
        ]

    entropy_vars = {match.group("var") for match in _BLOCKHASH_VAR_RE.finditer(source)}
    for var in sorted(entropy_vars):
        value_from_var = re.search(
            rf"(?is)\b(?:assets|shares|amount|amountOut|payout|settlementAmount|"
            rf"settlement|price|rate|reward|claimable|debt|collateral|value)\s*=\s*"
            rf"[^;]*\b{re.escape(var)}\b[^;]*(?:\*|/|%)[^;]*;",
            source,
        )
        if value_from_var:
            return [
                _BranchFinding(
                    branch="stale-blockhash-value-math",
                    offset=value_from_var.start(),
                    detail=(
                        f"blockhash-derived `{var}` feeds amount or price math "
                        "without a 256-block freshness guard"
                    ),
                )
            ]
    return []


def _find_branches(source: str, slots: Iterable[str]) -> list[_BranchFinding]:
    branches: list[_BranchFinding] = []
    branches.extend(_find_cast_after_arithmetic(source))
    branches.extend(_find_self_ref_denominator(source, slots))
    branches.extend(_find_blockhash_value_math(source))
    return branches


def _regex_finding(source: str, file_path: str, offset: int, branch: _BranchFinding):
    return {
        "detector": DETECTOR_NAME,
        "severity": DETECTOR_SEVERITY_DEFAULT,
        "file": file_path,
        "line": _line_for(source, offset),
        "message": (
            f"{DETECTOR_NAME}: branch {branch.branch}: {branch.detail}. "
            "NOT_SUBMIT_READY: detector fixture smoke evidence only."
        ),
        "function": None,
    }


def scan(source: str, file_path: str):
    """Regex-runner entrypoint for recall scoreboard integration."""
    text = _strip_comments(source)
    slots = _state_value_slots(text)
    findings = []
    for function in _iter_functions(text):
        if not _is_public_economic(function.name, function.trailer, function.text):
            continue
        for branch in _find_branches(function.text, slots):
            findings.append(
                _regex_finding(source, file_path, function.start + branch.offset, branch)
            )
    return findings


class FundLossArithmeticCastCompoundFire23(AbstractDetector):
    ARGUMENT = DETECTOR_NAME
    HELP = (
        "Flags value math where arithmetic is narrowed by a bare cast, a "
        "denominator self-references, or stale blockhash entropy feeds amount math."
    )
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.LOW
    WIKI = "https://github.com/Vuk97/auditooor"
    WIKI_TITLE = "Fund-loss arithmetic via cast, compounding, or stale blockhash"
    WIKI_DESCRIPTION = (
        "Value-moving paths can lose funds when computed amounts are narrowed "
        "after arithmetic, when a denominator or rate is assigned from its own "
        "current value, or when blockhash-derived stale entropy is consumed as "
        "a price or payout factor."
    )
    WIKI_EXPLOIT_SCENARIO = (
        "A settlement path computes a uint256 net amount, narrows it to uint96, "
        "and debits reserves; a redemption path mutates a denominator using "
        "the denominator itself before dividing user shares; or a payout path "
        "derives price math from an old blockhash that can return zero."
    )
    WIKI_RECOMMENDATION = (
        "Use SafeCast or explicit upper-bound checks, compute denominators "
        "from stable snapshots, and reject blockhash inputs older than 255 "
        "blocks before any value calculation."
    )

    SUBMISSION_POSTURE = "NOT_SUBMIT_READY"
    COVERAGE_CLAIM = "detector_fixture_smoke_only"
    PROMOTION_ALLOWED = False

    def _detect(self):
        results = []
        for contract in self.contracts:
            if is_vendored_or_test_contract(contract):
                continue
            contract_source = _strip_comments(_source_text(contract))
            contract_slots = _state_value_slots(contract_source)

            for function in contract.functions_and_modifiers_declared:
                if is_leaf_helper(function):
                    continue
                source = _strip_comments(_source_text(function))
                if not source:
                    continue
                if not _is_candidate_function(function, source):
                    continue

                slots = set(contract_slots)
                slots.update(_state_variables_written(function))
                for branch in _find_branches(source, slots):
                    info = [
                        function,
                        (
                            f" - {DETECTOR_NAME}: branch {branch.branch}: "
                            f"{branch.detail}. NOT_SUBMIT_READY: detector "
                            "fixture smoke evidence only."
                        ),
                    ]
                    results.append(self.generate_result(info))
        return results


__all__ = [
    "FundLossArithmeticCastCompoundFire23",
    "DETECTOR_NAME",
    "DETECTOR_SEVERITY_DEFAULT",
    "scan",
]
