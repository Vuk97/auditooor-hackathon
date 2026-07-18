"""
fund-loss-safecast-int128-fire26

Fire26 Solidity lift for `fund-loss-via-arithmetic` recall gaps where
liquidity, balance, delta, or amount values are cast into int128 or uint128
without SafeCast or explicit bounds before value accounting changes.

This detector is candidate evidence only. It is NOT_SUBMIT_READY and cannot be
cited as exploit proof without a real in-scope path, negative control, and
R40/R76/R80 evidence.
"""

from __future__ import annotations

import re
import sys
from dataclasses import dataclass
from pathlib import Path as _Path
from typing import Iterable

sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_leaf_helper, is_vendored_or_test_contract

try:
    from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification
except Exception:  # pragma: no cover - regex runner can run without slither.
    class AbstractDetector:  # type: ignore[no-redef]
        pass

    class DetectorClassification:  # type: ignore[no-redef]
        MEDIUM = "Medium"
        LOW = "Low"


DETECTOR_NAME = "fund-loss-safecast-int128-fire26"
DETECTOR_SEVERITY_DEFAULT = "Medium"

_FUNCTION_START_RE = re.compile(
    r"(?is)\bfunction\s+(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*"
    r"\([^)]*\)(?P<trailer>[^{;]*)\{"
)
_VISIBILITY_RE = re.compile(r"(?i)\b(?:external|public|internal)\b")
_PUBLIC_OR_EXTERNAL_RE = re.compile(r"(?i)\b(?:external|public)\b")
_SKIP_NAME_RE = re.compile(r"(?i)(?:test|mock|fixture|harness|setup)")
_ECONOMIC_ENTRY_RE = re.compile(
    r"(?i)^(?:deposit|withdraw|redeem|mint|burn|claim|settle|payout|"
    r"collect|liquidate|borrow|repay|swap|trade|buy|sell|quote|preview|"
    r"convert|request|queue|process|finalize|draw|resolve|accrue|update|"
    r"distribute|harvest|allocate|apply|modify)"
)
_VALUE_NAME_RE = re.compile(
    r"(?i)(?:amount|amount0|amount1|asset|assets|share|shares|balance|"
    r"balances|delta|liquidity|reserve|reserves|owed|credit|debit|debt|"
    r"collateral|fee|fees|payout|claimable|reward|settlement|principal|"
    r"net|gross|token)"
)
_VALUE_CONTEXT_RE = re.compile(
    r"(?is)(?:amount|asset|share|balance|delta|liquidity|reserve|owed|"
    r"credit|debit|debt|collateral|fee|payout|claimable|reward|settlement|"
    r"tokensOwed|position|pool|reserve|account)"
)
_ACCOUNTING_EFFECT_RE = re.compile(
    r"(?is)(?:"
    r"\b[A-Za-z_][A-Za-z0-9_]*(?:balance|balances|liquidity|reserve|"
    r"reserves|owed|credit|credits|debit|debt|collateral|claimable|reward|"
    r"settlement|assets|shares|amount|fee|tokensOwed|principal)[A-Za-z0-9_]*"
    r"(?:\s*\[[^\]]+\])?(?:\.[A-Za-z_][A-Za-z0-9_]*)?\s*(?:=|\+=|-=)"
    r"|"
    r"\bposition\.[A-Za-z_][A-Za-z0-9_]*\s*(?:=|\+=|-=)"
    r"|"
    r"\b(?:_?updatePosition|_?modifyPosition|modifyLiquidity|account|"
    r"settle|credit|debit|applyDelta|applyLiquidity|_?mint|_?burn|"
    r"transfer|safeTransfer|transferFrom|safeTransferFrom)\s*\("
    r")"
)
_RETURN_CAST_RE = re.compile(
    r"(?is)\breturn\s+u?int128\s*\(\s*[A-Za-z_][A-Za-z0-9_]*\s*\)"
)
_CAST_RE = re.compile(
    r"(?is)\b(?P<target>u?int128)\s*\(\s*(?P<arg>[^()\n;]+?)\s*\)"
)
_DECL_RE = re.compile(
    r"(?is)\b(?P<type>u?int(?:8|16|24|32|40|48|56|64|72|80|88|96|"
    r"104|112|120|128|136|144|152|160|168|176|184|192|200|208|216|224|"
    r"232|240|248|256)?|uint|int)\s+"
    r"(?:memory\s+|calldata\s+|storage\s+)?"
    r"(?P<name>[A-Za-z_][A-Za-z0-9_]*)\b"
)
_SAFE_CAST_RE = re.compile(
    r"(?is)(?:SafeCast|safeCast|\.toUint128\s*\(|\.toInt128\s*\(|"
    r"\btoUint128\s*\(|\btoInt128\s*\(|SafeCastOverflow|CastOverflow|"
    r"checked conversion|cast overflow)"
)
_MUTATING_HEADER_RE = re.compile(r"(?i)\b(?:view|pure)\b")


@dataclass(frozen=True)
class Finding:
    detector: str
    file: str
    line: int
    severity: str
    message: str
    function: str | None = None


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


def _declarations(source: str) -> dict[str, str]:
    return {
        match.group("name"): match.group("type").lower()
        for match in _DECL_RE.finditer(source)
    }


def _simple_arg_name(arg: str) -> str | None:
    stripped = arg.strip()
    if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", stripped):
        return stripped
    return None


def _arg_is_value_like(arg: str, declarations: dict[str, str]) -> bool:
    name = _simple_arg_name(arg)
    if name is not None:
        return bool(_VALUE_NAME_RE.search(name) or name in declarations)
    return bool(_VALUE_CONTEXT_RE.search(arg))


def _source_kind(arg: str, declarations: dict[str, str]) -> str:
    name = _simple_arg_name(arg)
    typ = declarations.get(name or "", "")
    if typ.startswith("uint"):
        return "unsigned"
    if typ.startswith("int"):
        return "signed"
    if re.search(r"(?i)\bint128\b", arg):
        return "signed"
    if re.search(r"(?i)\buint|amount|liquidity|balance|assets|shares", arg):
        return "unsigned"
    return "unknown"


def _has_non_negative_guard(source: str, arg_name: str | None) -> bool:
    if _SAFE_CAST_RE.search(source):
        return True
    if arg_name is None:
        return False
    escaped = re.escape(arg_name)
    patterns = [
        rf"(?is)\brequire\s*\([^;]*\b{escaped}\b\s*>=\s*0",
        rf"(?is)\brequire\s*\([^;]*0\s*<=\s*\b{escaped}\b",
        rf"(?is)\bif\s*\([^;]*\b{escaped}\b\s*<\s*0[^;{{]*revert",
        rf"(?is)\bif\s*\([^;]*0\s*>\s*\b{escaped}\b[^;{{]*revert",
        rf"(?is)\b{escaped}\b\s*>=\s*0",
    ]
    return any(re.search(pattern, source) for pattern in patterns)


def _has_uint128_bound(source: str, arg_name: str | None) -> bool:
    if _SAFE_CAST_RE.search(source):
        return True
    if arg_name is None:
        return bool(re.search(r"(?is)type\s*\(\s*uint128\s*\)\s*\.max", source))
    escaped = re.escape(arg_name)
    patterns = [
        rf"(?is)\brequire\s*\([^;]*\b{escaped}\b\s*<=\s*type\s*\(\s*uint128\s*\)\s*\.max",
        rf"(?is)\bif\s*\([^;]*\b{escaped}\b\s*>\s*type\s*\(\s*uint128\s*\)\s*\.max[^;{{]*revert",
        rf"(?is)\brequire\s*\([^;]*\b{escaped}\b\s*<\s*2\s*\*\*\s*128",
        rf"(?is)\b{escaped}\b\s*<=\s*type\s*\(\s*uint128\s*\)\s*\.max",
    ]
    return any(re.search(pattern, source) for pattern in patterns)


def _has_int128_bound(source: str, arg_name: str | None) -> bool:
    if _SAFE_CAST_RE.search(source):
        return True
    if arg_name is None:
        return bool(re.search(r"(?is)type\s*\(\s*int128\s*\)\s*\.max", source))
    escaped = re.escape(arg_name)
    patterns = [
        rf"(?is)\brequire\s*\([^;]*\b{escaped}\b\s*<=\s*(?:uint128\s*\(\s*)?type\s*\(\s*int128\s*\)\s*\.max",
        rf"(?is)\bif\s*\([^;]*\b{escaped}\b\s*>\s*(?:uint128\s*\(\s*)?type\s*\(\s*int128\s*\)\s*\.max[^;{{]*revert",
        rf"(?is)\brequire\s*\([^;]*\b{escaped}\b\s*<\s*2\s*\*\*\s*127",
        rf"(?is)\b{escaped}\b\s*<=\s*(?:uint128\s*\(\s*)?type\s*\(\s*int128\s*\)\s*\.max",
    ]
    return any(re.search(pattern, source) for pattern in patterns)


def _assigned_local_near_cast(function_text: str, cast_start: int) -> str | None:
    prefix = function_text[max(0, cast_start - 120):cast_start]
    match = re.search(
        r"(?is)(?:u?int128|u?int256|uint|int)\s+"
        r"(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*=\s*[^;{}]*$",
        prefix,
    )
    return match.group("name") if match else None


def _suffix_consumes_value(function_text: str, cast: re.Match[str], assigned: str | None) -> bool:
    suffix = function_text[cast.end():cast.end() + 700]
    if assigned:
        assigned_use = re.search(rf"(?is)\b{re.escape(assigned)}\b", suffix)
        if assigned_use:
            window = suffix[assigned_use.start():assigned_use.start() + 260]
            if _ACCOUNTING_EFFECT_RE.search(window):
                return True
    direct_window = function_text[max(0, cast.start() - 120):cast.end() + 260]
    return bool(_ACCOUNTING_EFFECT_RE.search(direct_window) or _ACCOUNTING_EFFECT_RE.search(suffix))


def _helper_cast_context(fn: _FunctionSource, cast: re.Match[str], declarations: dict[str, str]) -> bool:
    arg = (cast.group("arg") or "").strip()
    arg_name = _simple_arg_name(arg)
    if cast.group("target").lower() != "uint128":
        return False
    if _source_kind(arg, declarations) != "signed":
        return False
    if not _RETURN_CAST_RE.search(fn.text):
        return False
    return bool(re.search(r"(?i)(delta|amount|balance|liquidity|toUint128|apply)", fn.name))


def _is_candidate_function(fn: _FunctionSource) -> bool:
    if _SKIP_NAME_RE.search(fn.name):
        return False
    if not _VISIBILITY_RE.search(fn.trailer):
        return False
    if _PUBLIC_OR_EXTERNAL_RE.search(fn.trailer) and _ECONOMIC_ENTRY_RE.search(fn.name):
        return True
    if _VALUE_CONTEXT_RE.search(fn.text) and _CAST_RE.search(fn.text):
        return True
    return False


def _branch_for_cast(fn: _FunctionSource, cast: re.Match[str], declarations: dict[str, str]) -> _BranchFinding | None:
    target = cast.group("target").lower()
    arg = (cast.group("arg") or "").strip()
    arg_name = _simple_arg_name(arg)
    source_kind = _source_kind(arg, declarations)

    if not _arg_is_value_like(arg, declarations):
        return None

    consumes_value = _suffix_consumes_value(
        fn.text, cast, _assigned_local_near_cast(fn.text, cast.start())
    )
    helper_context = _helper_cast_context(fn, cast, declarations)
    if not consumes_value and not helper_context:
        return None

    if target == "uint128" and source_kind == "signed":
        if _has_non_negative_guard(fn.text, arg_name):
            return None
        return _BranchFinding(
            branch="signed-delta-to-uint128",
            offset=cast.start(),
            detail=(
                f"signed value `{arg}` is cast through bare uint128 without "
                "a non-negative SafeCast guard before value accounting"
            ),
        )

    if target == "uint128":
        if _has_uint128_bound(fn.text, arg_name):
            return None
        return _BranchFinding(
            branch="wide-value-to-uint128",
            offset=cast.start(),
            detail=(
                f"value `{arg}` is narrowed through bare uint128 without a "
                "type(uint128).max or SafeCast guard before value accounting"
            ),
        )

    if target == "int128":
        if _has_int128_bound(fn.text, arg_name):
            return None
        return _BranchFinding(
            branch="value-to-int128",
            offset=cast.start(),
            detail=(
                f"value `{arg}` is cast through bare int128 without a "
                "type(int128).max or SafeCast guard before liquidity accounting"
            ),
        )

    return None


def _find_branches(fn: _FunctionSource) -> list[_BranchFinding]:
    declarations = _declarations(fn.text)
    out: list[_BranchFinding] = []
    for cast in _CAST_RE.finditer(fn.text):
        branch = _branch_for_cast(fn, cast, declarations)
        if branch is not None:
            out.append(branch)
    return out


def scan(source: str, file_path: str = "<unknown>") -> list[Finding]:
    text = _strip_comments(source)
    findings: list[Finding] = []
    for fn in _iter_functions(text):
        if not _is_candidate_function(fn):
            continue
        for branch in _find_branches(fn):
            findings.append(
                Finding(
                    detector=DETECTOR_NAME,
                    file=file_path,
                    line=_line_for(source, fn.start + branch.offset),
                    severity=DETECTOR_SEVERITY_DEFAULT,
                    function=fn.name,
                    message=(
                        f"{DETECTOR_NAME}: branch {branch.branch}: {branch.detail}. "
                        "NOT_SUBMIT_READY: detector fixture smoke evidence only."
                    ),
                )
            )
    return findings


class FundLossSafecastInt128Fire26(AbstractDetector):
    ARGUMENT = DETECTOR_NAME
    HELP = (
        "Flags direct int128 or uint128 casts of liquidity, delta, balance, "
        "or amount values before value accounting mutations when SafeCast or "
        "explicit bounds are absent."
    )
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.LOW
    WIKI = "https://github.com/Vuk97/auditooor"
    WIKI_TITLE = "Fund-loss arithmetic via unguarded int128 or uint128 cast"
    WIKI_DESCRIPTION = (
        "Balance delta and liquidity accounting paths can wrap signed values "
        "or truncate wide unsigned values when they use bare int128 or uint128 "
        "casts before mutating position, balance, reserve, or owed-token state."
    )
    WIKI_EXPLOIT_SCENARIO = (
        "A negative int128 delta is converted with uint128(delta) and credited "
        "as a huge positive owed amount, or a large liquidity amount is passed "
        "through int128(amount) before a burn or position update."
    )
    WIKI_RECOMMENDATION = (
        "Use OpenZeppelin SafeCast or equivalent checked helpers for every "
        "int128 and uint128 conversion. For signed-to-unsigned deltas, require "
        "the value to be non-negative. For unsigned-to-int128 and wide-to-"
        "uint128 casts, require the source value to fit in the destination."
    )

    SUBMISSION_POSTURE = "NOT_SUBMIT_READY"
    COVERAGE_CLAIM = "detector_fixture_smoke_only"
    PROMOTION_ALLOWED = False

    def _detect(self):
        results = []
        for contract in self.contracts:
            if is_vendored_or_test_contract(contract):
                continue
            for function in contract.functions_and_modifiers_declared:
                if is_leaf_helper(function):
                    continue
                source = _strip_comments(_source_text(function))
                if not source:
                    continue
                trailer = f" {getattr(function, 'visibility', '')} "
                fn = _FunctionSource(
                    name=str(getattr(function, "name", "") or ""),
                    trailer=trailer,
                    start=0,
                    end=len(source),
                    text=source,
                )
                if not _is_candidate_function(fn):
                    continue
                for branch in _find_branches(fn):
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
    "FundLossSafecastInt128Fire26",
    "Finding",
    "DETECTOR_NAME",
    "DETECTOR_SEVERITY_DEFAULT",
    "scan",
]
