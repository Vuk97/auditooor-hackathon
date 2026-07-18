"""
fund-loss-arithmetic-cast-fire24

Fire24 Solidity lift for fund-loss-via-arithmetic recall gaps around unsafe
casts and stale self-referential value accumulators. It is intentionally
narrower than a generic unsafe-cast detector: a hit requires a public economic
entrypoint, value-bearing accounting context, and one of these source shapes:

- arithmetic value narrowed through a bare uintN cast before accounting
- signed value cast to unsigned without SafeCast or a non-negative guard
- value-bearing state accumulator updated from itself again

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

try:
    from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification
except Exception:  # pragma: no cover - regex runner can run without slither.
    class AbstractDetector:  # type: ignore[no-redef]
        pass

    class DetectorClassification:  # type: ignore[no-redef]
        MEDIUM = "Medium"
        LOW = "Low"


DETECTOR_NAME = "fund-loss-arithmetic-cast-fire24"
DETECTOR_SEVERITY_DEFAULT = "Medium"

_ECONOMIC_ENTRY_RE = re.compile(
    r"(?i)^(?:deposit|withdraw|redeem|mint|burn|claim|settle|payout|"
    r"collect|liquidate|borrow|repay|swap|trade|buy|sell|quote|preview|"
    r"convert|request|queue|process|finalize|draw|resolve|accrue|update|"
    r"distribute|harvest|allocate)"
)
_SKIP_NAME_RE = re.compile(r"(?i)(?:test|mock|fixture|harness|setup|helper)")
_VISIBILITY_RE = re.compile(r"(?i)\b(?:external|public)\b")
_VALUE_CONTEXT_RE = re.compile(
    r"(?is)(?:balance|balances|balanceOf|asset|assets|share|shares|"
    r"reserve|reserves|settlement|settle|payout|claimable|reward|fee|"
    r"liquidity|debt|collateral|amount|amountOut|value|price|rate|index|"
    r"denominator|supply|totalSupply|totalAssets|credit|credits|principal|"
    r"accumulator|owed|withdrawable)"
)
_VALUE_EFFECT_RE = re.compile(
    r"(?is)(?:\b[A-Za-z_][A-Za-z0-9_]*(?:balance|balances|reserve|reserves|"
    r"settlement|payout|claimable|reward|rewards|debt|collateral|credit|"
    r"credits|principal|assets|supply|amount|index|accumulator|owed|"
    r"withdrawable)[A-Za-z0-9_]*\s*(?:\[[^\]]+\]\s*)?(?:=|\+=|-=)|"
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
    r"reserves|settlement|payout|claimable|reward|rewards|fee|liquidity|"
    r"debt|collateral|amount|value|price|rate|index|denom|denominator|"
    r"supply|totalSupply|totalAssets|credit|credits|principal|accumulator|"
    r"factor|scale|owed|withdrawable)"
)
_ARITH_LOCAL_RE = re.compile(
    r"(?is)\b(?:u?int(?:\d+)?|int(?:\d+)?)\s+"
    r"(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*=\s*"
    r"(?P<expr>[^;]*(?:\+|-|\*|/|%)[^;]*)\s*;"
)
_NARROW_UINT_CAST_RE = re.compile(
    r"(?is)\b(?P<target>uint(?P<bits>8|16|24|32|40|48|56|64|72|80|88|96|"
    r"104|112|120|128|136|144|152|160|168|176|184|192|200|208|216|224))"
    r"\s*\(\s*(?P<arg>[^()\n;]+?)\s*\)"
)
_SIGNED_TO_UINT_CAST_RE = re.compile(
    r"(?is)\b(?P<target>uint(?:8|16|24|32|40|48|56|64|72|80|88|96|"
    r"104|112|120|128|136|144|152|160|168|176|184|192|200|208|216|224|256)?)"
    r"\s*\(\s*(?P<arg>[A-Za-z_][A-Za-z0-9_]*)\s*\)"
)
_SIGNED_DECL_RE = re.compile(
    r"(?is)\bint(?:8|16|24|32|40|48|56|64|72|80|88|96|104|112|120|128|"
    r"136|144|152|160|168|176|184|192|200|208|216|224|232|240|248|256)?\s+"
    r"(?P<name>[A-Za-z_][A-Za-z0-9_]*)\b"
)
_SAFE_CAST_RE = re.compile(
    r"(?is)(?:SafeCast|\.toUint(?:8|16|32|64|96|112|128|160|192|224|256)"
    r"\s*\(|safeCast|cast overflow|CastOverflow|SafeCastOverflow)"
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


def _signed_names(source: str) -> set[str]:
    return {match.group("name") for match in _SIGNED_DECL_RE.finditer(source)}


def _has_unsigned_cast_guard(source: str, name: str, target: str, bits: str) -> bool:
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


def _has_signed_cast_guard(source: str, name: str) -> bool:
    if _SAFE_CAST_RE.search(source):
        return True
    escaped = re.escape(name)
    guard_patterns = [
        rf"(?is)\brequire\s*\([^;]*\b{escaped}\b\s*>=\s*0",
        rf"(?is)\brequire\s*\([^;]*0\s*<=\s*\b{escaped}\b",
        rf"(?is)\bif\s*\([^;]*\b{escaped}\b\s*<\s*0[^;{{]*revert",
        rf"(?is)\bif\s*\([^;]*0\s*>\s*\b{escaped}\b[^;{{]*revert",
        rf"(?is)\b{escaped}\b\s*>=\s*0",
    ]
    return any(re.search(pattern, source) for pattern in guard_patterns)


def _find_cast_after_value_math(source: str) -> list[_BranchFinding]:
    if not _has_value_math(source):
        return []
    locals_from_arithmetic = _arithmetic_locals(source)
    if not locals_from_arithmetic:
        return []

    findings: list[_BranchFinding] = []
    for match in _NARROW_UINT_CAST_RE.finditer(source):
        arg = (match.group("arg") or "").strip()
        if arg not in locals_from_arithmetic:
            continue
        target = match.group("target")
        bits = match.group("bits")
        if _has_unsigned_cast_guard(source, arg, target, bits):
            continue
        findings.append(
            _BranchFinding(
                branch="cast-after-value-math",
                offset=match.start(),
                detail=(
                    f"arithmetic value `{arg}` is narrowed through bare `{target}` "
                    "before value accounting"
                ),
            )
        )
        break
    return findings


def _find_signed_to_unsigned_value_cast(source: str) -> list[_BranchFinding]:
    if not _has_value_math(source):
        return []
    signed_names = _signed_names(source)
    if not signed_names:
        return []

    findings: list[_BranchFinding] = []
    for match in _SIGNED_TO_UINT_CAST_RE.finditer(source):
        arg = match.group("arg")
        if arg not in signed_names:
            continue
        if _has_signed_cast_guard(source, arg):
            continue
        findings.append(
            _BranchFinding(
                branch="signed-to-unsigned-value-cast",
                offset=match.start(),
                detail=(
                    f"signed value `{arg}` is cast through bare `{match.group('target')}` "
                    "without a non-negative or SafeCast guard"
                ),
            )
        )
        break
    return findings


def _compound_self_ref_pattern(slot: str) -> re.Pattern[str]:
    escaped = re.escape(slot)
    index = r"(?:\s*\[[^\]\n;{}]+\]){0,3}"
    return re.compile(
        rf"(?is)\b{escaped}\b{index}\s*(?P<op>\+=|-=|\*=|/=|%=)\s*"
        rf"(?P<rhs>[^;{{}}]*\b{escaped}\b{index}[^;{{}}]*)\s*;"
    )


def _assignment_self_ref_pattern(slot: str) -> re.Pattern[str]:
    escaped = re.escape(slot)
    return re.compile(
        rf"(?is)\b{escaped}\b\s*=\s*[^;{{}}]*\b{escaped}\b"
        rf"[^;{{}}]*(?:\+|-|\*|/|%)[^;{{}}]*;"
    )


def _find_self_referencing_accumulator(
    source: str,
    slots: Iterable[str],
) -> list[_BranchFinding]:
    findings: list[_BranchFinding] = []
    for slot in sorted(set(slots)):
        if not _VALUE_SLOT_RE.search(slot):
            continue
        compound = _compound_self_ref_pattern(slot).search(source)
        if compound:
            findings.append(
                _BranchFinding(
                    branch="self-referencing-value-accumulator",
                    offset=compound.start(),
                    detail=(
                        f"value-bearing state slot `{slot}` uses `{compound.group('op')}` "
                        "while the right-hand side reads the same slot again"
                    ),
                )
            )
            return findings
        assigned = _assignment_self_ref_pattern(slot).search(source)
        if assigned:
            findings.append(
                _BranchFinding(
                    branch="self-referencing-value-accumulator",
                    offset=assigned.start(),
                    detail=(
                        f"value-bearing state slot `{slot}` is assigned from arithmetic "
                        "that reads the same slot again"
                    ),
                )
            )
            return findings
    return findings


def _find_branches(source: str, slots: Iterable[str]) -> list[_BranchFinding]:
    branches: list[_BranchFinding] = []
    branches.extend(_find_cast_after_value_math(source))
    branches.extend(_find_signed_to_unsigned_value_cast(source))
    branches.extend(_find_self_referencing_accumulator(source, slots))
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


class FundLossArithmeticCastFire24(AbstractDetector):
    ARGUMENT = DETECTOR_NAME
    HELP = (
        "Flags value math where bare narrowing casts, signed-to-unsigned casts, "
        "or self-referential accumulators can corrupt balances or protocol value."
    )
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.LOW
    WIKI = "https://github.com/Vuk97/auditooor"
    WIKI_TITLE = "Fund-loss arithmetic via cast or self-referential accumulator"
    WIKI_DESCRIPTION = (
        "Value-moving paths can lose funds when computed values are narrowed "
        "without range checks, signed deltas are reinterpreted as unsigned "
        "credits, or state accumulators compound their own stale value."
    )
    WIKI_EXPLOIT_SCENARIO = (
        "A settlement path computes a uint256 net amount then stores uint128; "
        "a signed int128 fee delta is cast to uint128 before crediting claims; "
        "or a reward index uses `rewardIndex += rewardIndex + delta`, doubling "
        "the prior accumulator into every user balance calculation."
    )
    WIKI_RECOMMENDATION = (
        "Use SafeCast or explicit range checks before every narrowing or "
        "signed-to-unsigned cast. Compute accumulator deltas from stable "
        "snapshots and write the state slot exactly once."
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
    "FundLossArithmeticCastFire24",
    "DETECTOR_NAME",
    "DETECTOR_SEVERITY_DEFAULT",
    "scan",
]
